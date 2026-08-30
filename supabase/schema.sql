-- ============================================================
-- TV FAMÍLIA — esquema Supabase
-- Corre isto no SQL Editor do teu projeto Supabase, de uma vez, de cima a baixo.
-- Não testei isto contra um Supabase real (não tenho ligação a partir daqui) —
-- se alguma instrução der erro, manda-me a mensagem exata que corrijo na hora.
-- ============================================================

create extension if not exists pgcrypto;
create extension if not exists pg_cron;
-- Se a linha do pg_cron der erro de permissão: vai a Database → Extensions
-- no painel do Supabase e ativa "pg_cron" por lá (um toggle só), depois volta
-- e corre o resto deste ficheiro a partir daqui.

-- ============================================================
-- PROFILES (login) — nunca dá para ler password_hash pelo cliente;
-- tudo passa pelas funções abaixo.
-- ============================================================
create table if not exists profiles (
  id uuid primary key default gen_random_uuid(),
  username text unique not null,
  password_hash text not null,
  created_at timestamptz not null default now()
);
alter table profiles enable row level security;
-- (sem policies de select/insert direto — de propósito)

create or replace function register_user(p_username text, p_password text)
returns json language plpgsql security definer as $$
declare v_exists boolean;
begin
  select exists(select 1 from profiles where lower(username) = lower(p_username)) into v_exists;
  if v_exists then
    return json_build_object('ok', false, 'error', 'taken');
  end if;
  insert into profiles(username, password_hash) values (p_username, crypt(p_password, gen_salt('bf')));
  return json_build_object('ok', true, 'username', p_username);
end;
$$;

create or replace function login_user(p_username text, p_password text)
returns json language plpgsql security definer as $$
declare v_row profiles;
begin
  select * into v_row from profiles where lower(username) = lower(p_username);
  if v_row.id is null or v_row.password_hash <> crypt(p_password, v_row.password_hash) then
    return json_build_object('ok', false, 'error', 'wrong_credentials');
  end if;
  return json_build_object('ok', true, 'username', v_row.username);
end;
$$;

grant execute on function register_user(text,text) to anon;
grant execute on function login_user(text,text) to anon;

-- ============================================================
-- PROGRAMACAO (grelha de transmissões)
-- Leitura livre para todos; escrita só via função com código de admin/operador.
-- ============================================================
create table if not exists programacao (
  id bigint generated always as identity primary key,
  lang text not null check (lang in ('pt','en','fr','es')),
  video_id text not null,
  title text default '',
  start_time timestamptz not null,
  duration_seconds int not null default 3600,
  views int not null default 0,
  chat_purged boolean not null default false,
  created_at timestamptz not null default now()
);
alter table programacao enable row level security;
drop policy if exists "programacao_select_all" on programacao;
create policy "programacao_select_all" on programacao for select using (true);

create or replace function admin_list_operator_codes(p_admin_code text)
returns json language plpgsql security definer as $$
begin
  if p_admin_code <> 'Cv280513//////' then
    return json_build_object('codes', json_build_array());
  end if;
  return json_build_object('codes', coalesce(json_agg(json_build_object('code', code) order by created_at desc), json_build_array())) from codigos_operador;
end;
$$;

grant execute on function admin_list_operator_codes(text) to anon;

create or replace function admin_add_program(
  p_code text, p_lang text, p_video_id text, p_title text,
  p_start timestamptz, p_duration_seconds int
) returns json language plpgsql security definer as $$
begin
  if p_code <> 'Cv280513//////' and not exists (select 1 from codigos_operador where code = p_code) then
    return json_build_object('ok', false, 'error', 'invalid_code');
  end if;
  insert into programacao(lang, video_id, title, start_time, duration_seconds)
  values (p_lang, p_video_id, p_title, p_start, p_duration_seconds);
  return json_build_object('ok', true);
end;
$$;

create or replace function admin_delete_program(p_code text, p_id bigint)
returns json language plpgsql security definer as $$
begin
  if p_code <> 'Cv280513//////' then
    return json_build_object('ok', false, 'error', 'invalid_code');
  end if;
  delete from programacao where id = p_id;
  return json_build_object('ok', true);
end;
$$;

create or replace function increment_program_views(p_id bigint)
returns void language sql security definer as $$
  update programacao set views = views + 1 where id = p_id;
$$;

grant execute on function admin_add_program(text,text,text,text,timestamptz,int) to anon;
grant execute on function admin_delete_program(text,bigint) to anon;
grant execute on function increment_program_views(bigint) to anon;

-- ============================================================
-- MENSAGENS (chat)
-- Leitura e escrita livres (é chat; o portão de "precisa estar logado"
-- já fica a cargo do ecrã de login no app). Apagar por transmissão é
-- automático, ver a função de limpeza mais abaixo.
-- ============================================================
create table if not exists mensagens (
  id bigint generated always as identity primary key,
  program_id bigint references programacao(id) on delete cascade,
  username text not null,
  type text not null check (type in ('text','audio','media')),
  texto text,
  media_url text,
  media_kind text,
  created_at timestamptz not null default now()
);
alter table mensagens enable row level security;
drop policy if exists "mensagens_select_all" on mensagens;
create policy "mensagens_select_all" on mensagens for select using (true);
drop policy if exists "mensagens_insert_all" on mensagens;
create policy "mensagens_insert_all" on mensagens for insert with check (true);

-- ============================================================
-- CODIGOS_OPERADOR
-- Ninguém lê a lista toda pelo cliente — só se pode confirmar UM código
-- de cada vez, e só o admin mestre gera/revoga.
-- ============================================================
create table if not exists codigos_operador (
  id bigint generated always as identity primary key,
  code text unique not null,
  created_at timestamptz not null default now()
);
alter table codigos_operador enable row level security;

create or replace function check_operator_code(p_code text)
returns boolean language sql security definer as $$
  select exists(select 1 from codigos_operador where code = p_code);
$$;

create or replace function admin_generate_operator_code(p_admin_code text)
returns json language plpgsql security definer as $$
declare v_code text;
begin
  if p_admin_code <> 'Cv280513//////' then
    return json_build_object('ok', false, 'error', 'invalid_code');
  end if;
  v_code := upper(substr(md5(random()::text), 1, 6));
  insert into codigos_operador(code) values (v_code);
  return json_build_object('ok', true, 'code', v_code);
end;
$$;

create or replace function admin_revoke_operator_code(p_admin_code text, p_code text)
returns json language plpgsql security definer as $$
begin
  if p_admin_code <> 'Cv280513//////' then
    return json_build_object('ok', false, 'error', 'invalid_code');
  end if;
  delete from codigos_operador where code = p_code;
  return json_build_object('ok', true);
end;
$$;

grant execute on function check_operator_code(text) to anon;
grant execute on function admin_generate_operator_code(text) to anon;
grant execute on function admin_revoke_operator_code(text,text) to anon;

-- ============================================================
-- LIMPEZA AUTOMÁTICA — corre sozinha a cada minuto no servidor,
-- mesmo que ninguém esteja com o app aberto. É isto que garante
-- que o chat de uma Live se apaga "em qualquer sítio" depois do fim.
-- ============================================================
create or replace function purge_ended_program_chat() returns void
language plpgsql security definer as $$
begin
  delete from mensagens where program_id in (
    select id from programacao
    where chat_purged = false and start_time + (duration_seconds || ' seconds')::interval <= now()
  );
  update programacao set chat_purged = true
  where chat_purged = false and start_time + (duration_seconds || ' seconds')::interval <= now();
end;
$$;

select cron.schedule('purge-ended-chat', '* * * * *', 'select purge_ended_program_chat();');

-- ============================================================
-- REALTIME — para o chat atualizar sozinho em todos os aparelhos
-- ============================================================
do $$
begin
  if not exists (
    select 1 from pg_publication_tables where pubname='supabase_realtime' and tablename='mensagens'
  ) then
    alter publication supabase_realtime add table mensagens;
  end if;
end $$;
