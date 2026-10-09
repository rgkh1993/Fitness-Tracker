-- Cloud backup for gym-tracker_v2.html.
--
-- The whole app state is one JSON document. The page calls gym_pull/gym_push
-- with a PIN; the newest save wins. A daily snapshot is kept in
-- gym.state_history so an accidental wipe can be rolled back.

create schema if not exists gym;
create extension if not exists pgcrypto with schema extensions;

create table gym.state (
  id int primary key default 1 check (id = 1),
  data jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default 'epoch',
  pin_hash text not null
);

create table gym.state_history (
  id bigserial primary key,
  data jsonb not null,
  updated_at timestamptz not null,
  saved_at timestamptz not null default now()
);

create table gym.pin_attempts (
  id bigserial primary key,
  ok boolean not null,
  at timestamptz not null default now()
);

alter table gym.state enable row level security;
alter table gym.state_history enable row level security;
alter table gym.pin_attempts enable row level security;
revoke all on all tables in schema gym from anon, authenticated;

create function gym.check_pin(p_pin text) returns void
language plpgsql security definer set search_path = '' as $$
declare v_ok boolean;
begin
  if (select count(*) from gym.pin_attempts where not ok and at > now() - interval '15 minutes') >= 20 then
    raise exception 'locked';
  end if;
  select pin_hash = extensions.crypt(p_pin, pin_hash) into v_ok from gym.state where id = 1;
  insert into gym.pin_attempts (ok) values (coalesce(v_ok, false));
  if not coalesce(v_ok, false) then
    raise exception 'bad_pin';
  end if;
end
$$;

create function public.gym_pull(p_pin text) returns jsonb
language plpgsql security definer set search_path = '' as $$
begin
  perform gym.check_pin(p_pin);
  return (select jsonb_build_object('data', data, 'updated_at', updated_at) from gym.state where id = 1);
end
$$;

-- Saves only if this copy is at least as new as the stored one; always
-- returns what is stored afterwards so the page can adopt a newer copy.
create function public.gym_push(p_pin text, p_data jsonb, p_updated_at timestamptz) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare v_prev gym.state;
begin
  perform gym.check_pin(p_pin);
  select * into v_prev from gym.state where id = 1 for update;
  if p_updated_at >= v_prev.updated_at then
    if v_prev.data <> '{}'::jsonb and not exists (
      select 1 from gym.state_history where saved_at > now() - interval '1 day'
    ) then
      insert into gym.state_history (data, updated_at) values (v_prev.data, v_prev.updated_at);
    end if;
    update gym.state set data = p_data, updated_at = p_updated_at where id = 1;
  end if;
  return (select jsonb_build_object('data', data, 'updated_at', updated_at) from gym.state where id = 1);
end
$$;

revoke execute on function gym.check_pin(text) from public, anon, authenticated;
revoke execute on function public.gym_pull(text) from public;
revoke execute on function public.gym_push(text, jsonb, timestamptz) from public;
grant execute on function public.gym_pull(text) to anon, authenticated;
grant execute on function public.gym_push(text, jsonb, timestamptz) to anon, authenticated;
