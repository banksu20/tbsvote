-- Farewell Boom – Costume Vote: Supabase setup
-- วิธีใช้: Supabase Dashboard → SQL Editor → New query → วางทั้งหมด → Run
-- รันซ้ำได้ ไม่พัง

-- ---------- tables ----------
create table if not exists public.rooms (
  pin        text primary key check (pin ~ '^[0-9]{6}$'),
  owner      uuid not null default auth.uid(),
  phase      text not null default 'voting' check (phase in ('voting','closed','reveal')),
  reveal_at  bigint not null default 0,
  winners    text[] not null default '{}',
  created_at timestamptz not null default now()
);

create table if not exists public.contestants (
  id      uuid primary key default gen_random_uuid(),
  pin     text not null references public.rooms(pin) on delete cascade,
  no      int  not null default 0,
  name    text not null check (char_length(name) between 1 and 40),
  costume text not null default '' check (char_length(costume) <= 60),
  img     text not null default '' check (char_length(img) <= 400000)
);

create table if not exists public.players (
  pin        text not null references public.rooms(pin) on delete cascade,
  uid        uuid not null default auth.uid(),
  name       text not null check (char_length(name) between 1 and 30),
  created_at timestamptz not null default now(),
  primary key (pin, uid)
);

create table if not exists public.votes (
  pin        text not null references public.rooms(pin) on delete cascade,
  uid        uuid not null default auth.uid(),
  contestant uuid not null references public.contestants(id) on delete cascade,
  updated_at timestamptz not null default now(),
  primary key (pin, uid)
);

create index if not exists contestants_pin_idx on public.contestants(pin);
alter table public.contestants alter column no set default 0;

-- photo-desk helpers (staff can add names and photos from their phones)
create table if not exists public.room_keys (
  pin text primary key references public.rooms(pin) on delete cascade,
  key text not null check (char_length(key) >= 16)
);
create table if not exists public.cohosts (
  pin text not null references public.rooms(pin) on delete cascade,
  uid uuid not null,
  primary key (pin, uid)
);


-- ---------- helpers ----------
create or replace function public.is_room_owner(p text) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.rooms where pin = p and owner = auth.uid());
$$;

create or replace function public.room_is_open(p text) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.rooms where pin = p and phase = 'voting');
$$;


create or replace function public.is_room_staff(p text) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.rooms where pin = p and owner = auth.uid())
      or exists (select 1 from public.cohosts where pin = p and uid = auth.uid());
$$;

-- a helper's phone calls this with the secret from the host's photo-desk QR
create or replace function public.join_cohost(p text, k text) returns boolean
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then return false; end if;
  if exists (select 1 from public.room_keys where pin = p and key = k) then
    insert into public.cohosts(pin, uid) values (p, auth.uid()) on conflict do nothing;
    return true;
  end if;
  return false;
end;
$$;
grant execute on function public.join_cohost(text, text) to authenticated;

-- ---------- security (row level security) ----------
alter table public.rooms       enable row level security;
alter table public.contestants enable row level security;
alter table public.players     enable row level security;
alter table public.votes       enable row level security;
alter table public.room_keys   enable row level security;
alter table public.cohosts     enable row level security;

-- rooms: anyone can read a room's status; only its owner changes it
drop policy if exists rooms_read   on public.rooms;
drop policy if exists rooms_create on public.rooms;
drop policy if exists rooms_update on public.rooms;
create policy rooms_read   on public.rooms for select to anon, authenticated using (true);
create policy rooms_create on public.rooms for insert to authenticated with check (owner = auth.uid());
create policy rooms_update on public.rooms for update to authenticated using (owner = auth.uid()) with check (owner = auth.uid());

-- contestants: anyone reads; the host and photo-desk helpers add/edit/remove
drop policy if exists contestants_read   on public.contestants;
drop policy if exists contestants_insert on public.contestants;
drop policy if exists contestants_update on public.contestants;
drop policy if exists contestants_delete on public.contestants;
create policy contestants_read   on public.contestants for select to anon, authenticated using (true);
create policy contestants_insert on public.contestants for insert to authenticated with check (public.is_room_staff(pin));
create policy contestants_update on public.contestants for update to authenticated using (public.is_room_staff(pin)) with check (public.is_room_staff(pin));
create policy contestants_delete on public.contestants for delete to authenticated using (public.is_room_staff(pin));

-- players: each person writes only their own name; only the host sees the list
drop policy if exists players_read   on public.players;
drop policy if exists players_insert on public.players;
drop policy if exists players_update on public.players;
drop policy if exists players_delete on public.players;
create policy players_read   on public.players for select to authenticated using (uid = auth.uid() or public.is_room_owner(pin));
create policy players_insert on public.players for insert to authenticated with check (uid = auth.uid());
create policy players_update on public.players for update to authenticated using (uid = auth.uid()) with check (uid = auth.uid());
create policy players_delete on public.players for delete to authenticated using (public.is_room_owner(pin));

-- votes: one row per person; writable only while voting is open; only the host can read them all
drop policy if exists votes_read   on public.votes;
drop policy if exists votes_insert on public.votes;
drop policy if exists votes_update on public.votes;
drop policy if exists votes_delete on public.votes;
create policy votes_read   on public.votes for select to authenticated using (uid = auth.uid() or public.is_room_owner(pin));
create policy votes_insert on public.votes for insert to authenticated with check (
  uid = auth.uid() and public.room_is_open(pin)
  and exists (select 1 from public.contestants c where c.id = contestant and c.pin = votes.pin));
create policy votes_update on public.votes for update to authenticated using (uid = auth.uid()) with check (
  uid = auth.uid() and public.room_is_open(pin)
  and exists (select 1 from public.contestants c where c.id = contestant and c.pin = votes.pin));
create policy votes_delete on public.votes for delete to authenticated using (public.is_room_owner(pin));


-- photo-desk secret: only the host can see or create it
drop policy if exists room_keys_read   on public.room_keys;
drop policy if exists room_keys_insert on public.room_keys;
create policy room_keys_read   on public.room_keys for select to authenticated using (public.is_room_owner(pin));
create policy room_keys_insert on public.room_keys for insert to authenticated with check (public.is_room_owner(pin));

-- helpers list: added only through join_cohost(); each helper sees their own row, the host sees all
drop policy if exists cohosts_read   on public.cohosts;
drop policy if exists cohosts_delete on public.cohosts;
create policy cohosts_read   on public.cohosts for select to authenticated using (uid = auth.uid() or public.is_room_owner(pin));
create policy cohosts_delete on public.cohosts for delete to authenticated using (public.is_room_owner(pin));

-- ---------- live updates ----------
do $$
declare t text;
begin
  foreach t in array array['rooms','contestants','players','votes'] loop
    begin
      execute format('alter publication supabase_realtime add table public.%I', t);
    exception when duplicate_object then null;
    end;
  end loop;
end $$;
