-- =====================================================================
-- Страйкбол-клуб: схема, ограничения, RLS и хранилище фото для Supabase.
-- Запускать целиком в Supabase Dashboard -> SQL Editor (один раз).
-- Скрипт идемпотентен там, где это возможно (create ... if not exists /
-- drop policy if exists), но таблицы с данными он не удаляет.
-- =====================================================================

-- ---------- служебные функции ----------
create or replace function public.set_updated_at()
returns trigger language plpgsql as $$
begin
  new.updated_at := now();
  return new;
end $$;

-- ---------- профили ----------
create table if not exists public.profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  full_name   text not null check (char_length(btrim(full_name)) between 3 and 120),
  age         int  not null check (age between 10 and 99),
  phone       text not null check (char_length(phone) between 5 and 30),
  email       text not null,
  photo       text,                                   -- путь в Storage (bucket photos)
  role        text not null default 'player' check (role in ('player', 'admin')),
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);
create unique index if not exists profiles_email_lower_idx on public.profiles (lower(email));

drop trigger if exists profiles_updated_at on public.profiles;
create trigger profiles_updated_at before update on public.profiles
  for each row execute function public.set_updated_at();

-- email берётся из auth.users, клиент не может подставить чужой
create or replace function public.profiles_fill_email()
returns trigger language plpgsql security definer set search_path = public, auth as $$
begin
  select u.email into new.email from auth.users u where u.id = new.id;
  if new.email is null then
    raise exception 'auth_user_not_found';
  end if;
  return new;
end $$;

drop trigger if exists profiles_fill_email on public.profiles;
create trigger profiles_fill_email before insert on public.profiles
  for each row execute function public.profiles_fill_email();

-- проверка роли: security definer, чтобы не зациклить RLS на profiles
create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin');
$$;

-- ---------- мероприятия ----------
create table if not exists public.events (
  id            bigint generated always as identity primary key,
  title         text not null check (char_length(btrim(title)) > 0),
  description   text,
  location      text,
  photo         text,
  event_date    timestamptz not null,
  max_players   int check (max_players is null or max_players > 0),
  status        text not null default 'open' check (status in ('open', 'cancelled')),
  organizer_id  uuid references public.profiles(id) on delete set null default auth.uid(),
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);
create index if not exists events_date_idx on public.events (event_date);

drop trigger if exists events_updated_at on public.events;
create trigger events_updated_at before update on public.events
  for each row execute function public.set_updated_at();

-- ---------- записи на мероприятия ----------
create table if not exists public.registrations (
  id          bigint generated always as identity primary key,
  event_id    bigint not null references public.events(id) on delete cascade,
  user_id     uuid   not null references public.profiles(id) on delete cascade default auth.uid(),
  created_at  timestamptz not null default now(),
  constraint registrations_unique unique (event_id, user_id)   -- запрет дублей
);
create index if not exists registrations_user_idx on public.registrations (user_id);

-- Вместимость, статус и дата проверяются в БД. Строка мероприятия блокируется
-- (FOR UPDATE), поэтому параллельные заявки на последнее место выстраиваются в очередь.
create or replace function public.check_registration()
returns trigger language plpgsql security definer set search_path = public as $$
declare
  ev  public.events%rowtype;
  cnt int;
begin
  -- служебная загрузка (скрипт миграции со service_role) ограничения не проверяет
  if coalesce(nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'role', '') = 'service_role' then
    return new;
  end if;

  select * into ev from public.events where id = new.event_id for update;
  if not found then raise exception 'event_not_found'; end if;
  if ev.status <> 'open' then raise exception 'event_closed'; end if;
  if ev.event_date < now() then raise exception 'event_past'; end if;
  if ev.max_players is not null then
    select count(*) into cnt from public.registrations where event_id = new.event_id;
    if cnt >= ev.max_players then raise exception 'event_full'; end if;
  end if;
  return new;
end $$;

drop trigger if exists registrations_check on public.registrations;
create trigger registrations_check before insert on public.registrations
  for each row execute function public.check_registration();

-- ---------- галерея ----------
create table if not exists public.albums (
  id          bigint generated always as identity primary key,
  title       text not null check (char_length(btrim(title)) > 0),
  created_at  timestamptz not null default now()
);

create table if not exists public.photos (
  id          bigint generated always as identity primary key,
  album_id    bigint not null references public.albums(id) on delete cascade,
  user_id     uuid references public.profiles(id) on delete set null default auth.uid(),
  path        text not null,                          -- путь в Storage
  created_at  timestamptz not null default now()
);
create index if not exists photos_album_idx on public.photos (album_id);

-- ---------- представления ----------
-- Публичная часть профиля (без телефона и почты). Намеренно выполняется с правами
-- владельца, чтобы игроки видели имена друг друга; Supabase Advisor может показать
-- предупреждение "security definer view" - для этого представления это ожидаемо.
create or replace view public.public_profiles as
  select id, full_name, age, photo from public.profiles;

-- Счётчики: выполняются с правами вызывающего (RLS учитывается)
create or replace view public.event_stats with (security_invoker = true) as
  select e.id as event_id, count(r.id)::int as cnt
  from public.events e left join public.registrations r on r.event_id = e.id
  group by e.id;

create or replace view public.album_stats with (security_invoker = true) as
  select a.id as album_id, count(p.id)::int as cnt,
         (select p2.path from public.photos p2 where p2.album_id = a.id order by p2.id desc limit 1) as cover
  from public.albums a left join public.photos p on p.album_id = a.id
  group by a.id;

-- ---------- права доступа (GRANT) ----------
revoke all on public.profiles, public.events, public.registrations, public.albums,
              public.photos, public.public_profiles, public.event_stats, public.album_stats
  from anon, authenticated;

grant select on public.profiles to authenticated;
grant insert (id, full_name, age, phone, photo) on public.profiles to authenticated;   -- role/email не вставить
grant update (full_name, age, phone, photo)     on public.profiles to authenticated;   -- role менять нельзя

grant select, delete on public.events to authenticated;
grant insert (title, description, location, photo, event_date, max_players, status) on public.events to authenticated;
grant update (title, description, location, photo, event_date, max_players, status) on public.events to authenticated;

grant select, delete on public.registrations to authenticated;
grant insert (event_id, user_id) on public.registrations to authenticated;

grant select, delete on public.albums to authenticated;
grant insert (title) on public.albums to authenticated;
grant update (title) on public.albums to authenticated;

grant select, delete on public.photos to authenticated;
grant insert (album_id, user_id, path) on public.photos to authenticated;

grant select on public.public_profiles, public.event_stats, public.album_stats to authenticated;

-- ---------- RLS ----------
alter table public.profiles      enable row level security;
alter table public.events        enable row level security;
alter table public.registrations enable row level security;
alter table public.albums        enable row level security;
alter table public.photos        enable row level security;

-- profiles: свой профиль или админ. Телефоны и почты остальным недоступны.
drop policy if exists profiles_select on public.profiles;
create policy profiles_select on public.profiles for select to authenticated
  using (id = auth.uid() or public.is_admin());
drop policy if exists profiles_insert on public.profiles;
create policy profiles_insert on public.profiles for insert to authenticated
  with check (id = auth.uid());
drop policy if exists profiles_update on public.profiles;
create policy profiles_update on public.profiles for update to authenticated
  using (id = auth.uid() or public.is_admin()) with check (id = auth.uid() or public.is_admin());

-- events: читают все вошедшие, пишет только админ
drop policy if exists events_select on public.events;
create policy events_select on public.events for select to authenticated using (true);
drop policy if exists events_admin_insert on public.events;
create policy events_admin_insert on public.events for insert to authenticated with check (public.is_admin());
drop policy if exists events_admin_update on public.events;
create policy events_admin_update on public.events for update to authenticated
  using (public.is_admin()) with check (public.is_admin());
drop policy if exists events_admin_delete on public.events;
create policy events_admin_delete on public.events for delete to authenticated using (public.is_admin());

-- registrations: видны всем вошедшим (состав команды), записаться можно только за себя,
-- отменить - себе, убрать любого - админу
drop policy if exists reg_select on public.registrations;
create policy reg_select on public.registrations for select to authenticated using (true);
drop policy if exists reg_insert on public.registrations;
create policy reg_insert on public.registrations for insert to authenticated
  with check (user_id = auth.uid());
drop policy if exists reg_delete on public.registrations;
create policy reg_delete on public.registrations for delete to authenticated
  using (user_id = auth.uid() or public.is_admin());

-- albums: читают все, управляет админ
drop policy if exists albums_select on public.albums;
create policy albums_select on public.albums for select to authenticated using (true);
drop policy if exists albums_admin_insert on public.albums;
create policy albums_admin_insert on public.albums for insert to authenticated with check (public.is_admin());
drop policy if exists albums_admin_update on public.albums;
create policy albums_admin_update on public.albums for update to authenticated
  using (public.is_admin()) with check (public.is_admin());
drop policy if exists albums_admin_delete on public.albums;
create policy albums_admin_delete on public.albums for delete to authenticated using (public.is_admin());

-- photos: читают все, добавить можно только от своего имени, удалить - своё или любое (админ)
drop policy if exists photos_select on public.photos;
create policy photos_select on public.photos for select to authenticated using (true);
drop policy if exists photos_insert on public.photos;
create policy photos_insert on public.photos for insert to authenticated
  with check (user_id = auth.uid());
drop policy if exists photos_delete on public.photos;
create policy photos_delete on public.photos for delete to authenticated
  using (user_id = auth.uid() or public.is_admin());

-- ---------- Storage: bucket photos ----------
-- Публичный bucket: файл открывается по ссылке (имена - случайные UUID).
-- Лимит 10 МБ и только картинки проверяются самим Storage.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('photos', 'photos', true, 10485760, array['image/jpeg', 'image/png', 'image/gif', 'image/webp'])
on conflict (id) do update
  set public = excluded.public,
      file_size_limit = excluded.file_size_limit,
      allowed_mime_types = excluded.allowed_mime_types;

-- загружать можно только в свою папку <uid>/..., удалять - из своей папки или админу
drop policy if exists photos_bucket_insert on storage.objects;
create policy photos_bucket_insert on storage.objects for insert to authenticated
  with check (bucket_id = 'photos' and (storage.foldername(name))[1] = auth.uid()::text);
drop policy if exists photos_bucket_delete on storage.objects;
create policy photos_bucket_delete on storage.objects for delete to authenticated
  using (bucket_id = 'photos' and ((storage.foldername(name))[1] = auth.uid()::text or public.is_admin()));
