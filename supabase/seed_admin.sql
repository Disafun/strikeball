-- Делает уже созданного в Authentication пользователя администратором.
-- 1) Dashboard -> Authentication -> Users -> Add user (email + пароль, галочка Auto Confirm User).
-- 2) Подставьте ЭТУ ЖЕ почту ниже и выполните скрипт в SQL Editor.
-- Роль admin нельзя получить через API приложения - только так, из SQL Editor.
insert into public.profiles (id, full_name, age, phone, email, role)
select id, 'Администратор', 30, '00000', email, 'admin'
from auth.users
where lower(email) = lower('admin@example.com')      -- <-- ЗАМЕНИТЕ на почту админ-аккаунта
on conflict (id) do update set role = 'admin';
