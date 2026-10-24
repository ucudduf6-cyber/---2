-- Run AFTER database.sql in Supabase SQL Editor.
create table if not exists public.submissions (
 id bigint generated always as identity primary key,
 user_id uuid not null references auth.users(id) on delete cascade,
 data jsonb not null,
 status text not null default 'pending' check(status in ('pending','approved','rejected')),
 moderation_note text not null default '',
 created_at timestamptz not null default now()
);
create table if not exists public.people (
 id bigint generated always as identity primary key,
 name text not null check(length(name) between 2 and 150),
 bio text not null default '',
 created_by uuid not null references auth.users(id),
 created_at timestamptz not null default now()
);
create table if not exists public.film_people (
 film_id bigint not null references public.catalog(id) on delete cascade,
 person_id bigint not null references public.people(id) on delete cascade,
 role text not null check(length(role) between 2 and 100),
 added_by uuid not null default auth.uid() references auth.users(id),
 primary key(film_id,person_id,role)
);
alter table public.submissions enable row level security;
alter table public.people enable row level security;
alter table public.film_people enable row level security;
create policy "submission read own or admin" on public.submissions for select to authenticated using(user_id=auth.uid() or exists(select 1 from public.admins where user_id=auth.uid()));
create policy "submission insert own pending" on public.submissions for insert to authenticated with check(user_id=auth.uid() and status='pending' and jsonb_typeof(data)='object' and length(coalesce(data->>'t','')) between 1 and 160 and length(coalesce(data->>'d','')) between 20 and 5000 and data->>'type' in ('movie','series'));
create policy "people public read" on public.people for select to anon,authenticated using(true);
-- A person may be created only if the author already has an approved submission.
create policy "people create after approved film" on public.people for insert to authenticated with check(created_by=auth.uid() and exists(select 1 from public.submissions where user_id=auth.uid() and status='approved'));
create policy "people update by author or admin" on public.people for update to authenticated using(created_by=auth.uid() or exists(select 1 from public.admins where user_id=auth.uid())) with check(created_by=auth.uid() or exists(select 1 from public.admins where user_id=auth.uid()));
create policy "film_people public read" on public.film_people for select to anon,authenticated using(true);
-- Anyone who owns an approved submission for this exact published catalog entry may attach a person.
create policy "film_people insert for project owner" on public.film_people for insert to authenticated with check((added_by=auth.uid() and exists(select 1 from public.catalog c where c.id=film_id and (c.data->>'submitted_by')=auth.uid()::text)) or exists(select 1 from public.admins where user_id=auth.uid()));
create policy "film_people delete by owner" on public.film_people for delete to authenticated using(added_by=auth.uid() or exists(select 1 from public.admins where user_id=auth.uid()));
-- Permit authenticated users to upload media ONLY inside their own submissions prefix.
create policy "user media submission upload" on storage.objects for insert to authenticated with check(bucket_id='media' and (storage.foldername(name))[1]='submissions' and (storage.foldername(name))[2]=auth.uid()::text);
-- Atomic moderation. SECURITY DEFINER is limited to approved admins and fixed allowed decisions.
create or replace function public.moderate_submission(submission_id bigint, decision text, note text default '')
returns void language plpgsql security definer set search_path=public as $$
declare s public.submissions%rowtype;
begin
 if not exists(select 1 from public.admins where user_id=auth.uid()) then raise exception 'Forbidden'; end if;
 if decision not in ('approved','rejected') then raise exception 'Invalid decision'; end if;
 select * into s from public.submissions where id=submission_id for update;
 if not found or s.status<>'pending' then raise exception 'Submission not pending'; end if;
 if decision='approved' then
   insert into public.catalog(data) values (s.data || jsonb_build_object('submitted_by',s.user_id::text));
 end if;
 update public.submissions set status=decision,moderation_note=left(coalesce(note,''),500) where id=submission_id;
end $$;
revoke all on function public.moderate_submission(bigint,text,text) from public;
grant execute on function public.moderate_submission(bigint,text,text) to authenticated;
