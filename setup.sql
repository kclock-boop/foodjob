-- 신규 프로젝트에서 한 번 실행하세요. 기존 테이블은 삭제하지 않습니다.
begin;
create table public.departments(id bigint generated always as identity primary key, name text unique not null);
insert into public.departments(name) values ('생산1팀'),('스파이럴'),('고속/가압'),('성형'),('용접'),('열처리'),('산업용모터(JY)'),('생산2팀'),('TRF'),('SHELL'),('ac comp'),('동서일렉'),('공사인원');
create table public.profiles(id uuid primary key references auth.users on delete cascade, name text not null, email text not null, role text not null default 'user' check(role in ('admin','user')), active boolean not null default false, department_id bigint references public.departments);
create table public.days(day date primary key, closed boolean not null default false);
create table public.meals(day date not null references public.days, department_id bigint not null references public.departments, day_count integer not null check(day_count between 0 and 10000), night_count integer not null check(night_count between 0 and 10000), detail text not null default '' check(length(detail)<=500), version integer not null default 1, updated_by uuid references auth.users, updated_at timestamptz not null default now(), primary key(day,department_id));
create table public.operations(day date not null references public.days, category text not null check(category in ('식당','차량')), name text not null, shift text not null check(shift in ('주간','야간','공통')), enabled boolean not null, primary key(day,category,name,shift));
create table public.audit(id bigint generated always as identity primary key, at timestamptz not null default now(), actor uuid, action text not null, payload jsonb not null);
create function public.new_meal_user() returns trigger language plpgsql security definer set search_path=public as $$ begin insert into public.profiles(id,name,email) values(new.id,coalesce(nullif(new.raw_user_meta_data->>'name',''),'사용자'),new.email); return new; end $$;
create trigger meal_user_created after insert on auth.users for each row execute function public.new_meal_user();
create function public.is_admin() returns boolean language sql stable security definer set search_path=public as $$ select exists(select 1 from profiles where id=auth.uid() and active and role='admin') $$;
create function public.is_active() returns boolean language sql stable security definer set search_path=public as $$ select exists(select 1 from profiles where id=auth.uid() and active) $$;
create function public.my_department() returns bigint language sql stable security definer set search_path=public as $$ select department_id from profiles where id=auth.uid() and active $$;
alter table public.departments enable row level security;
alter table public.profiles enable row level security;
alter table public.days enable row level security;
alter table public.meals enable row level security;
alter table public.operations enable row level security;
alter table public.audit enable row level security;
create policy dept_read on public.departments for select to authenticated using(public.is_active());
create policy dept_admin on public.departments for insert to authenticated with check(public.is_admin());
create policy profile_read on public.profiles for select to authenticated using(id=auth.uid() or public.is_admin());
create policy days_read on public.days for select to authenticated using(public.is_active());
create policy meals_read on public.meals for select to authenticated using(public.is_admin() or department_id=public.my_department());
create policy ops_read on public.operations for select to authenticated using(public.is_active());
create policy audit_read on public.audit for select to authenticated using(public.is_admin());
-- 업무 데이터 쓰기는 아래 함수만 사용합니다. UI를 우회해도 서버 권한이 적용됩니다.
revoke all on public.profiles,public.days,public.meals,public.operations,public.audit,public.departments from anon,authenticated;
grant select on public.profiles,public.days,public.meals,public.operations,public.audit,public.departments to authenticated;
grant insert on public.departments to authenticated;
grant usage, select on sequence public.departments_id_seq to authenticated;
create function public.save_meal(p_day date,p_department bigint,p_day_count integer,p_night_count integer,p_detail text,p_version integer) returns void language plpgsql security definer set search_path=public as $$
declare v integer; locked boolean;
begin
 if not public.is_active() or (not public.is_admin() and p_department is distinct from public.my_department()) then raise exception '권한이 없습니다'; end if;
 insert into days(day) values(p_day) on conflict do nothing;
 select closed into locked from days where day=p_day for update;
 if locked then raise exception '마감된 날짜입니다. 관리자에게 마감 해제를 요청하세요'; end if;
 select version into v from meals where day=p_day and department_id=p_department;
 if coalesce(v,0)<>p_version then raise exception '다른 사용자가 수정했습니다. 새로고침 후 다시 입력하세요'; end if;
 insert into meals(day,department_id,day_count,night_count,detail,updated_by) values(p_day,p_department,p_day_count,p_night_count,p_detail,auth.uid()) on conflict(day,department_id) do update set day_count=excluded.day_count,night_count=excluded.night_count,detail=excluded.detail,version=meals.version+1,updated_at=now(),updated_by=auth.uid();
 insert into audit(actor,action,payload) values(auth.uid(),'식수 저장',jsonb_build_object('day',p_day,'department',p_department,'주간',p_day_count,'야간',p_night_count,'상세',p_detail));
end $$;
create function public.set_day_closed(p_day date,p_closed boolean) returns void language plpgsql security definer set search_path=public as $$ begin
 if not public.is_admin() then raise exception '관리자 권한이 필요합니다'; end if;
 insert into days(day,closed) values(p_day,p_closed) on conflict(day) do update set closed=excluded.closed;
 insert into audit(actor,action,payload) values(auth.uid(),'마감 변경',jsonb_build_object('day',p_day,'closed',p_closed)); end $$;
create function public.save_operation(p_day date,p_category text,p_name text,p_shift text,p_enabled boolean) returns void language plpgsql security definer set search_path=public as $$ declare locked boolean; begin
 if not public.is_admin() then raise exception '관리자 권한이 필요합니다'; end if;
 insert into days(day) values(p_day) on conflict do nothing;
 select closed into locked from days where day=p_day for update;
 if locked then raise exception '마감된 날짜입니다'; end if;
 if not ((p_category='식당' and p_name in ('중식','석식','야식') and p_shift='공통') or (p_category='차량' and p_name in ('창원1','창원2','마산','진해','김해/부산') and p_shift in ('주간','야간'))) then raise exception '잘못된 운영 항목'; end if;
 insert into operations values(p_day,p_category,p_name,p_shift,p_enabled) on conflict(day,category,name,shift) do update set enabled=excluded.enabled;
 insert into audit(actor,action,payload) values(auth.uid(),'운영 변경',jsonb_build_object('day',p_day,'category',p_category,'name',p_name,'shift',p_shift,'enabled',p_enabled)); end $$;
create function public.manage_user(p_id uuid,p_active boolean,p_role text,p_department bigint) returns void language plpgsql security definer set search_path=public as $$ begin
 if not public.is_admin() then raise exception '관리자 권한이 필요합니다'; end if;
 if p_id=auth.uid() then raise exception '자신의 권한은 변경할 수 없습니다'; end if;
 update profiles set active=p_active,role=p_role,department_id=p_department where id=p_id;
 if not found then raise exception '사용자를 찾지 못했습니다'; end if;
 insert into audit(actor,action,payload) values(auth.uid(),'사용자 변경',jsonb_build_object('id',p_id,'active',p_active,'role',p_role,'department',p_department)); end $$;
revoke execute on function public.save_meal(date,bigint,integer,integer,text,integer), public.set_day_closed(date,boolean), public.save_operation(date,text,text,text,boolean), public.manage_user(uuid,boolean,text,bigint) from public,anon;
grant execute on function public.save_meal(date,bigint,integer,integer,text,integer), public.set_day_closed(date,boolean), public.save_operation(date,text,text,text,boolean), public.manage_user(uuid,boolean,text,bigint) to authenticated;
commit;
