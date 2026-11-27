create table if not exists public.profehub_state (
    key text primary key,
    value jsonb not null default '{}'::jsonb
);

alter table public.profehub_state enable row level security;
grant all on public.profehub_state to service_role;

create or replace function public.profehub_update_state(
    p_key text,
    p_changes jsonb,
    p_deletions text[]
) returns void
language plpgsql
security definer
set search_path = public
as $$
begin
    insert into public.profehub_state (key, value)
    values (p_key, '{}'::jsonb)
    on conflict (key) do nothing;

    update public.profehub_state
    set value = (value - coalesce(p_deletions, array[]::text[]))
                || coalesce(p_changes, '{}'::jsonb)
    where key = p_key;
end;
$$;

revoke all on function public.profehub_update_state(text, jsonb, text[])
    from public, anon, authenticated;
grant execute on function public.profehub_update_state(text, jsonb, text[])
    to service_role;

insert into storage.buckets (id, name, public)
values ('profhub-pdfs', 'profhub-pdfs', false)
on conflict (id) do nothing;
