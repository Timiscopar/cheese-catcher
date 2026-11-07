-- Store only hashed short-lived player session tokens. The raw bearer token is returned once.
create table if not exists public.player_sessions (
  token_hash text primary key,
  wallet_address text not null check (wallet_address ~ '^0x[a-fA-F0-9]{40}$'),
  expires_at timestamptz not null,
  last_used_at timestamptz,
  created_at timestamptz not null default now()
);

alter table public.player_sessions enable row level security;
revoke all on public.player_sessions from anon, authenticated;
grant all on public.player_sessions to service_role;

-- Only the Edge Function may write scores.
revoke insert, update, delete on public.scores from anon, authenticated;
grant select on public.scores to anon, authenticated;
