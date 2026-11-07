-- One-time wallet challenges for signed community score submissions.
create table if not exists public.score_challenges (
  id uuid primary key default gen_random_uuid(),
  wallet_address text not null check (wallet_address ~ '^0x[a-fA-F0-9]{40}$'),
  message text not null,
  expires_at timestamptz not null,
  consumed_at timestamptz,
  created_at timestamptz not null default now()
);

alter table public.score_challenges enable row level security;
revoke all on public.score_challenges from anon, authenticated;
grant all on public.score_challenges to service_role;\ngrant all on public.scores to service_role;

-- Browser clients can read the public leaderboard, but only the Edge Function
-- (using the server-only service role key) can create score rows.
revoke insert, update, delete on public.scores from anon, authenticated;
grant select on public.scores to anon, authenticated;
