-- Run this once in Supabase SQL Editor (https://supabase.com/dashboard → SQL Editor)

create table if not exists hx_users (
    id            bigserial primary key,
    github_id     bigint unique,
    username      text unique not null,
    github_token  text,
    avatar_url    text,
    email         text,
    password_hash text not null,
    created_at    timestamptz default now()
);

create table if not exists hx_repositories (
    id            bigserial primary key,
    user_id       bigint references hx_users(id) on delete cascade,
    url           text not null,
    owner         text,
    repo_name     text,
    is_moderated  boolean default false,
    scanned_at    timestamptz default now(),
    unique(user_id, url)
);

create table if not exists hx_scan_results (
    id                bigserial primary key,
    repo_id           bigint references hx_repositories(id) on delete cascade,
    package_name      text,
    installed_version text,
    vuln_id           text,
    severity          text,
    cvss              float,
    risk_score        float,
    summary           text,
    source_manifest   text,
    affected_file     text,
    line_number       int,
    fix_suggestion    text,
    risk_impact       text
);

create table if not exists hx_cve_cache (
    id           bigserial primary key,
    ghsa_id      text unique,
    package_name text,
    severity     text,
    cvss         float,
    summary      text,
    published_at text,
    fetched_at   timestamptz default now()
);

-- disable RLS so the anon key can read/write (fine for hackathon)
alter table hx_users          disable row level security;
alter table hx_repositories   disable row level security;
alter table hx_scan_results   disable row level security;
alter table hx_cve_cache      disable row level security;

-- Force Supabase to refresh its Data API Cache (handled automatically by the SQL Editor)
-- NOTIFY pgrst, 'reload schema';
