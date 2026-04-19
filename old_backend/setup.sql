-- Run this once in Supabase SQL Editor (https://supabase.com/dashboard → SQL Editor)

create table if not exists users (
    id            bigserial primary key,
    username      text unique not null,
    password_hash text not null,
    created_at    timestamptz default now()
);

create table if not exists repositories (
    id         bigserial primary key,
    user_id    bigint references users(id) on delete cascade,
    url        text not null,
    owner      text,
    repo_name  text,
    scanned_at timestamptz default now(),
    unique(user_id, url)
);

create table if not exists scan_results (
    id                bigserial primary key,
    repo_id           bigint references repositories(id) on delete cascade,
    package_name      text,
    installed_version text,
    vuln_id           text,
    severity          text,
    cvss              float,
    risk_score        float,
    summary           text,
    affected_file     text,
    line_number       int,
    fix_suggestion    text,
    risk_impact       text
);

create table if not exists cve_cache (
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
alter table users          disable row level security;
alter table repositories   disable row level security;
alter table scan_results   disable row level security;
alter table cve_cache      disable row level security;
