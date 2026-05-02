# Agent Instructions

Assume the worktree can be dirty.

Before every commit or deploy, run `git status` and briefly name the concrete
files that will be affected. Commit only explicitly intended files and push the
commit directly when a push is requested. Do not include unrelated local
changes.

Document work in rollback-friendly Markdown files inside this project.

## Private Repositories

Host-specific documentation, recovery notes, internal deployment notes,
infrastructure paths, and placeholder `.env.example` files are acceptable in
private repositories. Real secrets, API keys, private keys, tokens,
certificates, wallet files, productive `.env` files, or other sensitive content
must never be committed or pushed.

## Public Repositories

Be stricter. Do not include private paths, internal infrastructure details,
recovery internals, local user paths, or production configuration hints with
sensitive details. Example values and clearly marked example files are allowed.

## General

When files or contents look suspicious, check whether they contain real secrets,
production credentials, or only documentation and placeholders. If unsure, do
not commit or push; name and assess the finding first.

Generated reports, build artifacts, test outputs, and tool noise should not be
added to the repository unless explicitly requested.

