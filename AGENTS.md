# Agent Instructions

## Verbindliche Branch-/Worktree-Angabe nach Pushes

Sobald in einem Auftrag mindestens ein Commit gepusht wurde, muss die
abschliessende Nutzerzusammenfassung fuer jedes betroffene Repository den
tatsaechlich verwendeten Branch und den konkreten absoluten Worktree-Pfad
ausgeben. Diese Angabe steht neben der ohnehin vorgeschriebenen Anzahl der
eingesetzten Sub-Agenten und deren Einstellungen, damit der Nutzer den
Arbeitsort und das Push-Ziel unmittelbar vergleichen kann. Wurden mehrere
Repositories oder Worktrees verwendet, werden sie einzeln und eindeutig
zugeordnet aufgefuehrt.

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

## Repository Boundaries

This Auth Gateway repository is not a source or deployment target for the
public website or any mobile client. Website and client work is maintained in
separately governed repositories and must follow the authoritative agent rules
of those repositories.

A website or client task does not authorize changes or deployments to Auth
Gateway, its configuration, or infrastructure. Historical client sources are
reference-only and must not be treated as an active implementation or release
source. If the owning repository or its rules cannot be identified, stop and
ask before making a cross-repository change.
