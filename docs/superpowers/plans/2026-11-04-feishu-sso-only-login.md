# Feishu SSO-Only Login Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let Feishu members enter Multica as independent SSO-only accounts, including duplicate-email users, with immediate session and PAT rejection after SSO logout.

**Architecture:** OIDC authorization code with PKCE establishes a verified `(issuer, subject)` identity. Multica stores separate local and Feishu account types, issues its own JWT/PAT credentials carrying Hydra `sid`, and checks SSO revocation on every protected request for those credentials. Email remains profile data and can be duplicated across account types.

**Tech Stack:** Go/Chi/sqlc/PostgreSQL, Next.js/React/TypeScript, Electron, Docker Compose, Ory Hydra.

**Spec:** `docs/superpowers/specs/2026-11-04-feishu-sso-only-multica-design.md`

**Provider plan:** `D:/AI/feishu-sso/docs/superpowers/plans/2026-11-04-multica-oidc-provider.md`

## Global Constraints

- Base branch is `internal/main`; work on `feat/feishu-sso-only-login`.
- Keep existing local users' email/Google login, JWT, and PAT behavior.
- Use verified OIDC `(iss, sub)` and expected Feishu tenant/app claims as identity; never merge by email.
- Treat SSO email as unverified and possibly empty; preserve account identity when it changes.
- Reject revoked SSO JWT/PAT on the next protected request, including a PAT cache hit; return 503 when the SSO status service is unavailable.
- Follow `AGENTS.md` migration, sqlc, API compatibility, and UI localization rules.

## Review Focus

- Two users have the same email: local auth reaches only the local account, SSO reaches only the Feishu account.
- Two Feishu users have the same or empty email: each keeps a unique `(iss, sub)` account.
- OIDC callback has a bad state, nonce, signature, issuer, audience, tenant, or app: no user or session is created.
- A cached PAT is used just after global logout: it is rejected before the handler runs.
- An invitation targets one of two same-email accounts: only that `user_id` can view and accept it.

---

## File Map

- `server/migrations/`, `server/pkg/db/queries/user.sql`, `server/pkg/db/queries/personal_access_token.sql`, `server/pkg/db/queries/invitation.sql`: user identity, partial email uniqueness, session-linked PAT, and account-targeted invitations.
- `server/internal/handler/feishu_oidc.go` and tests: OIDC start/callback and user provisioning.
- `server/internal/auth/feishu_oidc.go` and tests: state/nonce/PKCE, token exchange, ID Token verification, and SSO status client.
- `server/internal/handler/auth.go`, `server/internal/handler/personal_access_token.go`, `server/internal/middleware/auth.go`: local-login isolation and JWT/PAT SSO `sid` propagation/checks.
- `server/cmd/server/router.go`, `server/internal/handler/config.go`, `docker-compose.selfhost.yml`, `.env.example`: routes and deployment configuration.
- `apps/web/app/(auth)/login/page.tsx`, `packages/views/auth/login-page.tsx`, `packages/core/`: Feishu entry and handoff state; desktop/CLI wiring only where existing flow requires it.
- `server/internal/handler/invitation.go`, `packages/views/` invitation UI: explicit recipient account selection when an email matches multiple users.

### Task 1: User identity and duplicate email schema

**Files:** Create sequential migration files under `server/migrations/`; modify `server/pkg/db/queries/user.sql`; test beside query/handler users; regenerate `server/pkg/db/generated/` with `make sqlc`.

**Interfaces:** `user.auth_source` defaults to `local`; Feishu rows store `oidc_issuer` and `oidc_subject`; `GetUserByEmail` returns local users only; new `GetUserByOIDC` and `CreateFeishuUser` queries; unique partial index on local email and unique index on non-null `(oidc_issuer, oidc_subject)`.

- [ ] Add DB tests for duplicate email across account types, duplicate/empty Feishu email, unique local email, and unique OIDC identity.
- [ ] Run the focused DB tests and confirm they fail on the current schema.
- [ ] Add columns; create each new index with its own single-statement `CREATE UNIQUE INDEX CONCURRENTLY` migration; drop the old global email constraint only after the local partial index exists. Add queries and run `make sqlc`.
- [ ] Run focused DB tests and `make test`; confirm they pass.
- [ ] Commit `feat: store independent Feishu identities`.

### Task 2: OIDC callback and account provisioning

**Files:** Create `server/internal/auth/feishu_oidc.go`, `server/internal/handler/feishu_oidc.go` and tests; modify `server/cmd/server/router.go`.

**Interfaces:** `GET /auth/feishu/start` stores short-lived state/nonce/PKCE in HttpOnly cookie and redirects to Hydra; `GET /auth/feishu/callback` validates the OIDC response and creates or loads a user by `(iss, sub)` in a transaction; the resulting Multica JWT contains Hydra `sid`.

- [ ] Add tests for the successful first/repeat login and the Review Focus OIDC rejection matrix, including email changes and concurrent first login.
- [ ] Run focused tests and confirm missing implementation fails.
- [ ] Implement the OIDC client with public issuer and internal token/JWKS addresses, callback checks, tenant/app checks, transactional provisioning, and safe `next`/CLI/desktop redirect state.
- [ ] Run focused tests and `make test`; confirm they pass.
- [ ] Commit `feat: authenticate Feishu OIDC users`.

### Task 3: Block other login methods for Feishu users

**Files:** Modify `server/internal/handler/auth.go`; test `server/internal/handler/auth_signup_test.go`, `auth_google_error_code_test.go`, and focused new cases.

**Interfaces:** `SendCode`, `VerifyCode`, and `GoogleLogin` never issue a session for a Feishu row. Existing local row with the same email continues to authenticate. When only a Feishu row has that email, return a stable `feishu_login_required` error rather than creating a local row.

- [ ] Add tests for email code and Google with Feishu-only email, local/Feishu duplicate email, and changed Feishu email.
- [ ] Run focused handler tests and confirm new cases fail.
- [ ] Add local-only lookup and the server-side issuance guard; keep UI errors actionable.
- [ ] Run focused tests and `make test`; confirm they pass.
- [ ] Commit `feat: enforce Feishu-only account login`.

### Task 4: Session-linked JWT and PAT revocation

**Files:** Modify `server/internal/handler/auth.go`, `server/internal/handler/personal_access_token.go`, `server/internal/middleware/auth.go`, `server/pkg/db/queries/personal_access_token.sql`; add migration and tests under `server/internal/auth/`, `server/internal/middleware/`, `server/internal/handler/`.

**Interfaces:** SSO JWTs carry `sso_sid`; Feishu PAT rows carry the same `sso_sid`, inherited through JWT-to-PAT and PAT-to-PAT minting. The middleware checks `POST /internal/session-status` with `X-SSO-Service-Key` on every SSO JWT/PAT request, even when the PAT DB cache hits. Revoked => 401; SSO unavailable => 503.

- [ ] Add tests for JWT renewal/CLI handoff retaining `sso_sid`, PAT mint/inheritance, cache-hit revocation, PAT renewal after logout, SSO outage, and unchanged local credentials.
- [ ] Run focused auth/middleware/handler tests and confirm new cases fail.
- [ ] Implement sid propagation and central status client; update PAT cache entry shape or bypass its identity shortcut for SSO PATs without skipping the status check.
- [ ] Run focused tests and `make test`; confirm they pass.
- [ ] Commit `feat: revoke Feishu sessions and PATs on SSO logout`.

### Task 5: Invitations for same-email accounts

**Files:** Modify `server/pkg/db/queries/invitation.sql`, `server/internal/handler/invitation.go`, relevant request schemas and `packages/views/` invitation components; add nearby Go and UI tests.

**Interfaces:** Existing users are invited by explicit `invitee_user_id`; duplicate-email search returns selectable accounts. If an invitation has a target ID, only that account may list/accept/decline it. Email-only legacy invitations remain available to local accounts, not unverified Feishu accounts.

- [ ] Add tests for same-email recipient selection, ID-bound invitation access, and email-only legacy invitation isolation.
- [ ] Run focused Go/UI tests and confirm new cases fail.
- [ ] Implement account selection, scoped SQL queries, and handler checks; regenerate sqlc and update API response schemas.
- [ ] Run focused tests, `make test`, and `pnpm typecheck`; confirm they pass.
- [ ] Commit `feat: target invitations to independent accounts`.

### Task 6: Web login, logout, and client handoff

**Files:** Modify `apps/web/app/(auth)/login/page.tsx`, `packages/views/auth/login-page.tsx`, `packages/core/config/`, web callback and logout wiring; add nearby UI tests and required translations.

**Interfaces:** A Feishu button appears only when the server config enables SSO; web/desktop/CLI handoff parameters survive the OIDC round-trip; SSO users' logout starts Hydra end-session and returns to a signed-out page without auto-login.

- [ ] Add UI tests for button visibility, safe redirect/handoff state, logout, and localized errors.
- [ ] Run focused UI tests and confirm new cases fail.
- [ ] Implement shared login UI and web-specific navigation using existing auth-store and handoff conventions.
- [ ] Run focused UI tests, `pnpm typecheck`, and `pnpm lint`; confirm they pass.
- [ ] Commit `feat: expose Feishu login across Multica clients`.

### Task 7: Docker configuration and end-to-end integration

**Files:** Modify `docker-compose.selfhost.yml`, `.env.example`, self-hosting docs and focused integration tests; consume the SSO Compose network and client from the provider plan.

**Interfaces:** Browser sees `localhost:4444/` issuer; Multica backend reaches `hydra:4444` and `sso:9000`; secrets stay in ignored `.env`.

- [ ] Add configuration tests for missing OIDC values, issuer/internal endpoint separation, and disabled SSO mode.
- [ ] Run config tests and confirm new cases fail.
- [ ] Add opt-in Compose network/env wiring and documentation; keep existing self-hosting unchanged when SSO is disabled.
- [ ] Run `docker compose config`, `make check`, and a real two-member local flow: duplicate email, repeat login, web/CLI/desktop PAT usage, and global logout rejection.
- [ ] Commit `docs: configure local Feishu SSO integration` and record exact verification outcomes.

## Final Verification

- [ ] Confirm both repositories are on their requested feature branches and clean after commits.
- [ ] Run `git diff --check` and the repository's narrowest relevant Go/UI checks; report any skipped gate explicitly.
- [ ] Verify no secret, raw token, or full member email appears in commits or logs.
