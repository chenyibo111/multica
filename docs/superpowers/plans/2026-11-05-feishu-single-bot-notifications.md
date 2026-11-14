# Feishu Single Bot Notifications Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver selected Multica inbox notifications to a member through the sole active Feishu Bot in their workspace.

**Architecture:** Keep the existing inbox as the source of recipients and preferences. A Feishu subscriber looks up the sole active installation and the recipient's binding, checks current membership, and sends a plain-text private message to that binding's `open_id`. The send is best-effort and runs outside the synchronous event publisher.

**Tech Stack:** Go, existing event bus, sqlc `channel_*` queries, Feishu IM v1 HTTP API.

**Spec:** `docs/superpowers/specs/2026-11-05-feishu-single-bot-notifications-design.md`

## Global Constraints

- No `feishu-sso` changes, new tables, or UI settings.
- Only one active Feishu Bot per workspace is eligible; no guessing with multiple Bots.
- A failed Feishu call must not fail the issue or inbox write.
- No cross-app identity inference; only an explicit binding to the selected Bot may receive a push.

## Review Focus

- Multiple active Bots must suppress the push instead of picking the newest binding.
- Removed workspace members must not receive a push from a stale binding.
- Missing recipient, malformed IDs, and unsupported inbox types must be ignored safely.
- Member-authored titles and bodies must be sent as plain text.
- A blocked or failed Feishu API call must not delay or fail the event publisher.

---

### Task 1: Direct private text transport

**Files:** `server/internal/integrations/lark/client.go`, `server/internal/integrations/lark/http_client.go`, `server/internal/integrations/lark/http_client_test.go`

**Interface:** `SendDirectTextMessage(context.Context, SendDirectTextParams) (string, error)` with credentials, `open_id`, and text.

- [x] Write an HTTP contract test for `receive_id_type=open_id`, recipient, encoded text, and returned message ID.
- [x] Run the focused test and observe failure.
- [x] Implement the direct-message method without changing the existing chat reply API.
- [x] Run the focused transport tests.

### Task 2: Inbox notification routing

**Files:** `server/internal/integrations/lark/inbox_notifier.go`, `server/internal/integrations/lark/inbox_notifier_test.go`, `server/cmd/server/router.go`

**Interface:** `NewInboxNotifier(store, credentials, sender, appURL, logger)` and `Register(bus)`.

- [x] Write routing tests for the successful send, unsupported event, unbound member, stale membership, and multiple active Bots.
- [x] Run the focused tests and observe failure.
- [x] Implement rendering, recipient lookup, membership check, single-Bot selection, and best-effort asynchronous subscription.
- [x] Wire the subscriber beside the existing Feishu outbound components.
- [x] Run focused notifier tests, the Feishu package tests, and server compile/tests as appropriate.

### Task 3: Local usage documentation

**Files:** `apps/docs/content/docs/lark-bot-integration.zh.mdx`

- [x] Document the one-Bot notification behavior, supported events, member binding, `localhost` link limitation, and failure behavior.
- [x] Run `git diff --check` and review the full change.

## Local verification status

- Feishu package tests passed in `golang:1.27.3-alpine`; `cmd/server` test binary compiled.
- The self-host backend image built and `/readyz` returned success; startup reported the Feishu long-connection and install services enabled.
- No active Feishu Bot is connected yet. Live send/receive validation requires an operator to scan the Bot installation QR code and bind member accounts.
