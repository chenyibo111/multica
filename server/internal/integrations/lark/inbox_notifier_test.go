package lark

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/multica-ai/multica/server/internal/events"
	"github.com/multica-ai/multica/server/internal/util"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
	"github.com/multica-ai/multica/server/pkg/protocol"
)

const (
	notifyWorkspaceID = "11111111-1111-4111-8111-111111111111"
	notifyMemberID    = "22222222-2222-4222-8222-222222222222"
	notifyInstallID   = "33333333-3333-4333-8333-333333333333"
	notifyIssueID     = "44444444-4444-4444-8444-444444444444"
)

type fakeInboxNotifierStore struct {
	installations []Installation
	binding       db.ChannelUserBinding
	bindErr       error
	member        bool
	workspace     db.Workspace
}

func (s *fakeInboxNotifierStore) ListLarkInstallationsByWorkspace(context.Context, pgtype.UUID) ([]Installation, error) {
	return s.installations, nil
}

func (s *fakeInboxNotifierStore) FindChannelBindingForMember(context.Context, db.FindChannelBindingForMemberParams) (db.ChannelUserBinding, error) {
	return s.binding, s.bindErr
}

func (s *fakeInboxNotifierStore) IsWorkspaceMember(context.Context, pgtype.UUID, pgtype.UUID) (bool, error) {
	return s.member, nil
}

func (s *fakeInboxNotifierStore) GetWorkspace(context.Context, pgtype.UUID) (db.Workspace, error) {
	return s.workspace, nil
}

type fakeDirectTextSender struct {
	sent []SendDirectTextParams
	err  error
}

func (s *fakeDirectTextSender) SendDirectTextMessage(_ context.Context, p SendDirectTextParams) (string, error) {
	s.sent = append(s.sent, p)
	return "om_notification", s.err
}

func notifierEvent(notifType string) events.Event {
	issueID := notifyIssueID
	return events.Event{Type: protocol.EventInboxNew, WorkspaceID: notifyWorkspaceID, Payload: map[string]any{
		"item": map[string]any{
			"id":             "55555555-5555-4555-8555-555555555555",
			"workspace_id":   notifyWorkspaceID,
			"recipient_type": "member",
			"recipient_id":   notifyMemberID,
			"type":           notifType,
			"title":          "修复登录",
			"body":           "请今天处理",
			"issue_id":       &issueID,
		},
	}}
}

func notifierFixture() (*InboxNotifier, *fakeInboxNotifierStore, *fakeDirectTextSender) {
	store := &fakeInboxNotifierStore{
		installations: []Installation{{
			ID: util.MustParseUUID(notifyInstallID), WorkspaceID: util.MustParseUUID(notifyWorkspaceID),
			Status: "active", AppID: "cli_notify", Region: "feishu",
		}},
		binding: db.ChannelUserBinding{
			InstallationID: util.MustParseUUID(notifyInstallID), ChannelUserID: "ou_member_1",
		},
		member:    true,
		workspace: db.Workspace{Slug: "demo-team"},
	}
	sender := &fakeDirectTextSender{}
	return NewInboxNotifier(store, fakeCredentials{secret: "bot-secret"}, sender, "http://localhost:3000", nil), store, sender
}

func TestInboxNotifier_DeliversToSoleBotBoundMember(t *testing.T) {
	notifier, _, sender := notifierFixture()
	delivered, err := notifier.Notify(context.Background(), notifierEvent("issue_assigned"))
	if err != nil || !delivered {
		t.Fatalf("Notify = (%v, %v), want (true, nil)", delivered, err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("sent %d messages, want 1", len(sender.sent))
	}
	got := sender.sent[0]
	if got.OpenID != "ou_member_1" || got.InstallationID.AppID != "cli_notify" || got.InstallationID.AppSecret != "bot-secret" {
		t.Errorf("wrong destination or credentials: %+v", got)
	}
	for _, want := range []string{"修复登录", "请今天处理", "http://localhost:3000/demo-team/inbox?issue=" + notifyIssueID} {
		if !strings.Contains(got.Text, want) {
			t.Errorf("notification text %q is missing %q", got.Text, want)
		}
	}
}

func TestInboxNotifier_SkipsIneligibleRecipients(t *testing.T) {
	tests := []struct {
		name   string
		change func(*fakeInboxNotifierStore, *events.Event)
	}{
		{"unsupported type", func(_ *fakeInboxNotifierStore, e *events.Event) {
			e.Payload.(map[string]any)["item"].(map[string]any)["type"] = "new_comment"
		}},
		{"wrong recipient type", func(_ *fakeInboxNotifierStore, e *events.Event) {
			e.Payload.(map[string]any)["item"].(map[string]any)["recipient_type"] = "agent"
		}},
		{"bad recipient id", func(_ *fakeInboxNotifierStore, e *events.Event) {
			e.Payload.(map[string]any)["item"].(map[string]any)["recipient_id"] = "bad"
		}},
		{"no bot", func(s *fakeInboxNotifierStore, _ *events.Event) { s.installations = nil }},
		{"multiple bots", func(s *fakeInboxNotifierStore, _ *events.Event) {
			s.installations = append(s.installations, Installation{Status: "active"})
		}},
		{"binding belongs to another bot", func(s *fakeInboxNotifierStore, _ *events.Event) {
			s.binding.InstallationID = util.MustParseUUID(notifyIssueID)
		}},
		{"unbound", func(s *fakeInboxNotifierStore, _ *events.Event) { s.bindErr = pgx.ErrNoRows }},
		{"no longer a member", func(s *fakeInboxNotifierStore, _ *events.Event) { s.member = false }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			notifier, store, sender := notifierFixture()
			e := notifierEvent("issue_assigned")
			tc.change(store, &e)
			delivered, err := notifier.Notify(context.Background(), e)
			if err != nil {
				t.Fatalf("Notify: %v", err)
			}
			if delivered || len(sender.sent) != 0 {
				t.Fatalf("delivered = %v, sends = %d; want no send", delivered, len(sender.sent))
			}
		})
	}
}

type blockingDirectTextSender struct {
	started chan struct{}
	release chan struct{}
}

func (s *blockingDirectTextSender) SendDirectTextMessage(context.Context, SendDirectTextParams) (string, error) {
	close(s.started)
	<-s.release
	return "om_notification", nil
}

func TestInboxNotifier_SendFailureDoesNotPanic(t *testing.T) {
	notifier, _, sender := notifierFixture()
	sender.err = errors.New("feishu unavailable")
	delivered, err := notifier.Notify(context.Background(), notifierEvent("task_failed"))
	if delivered || err == nil {
		t.Fatalf("Notify = (%v, %v), want failed delivery error", delivered, err)
	}
}

func TestInboxNotifier_LongBodyKeepsDetailLink(t *testing.T) {
	notifier, _, sender := notifierFixture()
	e := notifierEvent("status_changed")
	body := strings.Repeat("进", 5000)
	e.Payload.(map[string]any)["item"].(map[string]any)["body"] = &body
	if delivered, err := notifier.Notify(context.Background(), e); err != nil || !delivered {
		t.Fatalf("Notify = (%v, %v)", delivered, err)
	}
	got := sender.sent[0].Text
	if utf8.RuneCountInString(got) > 1000 {
		t.Errorf("message is too long: %d runes", utf8.RuneCountInString(got))
	}
	if !strings.HasSuffix(got, "/inbox?issue="+notifyIssueID) {
		t.Errorf("detail link was lost: %q", got)
	}
}

func TestInboxNotifier_RegisterDoesNotBlockPublisher(t *testing.T) {
	notifier, _, _ := notifierFixture()
	blocking := &blockingDirectTextSender{started: make(chan struct{}), release: make(chan struct{})}
	notifier.sender = blocking
	bus := events.New()
	notifier.Register(bus)
	done := make(chan struct{})
	go func() {
		bus.Publish(notifierEvent("mentioned"))
		close(done)
	}()
	select {
	case <-blocking.started:
	case <-time.After(time.Second):
		t.Fatal("Feishu send did not start")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("inbox event publisher blocked by Feishu notification")
	}
	close(blocking.release)
}
