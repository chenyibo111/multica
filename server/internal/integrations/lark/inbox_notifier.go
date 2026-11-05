package lark

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/multica-ai/multica/server/internal/events"
	"github.com/multica-ai/multica/server/internal/util"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
	"github.com/multica-ai/multica/server/pkg/protocol"
)

// InboxNotifierStore contains the existing installation, binding, and member
// lookups needed to turn a persisted inbox item into one private Feishu push.
type InboxNotifierStore interface {
	ListLarkInstallationsByWorkspace(context.Context, pgtype.UUID) ([]Installation, error)
	FindChannelBindingForMember(context.Context, db.FindChannelBindingForMemberParams) (db.ChannelUserBinding, error)
	IsWorkspaceMember(context.Context, pgtype.UUID, pgtype.UUID) (bool, error)
	GetWorkspace(context.Context, pgtype.UUID) (db.Workspace, error)
}

type DirectTextSender interface {
	SendDirectTextMessage(context.Context, SendDirectTextParams) (string, error)
}

type InboxNotifier struct {
	store       InboxNotifierStore
	credentials CredentialsResolver
	sender      DirectTextSender
	appURL      string
	logger      *slog.Logger
}

func NewInboxNotifier(store InboxNotifierStore, credentials CredentialsResolver, sender DirectTextSender, appURL string, logger *slog.Logger) *InboxNotifier {
	if logger == nil {
		logger = slog.Default()
	}
	return &InboxNotifier{store: store, credentials: credentials, sender: sender, appURL: appURL, logger: logger}
}

// Register keeps Feishu HTTP I/O off the synchronous event publisher. A failed
// push leaves the already-persisted inbox notification available in Multica.
func (n *InboxNotifier) Register(bus *events.Bus) {
	bus.Subscribe(protocol.EventInboxNew, func(e events.Event) {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := n.Notify(ctx, e); err != nil {
				n.logger.Warn("feishu inbox notification failed", "workspace_id", e.WorkspaceID, "error", err)
			}
		}()
	})
}

var inboxNotificationLabels = map[string]string{
	"issue_assigned": "任务分配",
	"mentioned":      "提及你",
	"status_changed": "任务状态更新",
	"task_failed":    "智能体执行失败",
}

// Notify sends one eligible inbox item through the workspace's sole active
// Feishu Bot. It is also the synchronous seam used by focused routing tests.
func (n *InboxNotifier) Notify(ctx context.Context, e events.Event) (bool, error) {
	if e.Type != protocol.EventInboxNew {
		return false, nil
	}
	payload, ok := e.Payload.(map[string]any)
	if !ok {
		return false, nil
	}
	item, ok := payload["item"].(map[string]any)
	if !ok || itemString(item, "recipient_type") != "member" {
		return false, nil
	}
	label, ok := inboxNotificationLabels[itemString(item, "type")]
	if !ok {
		return false, nil
	}
	workspaceIDStr := itemString(item, "workspace_id")
	recipientIDStr := itemString(item, "recipient_id")
	if workspaceIDStr == "" || recipientIDStr == "" || (e.WorkspaceID != "" && e.WorkspaceID != workspaceIDStr) {
		return false, nil
	}
	workspaceID, err := util.ParseUUID(workspaceIDStr)
	if err != nil {
		return false, nil
	}
	recipientID, err := util.ParseUUID(recipientIDStr)
	if err != nil {
		return false, nil
	}
	member, err := n.store.IsWorkspaceMember(ctx, workspaceID, recipientID)
	if err != nil {
		return false, fmt.Errorf("check workspace membership: %w", err)
	}
	if !member {
		return false, nil
	}
	installations, err := n.store.ListLarkInstallationsByWorkspace(ctx, workspaceID)
	if err != nil {
		return false, fmt.Errorf("list workspace bots: %w", err)
	}
	var selected Installation
	active := 0
	for _, inst := range installations {
		if inst.Status == "active" {
			selected = inst
			active++
		}
	}
	if active != 1 {
		if active > 1 {
			n.logger.Info("feishu inbox notification skipped: multiple active bots", "workspace_id", workspaceIDStr)
		} else {
			n.logger.Debug("feishu inbox notification skipped: no active bot", "workspace_id", workspaceIDStr)
		}
		return false, nil
	}
	binding, err := n.store.FindChannelBindingForMember(ctx, db.FindChannelBindingForMemberParams{
		WorkspaceID: workspaceID, MulticaUserID: recipientID, ChannelType: channelTypeFeishu,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("find member bot binding: %w", err)
	}
	if binding.InstallationID != selected.ID || binding.ChannelUserID == "" {
		return false, nil
	}
	secret, err := n.credentials.DecryptAppSecret(selected)
	if err != nil {
		return false, fmt.Errorf("decrypt bot credentials: %w", err)
	}
	creds := InstallationCredentials{AppID: selected.AppID, AppSecret: secret, Region: RegionOrDefault(selected.Region)}
	if selected.TenantKey.Valid {
		creds.TenantKey = selected.TenantKey.String
	}
	workspace, err := n.store.GetWorkspace(ctx, workspaceID)
	if err != nil {
		n.logger.Warn("feishu inbox notification link unavailable", "workspace_id", workspaceIDStr, "error", err)
	}
	message := n.message(item, label, workspace.Slug)
	if message == "" {
		return false, nil
	}
	if _, err := n.sender.SendDirectTextMessage(ctx, SendDirectTextParams{
		InstallationID: creds, OpenID: OpenID(binding.ChannelUserID), Text: message,
	}); err != nil {
		return false, fmt.Errorf("send private notification: %w", err)
	}
	return true, nil
}

func itemString(item map[string]any, field string) string {
	value, _ := item[field].(string)
	return value
}

func (n *InboxNotifier) message(item map[string]any, label, workspaceSlug string) string {
	title := shortenNotificationField(strings.TrimSpace(itemString(item, "title")), 200)
	if title == "" {
		return ""
	}
	var lines []string
	lines = append(lines, "【Multica · "+label+"】"+title)
	if body, ok := item["body"].(*string); ok && body != nil && strings.TrimSpace(*body) != "" {
		lines = append(lines, shortenNotificationField(strings.TrimSpace(*body), 500))
	} else if body, ok := item["body"].(string); ok && strings.TrimSpace(body) != "" {
		lines = append(lines, shortenNotificationField(strings.TrimSpace(body), 500))
	}
	if link := n.issueLink(workspaceSlug, item); link != "" {
		lines = append(lines, link)
	}
	return strings.Join(lines, "\n")
}

func shortenNotificationField(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit]) + "…"
}

func (n *InboxNotifier) issueLink(workspaceSlug string, item map[string]any) string {
	if workspaceSlug == "" {
		return ""
	}
	base, err := url.Parse(strings.TrimSpace(n.appURL))
	if err != nil || base.Host == "" || (base.Scheme != "http" && base.Scheme != "https") {
		return ""
	}
	issueID := itemString(item, "issue_id")
	if ptr, ok := item["issue_id"].(*string); ok && ptr != nil {
		issueID = *ptr
	}
	if _, err := util.ParseUUID(issueID); err != nil {
		return ""
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/" + url.PathEscape(workspaceSlug) + "/inbox"
	query := base.Query()
	query.Set("issue", issueID)
	base.RawQuery = query.Encode()
	return base.String()
}
