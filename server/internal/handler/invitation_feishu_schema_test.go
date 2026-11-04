package handler

import (
	"context"
	"github.com/jackc/pgx/v5/pgtype"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
	"testing"
)

func TestFeishuInvitationsCanTargetSameEmailAccounts(t *testing.T) {
	ctx := context.Background()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	var localID, feishuID string
	email := "invite-targets@example.test"
	if err := tx.QueryRow(ctx, `INSERT INTO "user" (name,email) VALUES ('Local',$1) RETURNING id`, email).Scan(&localID); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, `INSERT INTO "user" (name,email,auth_source,oidc_issuer,oidc_subject) VALUES ('Feishu',$1,'feishu','https://issuer.example/','invite-target') RETURNING id`, email).Scan(&feishuID); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{localID, feishuID} {
		_, err := tx.Exec(ctx, `INSERT INTO workspace_invitation (workspace_id, inviter_id, invitee_email, invitee_user_id, role) VALUES ($1,$2,$3,$4,'member')`, testWorkspaceID, testUserID, email, id)
		if err != nil {
			t.Fatalf("second same-email account invitation rejected: %v", err)
		}
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM workspace_invitation WHERE workspace_id=$1 AND invitee_email=$2 AND status='pending'`, testWorkspaceID, email).Scan(&count); err != nil || count != 2 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	localUUID, feishuUUID := parseUUID(localID), parseUUID(feishuID)
	localInvites, err := db.New(tx).ListPendingInvitationsForUser(ctx, db.ListPendingInvitationsForUserParams{InviteeUserID: localUUID, InviteeEmail: email, AllowEmailInvites: true})
	if err != nil || len(localInvites) != 1 || localInvites[0].InviteeUserID != localUUID {
		t.Fatalf("local invites=%d err=%v", len(localInvites), err)
	}
	feishuInvites, err := db.New(tx).ListPendingInvitationsForUser(ctx, db.ListPendingInvitationsForUserParams{InviteeUserID: feishuUUID, InviteeEmail: email, AllowEmailInvites: false})
	if err != nil || len(feishuInvites) != 1 || feishuInvites[0].InviteeUserID != feishuUUID {
		t.Fatalf("Feishu invites=%d err=%v", len(feishuInvites), err)
	}
}

func TestInvitationBelongsToSelectedAccount(t *testing.T) {
	local := db.User{ID: pgtype.UUID{Bytes: [16]byte{1}, Valid: true}, Email: "same@example.test", AuthSource: "local"}
	feishu := db.User{ID: pgtype.UUID{Bytes: [16]byte{2}, Valid: true}, Email: local.Email, AuthSource: "feishu"}
	bound := db.WorkspaceInvitation{InviteeUserID: feishu.ID, InviteeEmail: local.Email}
	if invitationBelongsToUser(bound, local) || !invitationBelongsToUser(bound, feishu) {
		t.Fatal("bound invitation leaked across same-email accounts")
	}
	legacy := db.WorkspaceInvitation{InviteeEmail: local.Email}
	if !invitationBelongsToUser(legacy, local) || invitationBelongsToUser(legacy, feishu) {
		t.Fatal("legacy email invitation leaked to Feishu")
	}
}
