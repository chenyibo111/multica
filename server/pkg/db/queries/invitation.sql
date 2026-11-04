-- name: CreateInvitation :one
INSERT INTO workspace_invitation (id, workspace_id, inviter_id, invitee_email, invitee_user_id, role, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetInvitation :one
SELECT * FROM workspace_invitation
WHERE id = $1;

-- name: ListPendingInvitationsByWorkspace :many
SELECT wi.*,
       u.name  AS inviter_name,
       u.email AS inviter_email
FROM workspace_invitation wi
JOIN "user" u ON u.id = wi.inviter_id
WHERE wi.workspace_id = $1 AND wi.status = 'pending' AND wi.expires_at > now()
ORDER BY wi.created_at DESC;

-- name: ListPendingInvitationsForUser :many
SELECT wi.*,
       w.name AS workspace_name,
       u.name AS inviter_name,
       u.email AS inviter_email
FROM workspace_invitation wi
JOIN workspace w ON w.id = wi.workspace_id
JOIN "user" u ON u.id = wi.inviter_id
WHERE wi.status = 'pending'
  AND (wi.invitee_user_id = $1 OR (wi.invitee_user_id IS NULL AND @allow_email_invites::boolean AND wi.invitee_email = $2))
  AND wi.expires_at > now()
ORDER BY wi.created_at DESC;

-- name: AcceptInvitation :one
UPDATE workspace_invitation
SET status = 'accepted', updated_at = now()
WHERE id = $1 AND status = 'pending'
RETURNING *;

-- name: DeclineInvitation :one
UPDATE workspace_invitation
SET status = 'declined', updated_at = now()
WHERE id = $1 AND status = 'pending'
RETURNING *;

-- name: RevokeInvitation :execrows
DELETE FROM workspace_invitation
WHERE id = $1 AND status = 'pending';

-- name: GetPendingInvitationByEmail :one
SELECT * FROM workspace_invitation
WHERE workspace_id = $1 AND invitee_email = $2 AND invitee_user_id IS NULL AND status = 'pending' AND expires_at > now();

-- name: GetPendingInvitationForTarget :one
SELECT * FROM workspace_invitation
WHERE workspace_id = $1 AND status = 'pending' AND expires_at > now()
  AND ((@invitee_user_id::uuid IS NOT NULL AND invitee_user_id = @invitee_user_id::uuid)
       OR (@invitee_user_id::uuid IS NULL AND invitee_user_id IS NULL AND invitee_email = @invitee_email));

-- name: GetPendingInvitationForUser :one
SELECT * FROM workspace_invitation
WHERE workspace_id = $1 AND status = 'pending' AND expires_at > now()
  AND (invitee_user_id = @user_id::uuid
       OR (invitee_user_id IS NULL AND @allow_email_invites::boolean AND invitee_email = @email))
ORDER BY CASE WHEN invitee_user_id = @user_id::uuid THEN 0 ELSE 1 END, created_at DESC
LIMIT 1;

-- name: HasPendingInvitationForEmail :one
SELECT EXISTS (
    SELECT 1
    FROM workspace_invitation
    WHERE invitee_email = $1
      AND invitee_user_id IS NULL
      AND status = 'pending'
      AND expires_at > now()
);

-- name: ExpireStalePendingInvitations :many
-- Mark any past-due pending invitations for (workspace_id, invitee_email) as expired,
-- so the next CreateInvitation does not collide with the partial unique index
-- idx_invitation_unique_pending (which is WHERE status = 'pending' and cannot
-- itself reference now() in its predicate).
UPDATE workspace_invitation
SET status = 'expired', updated_at = now()
WHERE workspace_id = $1
  AND invitee_email = $2
  AND status = 'pending'
  AND expires_at <= now()
RETURNING *;
