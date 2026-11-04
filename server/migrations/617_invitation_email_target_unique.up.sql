CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_invitation_email_target_pending ON workspace_invitation(workspace_id, invitee_email) WHERE status = 'pending' AND invitee_user_id IS NULL;
