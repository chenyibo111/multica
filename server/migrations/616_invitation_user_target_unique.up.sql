CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_invitation_user_target_pending ON workspace_invitation(workspace_id, invitee_user_id) WHERE status = 'pending' AND invitee_user_id IS NOT NULL;
