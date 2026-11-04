CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_invitation_unique_pending ON workspace_invitation(workspace_id, invitee_email) WHERE status = 'pending';
