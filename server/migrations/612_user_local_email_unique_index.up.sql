CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS user_local_email_unique_idx ON "user" (email) WHERE auth_source = 'local';
