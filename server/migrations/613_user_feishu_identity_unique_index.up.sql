CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS user_feishu_identity_unique_idx ON "user" (oidc_issuer, oidc_subject) WHERE auth_source = 'feishu';
