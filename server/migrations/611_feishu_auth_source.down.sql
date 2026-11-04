ALTER TABLE "user"
    DROP CONSTRAINT IF EXISTS user_feishu_identity_check,
    DROP CONSTRAINT IF EXISTS user_auth_source_check,
    DROP COLUMN IF EXISTS oidc_subject,
    DROP COLUMN IF EXISTS oidc_issuer,
    DROP COLUMN IF EXISTS auth_source;
