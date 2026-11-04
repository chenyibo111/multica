ALTER TABLE "user"
    ADD COLUMN auth_source TEXT NOT NULL DEFAULT 'local',
    ADD COLUMN oidc_issuer TEXT,
    ADD COLUMN oidc_subject TEXT,
    ADD CONSTRAINT user_auth_source_check CHECK (auth_source IN ('local', 'feishu')),
    ADD CONSTRAINT user_feishu_identity_check CHECK (
        (auth_source = 'local' AND oidc_issuer IS NULL AND oidc_subject IS NULL)
        OR (auth_source = 'feishu' AND NULLIF(oidc_issuer, '') IS NOT NULL AND NULLIF(oidc_subject, '') IS NOT NULL)
    );
