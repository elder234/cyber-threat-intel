-- ═════════════════════════════════════════════════════════════════════════════
-- Aegis CTI — Migration 0002: identity, RBAC, audit
-- ═════════════════════════════════════════════════════════════════════════════
SET search_path TO aegis, public;

-- ── Users ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS aegis.users (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email          citext NOT NULL UNIQUE,
  display_name   text NOT NULL,
  password_hash  text NOT NULL,               -- argon2id hash
  is_active      boolean NOT NULL DEFAULT true,
  mfa_secret     text,                         -- TOTP secret (encrypted at app layer)
  mfa_enabled    boolean NOT NULL DEFAULT false,
  last_login_at  timestamptz,
  failed_logins  int NOT NULL DEFAULT 0,
  locked_until   timestamptz,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now()
);

-- ── Roles & permissions (RBAC) ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS aegis.roles (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name         text NOT NULL UNIQUE,          -- 'admin','analyst','viewer', ...
  description  text NOT NULL DEFAULT '',
  is_system    boolean NOT NULL DEFAULT false,-- system roles can't be deleted
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now()
);

-- Permissions expressed as "resource:action" (e.g. 'ioc:write', 'scan:run')
CREATE TABLE IF NOT EXISTS aegis.permissions (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code        text NOT NULL UNIQUE,
  description text NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS aegis.role_permissions (
  role_id       uuid NOT NULL REFERENCES aegis.roles(id) ON DELETE CASCADE,
  permission_id uuid NOT NULL REFERENCES aegis.permissions(id) ON DELETE CASCADE,
  PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS aegis.user_roles (
  user_id    uuid NOT NULL REFERENCES aegis.users(id) ON DELETE CASCADE,
  role_id    uuid NOT NULL REFERENCES aegis.roles(id) ON DELETE CASCADE,
  granted_by uuid REFERENCES aegis.users(id) ON DELETE SET NULL,
  granted_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, role_id)
);

-- ── Refresh-token / session tracking (rotation + revocation) ─────────────────
CREATE TABLE IF NOT EXISTS aegis.refresh_tokens (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid NOT NULL REFERENCES aegis.users(id) ON DELETE CASCADE,
  token_hash  text NOT NULL,                  -- sha256 of the opaque token
  family_id   uuid NOT NULL,                  -- rotation family for reuse detection
  user_agent  text,
  ip          inet,
  expires_at  timestamptz NOT NULL,
  revoked_at  timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user   ON aegis.refresh_tokens(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_refresh_token_hash ON aegis.refresh_tokens(token_hash);

-- ── API keys (for programmatic / service access) ─────────────────────────────
CREATE TABLE IF NOT EXISTS aegis.api_keys (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid NOT NULL REFERENCES aegis.users(id) ON DELETE CASCADE,
  name        text NOT NULL,
  prefix      text NOT NULL,                  -- shown to user, e.g. 'aeg_live_ab12'
  key_hash    text NOT NULL,                  -- sha256 of full key
  scopes      text[] NOT NULL DEFAULT '{}',
  last_used_at timestamptz,
  expires_at  timestamptz,
  revoked_at  timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_api_key_hash ON aegis.api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON aegis.api_keys(user_id);

-- ── Audit log (append-only) ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS aegis.audit_log (
  id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  actor_id    uuid REFERENCES aegis.users(id) ON DELETE SET NULL,
  actor_email citext,                          -- denormalized for retention
  action      text NOT NULL,                   -- 'auth.login','ioc.create', ...
  resource    text,                            -- 'ioc','scan','user'
  resource_id text,
  ip          inet,
  user_agent  text,
  metadata    jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_actor   ON aegis.audit_log(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_action  ON aegis.audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_created ON aegis.audit_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_resource ON aegis.audit_log(resource, resource_id);

-- ── Triggers ─────────────────────────────────────────────────────────────────
SELECT aegis.attach_updated_at('aegis.users');
SELECT aegis.attach_updated_at('aegis.roles');
