package sqlimpl

import "github.com/gasmod/gas"

// migrations is the store's schema, applied by gas/migrate in version order.
//
// Times are Unix seconds, the precision the wire carries. Secrets are kept
// as they are, since a signing key is derived from the secret itself; a
// session token is kept as its SHA-256, since it is only ever compared.
// User, role and managed policy names are unique per account, and tag keys
// per resource, without regard to case, enforced by the schema, so concurrent requests cannot both create
// one. store_info has one row, the store's creation time, which the root
// user and its key report as their CreateDate.
var migrations = []gas.Migration{
	{
		Version:     "0001",
		Description: "create the identity schema",
		Up: `
CREATE TABLE users (
	id         TEXT PRIMARY KEY,
	account_id TEXT NOT NULL,
	name       TEXT NOT NULL,
	path       TEXT NOT NULL,
	created_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX users_account_name ON users (account_id, name COLLATE NOCASE);

CREATE TABLE user_tags (
	user_id TEXT NOT NULL,
	key     TEXT NOT NULL COLLATE NOCASE,
	value   TEXT NOT NULL,
	PRIMARY KEY (user_id, key)
);

CREATE TABLE access_keys (
	id         TEXT PRIMARY KEY,
	user_id    TEXT NOT NULL,
	secret     TEXT NOT NULL,
	status     TEXT NOT NULL,
	created_at INTEGER NOT NULL
);
CREATE INDEX access_keys_user ON access_keys (user_id);

CREATE TABLE role_sessions (
	access_key_id TEXT PRIMARY KEY,
	account_id    TEXT NOT NULL,
	session_name  TEXT NOT NULL,
	secret        TEXT NOT NULL,
	token_sha256  TEXT NOT NULL,
	expires_at    INTEGER NOT NULL,
	created_at    INTEGER NOT NULL
);

CREATE TABLE key_last_used (
	access_key_id TEXT PRIMARY KEY,
	service       TEXT NOT NULL,
	region        TEXT NOT NULL,
	used_at       INTEGER NOT NULL
);

CREATE TABLE store_info (
	created_at INTEGER NOT NULL
);
INSERT INTO store_info (created_at) VALUES (CAST(strftime('%s', 'now') AS INTEGER));
`,
		Down: `
DROP TABLE store_info;
DROP TABLE key_last_used;
DROP TABLE role_sessions;
DROP TABLE access_keys;
DROP TABLE user_tags;
DROP TABLE users;
`,
	},
	{
		Version:     "0002",
		Description: "add managed and inline policies and roles",
		// Role sessions name the role they are of from here on. A session
		// created before has no role to take its policies from, so the
		// sessions are dropped: they last an hour at most, and AssumeRole
		// issues new ones.
		//
		// AWS managed policies live in the table under the account "aws".
		// AdministratorAccess has the description, dates, version and
		// document the AWS Managed Policy Reference gives it, which gives
		// the times to the minute. Its ID is not in the reference; it is the
		// PolicyId AWS's GetPolicy is known to answer with.
		Up: `
DELETE FROM role_sessions;
ALTER TABLE role_sessions ADD COLUMN role_id TEXT NOT NULL DEFAULT '';
ALTER TABLE role_sessions ADD COLUMN role_name TEXT NOT NULL DEFAULT '';

CREATE TABLE roles (
	id                   TEXT PRIMARY KEY,
	account_id           TEXT NOT NULL,
	name                 TEXT NOT NULL,
	path                 TEXT NOT NULL,
	trust_policy         TEXT NOT NULL,
	description          TEXT NOT NULL,
	max_session_duration INTEGER NOT NULL,
	created_at           INTEGER NOT NULL
);
CREATE UNIQUE INDEX roles_account_name ON roles (account_id, name COLLATE NOCASE);

CREATE TABLE role_tags (
	role_id TEXT NOT NULL,
	key     TEXT NOT NULL COLLATE NOCASE,
	value   TEXT NOT NULL,
	PRIMARY KEY (role_id, key)
);

CREATE TABLE policies (
	id              TEXT PRIMARY KEY,
	account_id      TEXT NOT NULL,
	name            TEXT NOT NULL,
	path            TEXT NOT NULL,
	description     TEXT NOT NULL,
	default_version INTEGER NOT NULL,
	next_version    INTEGER NOT NULL,
	created_at      INTEGER NOT NULL
);
CREATE UNIQUE INDEX policies_account_name ON policies (account_id, name COLLATE NOCASE);

CREATE TABLE policy_versions (
	policy_id  TEXT NOT NULL,
	version    INTEGER NOT NULL,
	document   TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	PRIMARY KEY (policy_id, version)
);

CREATE TABLE policy_tags (
	policy_id TEXT NOT NULL,
	key       TEXT NOT NULL COLLATE NOCASE,
	value     TEXT NOT NULL,
	PRIMARY KEY (policy_id, key)
);

CREATE TABLE attached_policies (
	entity_kind TEXT NOT NULL,
	entity_id   TEXT NOT NULL,
	account_id  TEXT NOT NULL,
	policy_id   TEXT NOT NULL,
	PRIMARY KEY (entity_kind, entity_id, policy_id)
);
CREATE INDEX attached_policies_policy ON attached_policies (policy_id, account_id);

CREATE TABLE inline_policies (
	entity_kind TEXT NOT NULL,
	entity_id   TEXT NOT NULL,
	name        TEXT NOT NULL,
	document    TEXT NOT NULL,
	PRIMARY KEY (entity_kind, entity_id, name)
);

INSERT INTO policies (id, account_id, name, path, description, default_version,
                      next_version, created_at)
VALUES ('ANPAIWMBCKSKIEE64ZLYK', 'aws', 'AdministratorAccess', '/',
        'Provides full access to AWS services and resources.', 1, 2, 1423247940);
INSERT INTO policy_versions (policy_id, version, document, created_at)
VALUES ('ANPAIWMBCKSKIEE64ZLYK', 1, '{
  "Version" : "2012-10-17",
  "Statement" : [
    {
      "Effect" : "Allow",
      "Action" : "*",
      "Resource" : "*"
    }
  ]
}', 1423247940);
`,
		Down: `
DROP TABLE inline_policies;
DROP TABLE attached_policies;
DROP TABLE policy_tags;
DROP TABLE policy_versions;
DROP TABLE policies;
DROP TABLE role_tags;
DROP TABLE roles;
DELETE FROM role_sessions;
ALTER TABLE role_sessions DROP COLUMN role_name;
ALTER TABLE role_sessions DROP COLUMN role_id;
`,
	},
	{
		Version:     "0003",
		Description: "bind the principals of trust policies to unique IDs",
		// Each user and role ARN a role's trust policy names is bound to the
		// unique ID of the user or role it named when the policy was saved.
		// A role saved before has none, so its user and role principals
		// match nobody until its trust policy is saved again.
		Up: `
CREATE TABLE trust_principals (
	role_id      TEXT NOT NULL,
	arn          TEXT NOT NULL,
	principal_id TEXT NOT NULL,
	PRIMARY KEY (role_id, arn)
);
`,
		Down: `
DROP TABLE trust_principals;
`,
	},
	{
		Version:     "0004",
		Description: "record the accounts OrganizationAccountAccessRole was created in",
		// OrganizationAccountAccessRole is created once per member account,
		// as Organizations creates it with the account; a role the account
		// deletes is never created again. A role of that name already in an
		// account counts as created.
		Up: `
CREATE TABLE organization_roles (
	account_id TEXT PRIMARY KEY,
	created_at INTEGER NOT NULL
);
INSERT INTO organization_roles (account_id, created_at)
SELECT account_id, created_at FROM roles WHERE name = 'OrganizationAccountAccessRole';
`,
		Down: `
DROP TABLE organization_roles;
`,
	},
}
