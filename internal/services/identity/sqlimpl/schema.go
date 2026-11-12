package sqlimpl

import "github.com/gasmod/gas"

// migrations is the store's schema, applied by gas/migrate in version order.
//
// Times are Unix seconds, the precision the wire carries. Secrets are kept
// as they are, since a signing key is derived from the secret itself; a
// session token is kept as its SHA-256, since it is only ever compared.
// User names are unique per account, and tag keys per user, without regard
// to case, enforced by the schema, so concurrent requests cannot both create
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
}
