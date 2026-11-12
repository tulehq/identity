package sqlimpl

// Settings configures where the store keeps its data: Path is the SQLite
// database file, created with its directory when it does not exist.
type Settings struct {
	Path string `validate:"required"`
}

// RootSettings describes the management account's root user, whose access
// key is configured rather than stored: it signs in AccountID, and every key
// the store issues is checked against it so none can take its ID.
type RootSettings struct {
	AccessKeyID     string
	SecretAccessKey string
	AccountID       string
}
