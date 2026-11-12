package app

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"time"

	"github.com/gasmod/gas"
	"github.com/gasmod/gas/config"

	"tule.dev/identity/internal/services/identity/sqlimpl"
)

// hstsSettings configures the Strict-Transport-Security header. It is only
// sent when MaxAge is set, so plain-HTTP deployments can leave it out.
type hstsSettings struct {
	MaxAge time.Duration
}

// authSettings holds the root user's access key: the management account's,
// which every Tule service is configured with. Every request identity takes
// is signed with it or with a key identity issued, so both fields are
// required.
type authSettings struct {
	AccessKeyID     string
	SecretAccessKey string
}

// identitySettings configures the accounts identity serves. AccountID is
// the management account, the root user's; AccountsEndpoint is the accounts
// service AssumeRole asks about member accounts, or empty for none.
type identitySettings struct {
	AccountID        string `validate:"required"`
	AccountsEndpoint string
}

// errNoCredentials is returned when the access key is not configured.
var errNoCredentials = errors.New("config: TULE_Auth_AccessKeyID and " +
	"TULE_Auth_SecretAccessKey must be set; they are the root user's key")

// Config is the bound application configuration. It keeps the store it was
// bound from, which the app registers as the gas.ConfigProvider so services
// can read settings Config itself does not model.
type Config struct {
	HSTS     *hstsSettings
	Auth     *authSettings
	Store    *sqlimpl.Settings `validate:"required"`
	Identity *identitySettings `validate:"required"`

	store gas.ConfigProvider
	Env   config.Environment
}

const (
	envVarSeparator = "_"
	envVarPrefix    = "TULE_"
)

// LoadConfig loads configuration from a .env file and then the process
// environment, the later source winning.
func LoadConfig() (*Config, error) {
	return LoadConfigFrom(
		config.NewDotEnvProvider(
			config.WithDotEnvSeparator(envVarSeparator),
			config.WithDotEnvFileNotFoundPanic(false),
		),
		config.NewEnvProvider(
			config.WithEnvSeparator(envVarSeparator),
			config.WithEnvPrefix(envVarPrefix),
		),
	)
}

// LoadConfigFrom loads configuration from the given providers in order, then
// applies the same defaults and binding as LoadConfig. Tests use it to inject
// a provider of their own.
func LoadConfigFrom(provs ...config.Provider) (*Config, error) {
	env := config.NewEnvExtension()

	opts := make([]config.Option, 0, len(provs)+1)
	opts = append(opts, config.WithExtension(env))

	for _, p := range provs {
		opts = append(opts, config.WithProvider(p))
	}

	store := config.New(opts...)

	if err := store.Load(); err != nil {
		return nil, fmt.Errorf("config: load: %w", err)
	}

	return bindConfig(store, env.Current())
}

func bindConfig(store gas.ConfigProvider, env config.Environment) (*Config, error) {
	if err := applyDefaults(store); err != nil {
		return nil, err
	}

	cfg := Config{Env: env, store: store}
	if err := store.Bind(&cfg); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if cfg.Auth == nil || cfg.Auth.AccessKeyID == "" || cfg.Auth.SecretAccessKey == "" {
		return nil, errNoCredentials
	}
	if err := checkIdentity(cfg.Identity); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// accountIDPattern is an AWS account ID: 12 digits.
var accountIDPattern = regexp.MustCompile(`^\d{12}$`)

// checkIdentity holds the management account's ID to AWS's format, so every
// ARN the service reports is one AWS could, and the accounts endpoint, when
// set, to an absolute http or https URL.
func checkIdentity(s *identitySettings) error {
	if !accountIDPattern.MatchString(s.AccountID) {
		return fmt.Errorf("config: Identity.AccountID %q is not 12 digits", s.AccountID)
	}
	if s.AccountsEndpoint == "" {
		return nil
	}
	u, err := url.Parse(s.AccountsEndpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("config: Identity.AccountsEndpoint %q is not an http or https URL",
			s.AccountsEndpoint)
	}
	return nil
}

func applyDefaults(store gas.ConfigProvider) error {
	var errs []error
	setDefault := func(key string, value any) {
		if err := store.SetDefault(key, value); err != nil {
			errs = append(errs, fmt.Errorf("config: default %s: %w", key, err))
		}
	}

	// 9030, after object-store's 9000, secret-store's 9010 and accounts'
	// 9020, so all four can run at once.
	setDefault("Server.Port", 9030)

	// The server timeouts are set here rather than left to the gas defaults
	// (5s read, 10s write), which are too short for a signed request: the
	// signature covers the whole body, so a read cut short mid-body surfaces
	// to the client as a signature failure or a broken connection rather than
	// as a timeout. A request body may be up to sigv4.DefaultMaxBodySize,
	// 1 MiB, and 30s covers that at well under dial-up speed. Responses are a
	// page of at most 1000 small items, so writes get the same budget.
	// IdleTimeout keeps the SDKs' connection reuse working between calls, and
	// matches the gas default; it is set explicitly so it is visible here
	// rather than inherited.
	setDefault("Server.ReadTimeout", "30s")
	setDefault("Server.WriteTimeout", "30s")
	setDefault("Server.IdleTimeout", "120s")

	// The headers get the same 30s as the whole request. gas requires
	// ReadHeaderTimeout to be positive, so it cannot be unlimited even when
	// ReadTimeout is 0, and its gas default of 5s would cut a slow client's
	// headers short of the budget above.
	setDefault("Server.ReadHeaderTimeout", "30s")

	// ShutdownTimeout is shorter than the gas default of 30s, which is a
	// promise a container runtime does not keep: `docker stop` sends SIGTERM
	// and kills the process 10s later. Every request here is one small SQLite
	// transaction, or one call to the accounts service, so in-flight work
	// needs far less.
	//
	// It is not shorter than 7s because of a connection that was opened but
	// never sent a request, as an SDK client's spare one is. net/http closes
	// such a connection only once its whole-second timestamp is 6 seconds
	// old, 5s to 6s after it opened, and checks at most every 500ms, so the
	// shutdown can wait up to about 6.5s for it. With a shorter timeout gas
	// reports the deadline as an error and the process exits 1. Gas's
	// App.Stop returns within the timeout plus up to three 1s grace periods,
	// which only run while requests are still in flight: 10s at the very
	// worst, the edge of what docker gives.
	setDefault("Server.ShutdownTimeout", "7s")

	setDefault("Store.Path", "./data/identity.db")

	// The management account, accounts' default management account, so the
	// two agree out of the box. No accounts endpoint is the default: without
	// one, AssumeRole finds no role to assume.
	setDefault("Identity.AccountID", "000000000000")
	setDefault("Identity.AccountsEndpoint", "")

	return errors.Join(errs...)
}
