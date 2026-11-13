// Package app loads the configuration and wires the services, modules and
// middleware into a gas application.
package app

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gasmod/gas"
	"github.com/gasmod/gas/database"
	"github.com/gasmod/gas/migrate"

	"tule.dev/identity/internal/contracts"
	"tule.dev/identity/internal/httpx"
	"tule.dev/identity/internal/modules/health"
	"tule.dev/identity/internal/modules/principalids"
	"tule.dev/identity/internal/modules/query"
	serviceroles "tule.dev/identity/internal/modules/servicerole"
	"tule.dev/identity/internal/modules/signingkey"
	"tule.dev/identity/internal/services/identity/sqlimpl"
	"tule.dev/identity/internal/services/organization/sdkimpl"
)

// New builds the application from cfg. extra options are applied after the
// app's own.
func New(cfg *Config, extra ...gas.Option) (*gas.App, error) {
	return newApp(cfg, time.Now, extra...)
}

// newApp is New with the clock the store tells the time by, which tests set
// to expire role sessions.
func newApp(cfg *Config, now func() time.Time, extra ...gas.Option) (*gas.App, error) {
	logger, lErr := newLogger(cfg.Env)
	if lErr != nil {
		return nil, lErr
	}

	// SQLite creates the database file but not the directory it sits in.
	if err := os.MkdirAll(filepath.Dir(cfg.Store.Path), 0o700); err != nil {
		return nil, fmt.Errorf("failed to create the store directory: %w", err)
	}

	// Every request is a POST authenticated by its signature, not by a
	// cookie, so the cross-origin protection meant for browser sessions would
	// reject every call an SDK makes.
	opts := append([]gas.Option{gas.WithCSRFInsecureBypassPattern("/")}, extra...)
	app := gas.NewApp(opts...)

	registerInfraServices(app, cfg, logger)
	app.RegisterSingletonService[contracts.IdentityProvider](
		sqlimpl.NewService(sqlimpl.RootSettings{
			AccessKeyID:     cfg.Auth.AccessKeyID,
			SecretAccessKey: cfg.Auth.SecretAccessKey,
			AccountID:       cfg.Identity.AccountID,
		}, now))
	app.RegisterServiceInstance[contracts.AccountDirectory](sdkimpl.New(sdkimpl.Settings{
		Endpoint:        cfg.Identity.AccountsEndpoint,
		AccessKeyID:     cfg.Auth.AccessKeyID,
		SecretAccessKey: cfg.Auth.SecretAccessKey,
	}))
	registerAppModules(app)
	app.ReadyFunc(reportStoredTrust)
	if err := installMiddleware(app.Router(), cfg, logger); err != nil {
		return nil, err
	}

	return app, nil
}

func registerInfraServices(app *gas.App, cfg *Config, logger gas.Logger) {
	app.RegisterServiceInstance[gas.ConfigProvider](cfg.store)
	app.RegisterServiceInstance[gas.Logger](logger)
	app.RegisterScopedService[httpx.RequestLogger](resolveRequestLogger)
	app.RegisterSingletonService[gas.DatabaseProvider](
		database.New(database.WithConfig(databaseConfig(cfg.Store))))
	app.RegisterSingletonService[gas.MigrationManager](migrate.New())
}

// databaseConfig is the gas/database configuration of the store's SQLite
// file.
//
// The pool holds one connection. SQLite lets one writer in at a time, and a
// second connection that starts a transaction as a reader and then writes
// fails with SQLITE_BUSY at once rather than waiting, so every transaction
// goes through the one connection and waits its turn there. Each operation
// is one short transaction, so the queue is short.
func databaseConfig(store *sqlimpl.Settings) *database.Config {
	cfg := database.DefaultConfig()
	cfg.Database.Dialect = database.DialectSQLite
	cfg.Database.DSN = gas.Secret("file:" + store.Path)
	cfg.Database.MaxOpenConns = 1
	cfg.Database.MaxIdleConns = 1
	// The one connection is kept for as long as gas/database allows, rather
	// than reopened every 30 minutes, since nothing is gained by recycling a
	// connection to a local file.
	cfg.Database.ConnMaxLifetime = 2 * time.Hour
	cfg.Database.ConnMaxIdleTime = time.Hour
	return cfg
}

func registerAppModules(app *gas.App) {
	app.RegisterSingletonService[*query.Module](query.NewModule)
	app.RegisterSingletonService[*signingkey.Module](signingkey.NewModule)
	app.RegisterSingletonService[*serviceroles.Module](serviceroles.NewModule)
	app.RegisterSingletonService[*principalids.Module](principalids.NewModule)
	app.RegisterSingletonService[*health.Module](health.NewModule)
}

func installMiddleware(r *gas.Router, cfg *Config, logger gas.Logger) error {
	r.UseMiddlewareFunc(nil, httpx.RequestID(cfg.Env))

	// No X-Forwarded-For handling: nothing is expected in front of this
	// service, and the header is unsigned, so trusting a hop would only let a
	// caller choose the client IP that ends up in the logs.

	r.UseMiddlewareFunc(nil, withRequestLogger(logger))

	r.UseMiddlewareFunc(nil, gas.RequestLogger[httpx.RequestLogger]())

	verify, err := verifySignature(cfg.Auth)
	if err != nil {
		return err
	}
	r.UseMiddlewareFunc(nil, verify)

	var hsts string
	if cfg.HSTS != nil && cfg.HSTS.MaxAge > 0 {
		hsts = fmt.Sprintf("max-age=%0.f", cfg.HSTS.MaxAge.Seconds())
	}
	r.UseMiddlewareFunc(nil, gas.SecurityHeaders(
		gas.WithSecurityHeadersStrictTransportSecurity(hsts),
	))

	installUnrouted(r)
	return nil
}
