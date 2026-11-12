// Command tule-identity serves AWS IAM- and STS-compatible APIs over users,
// access keys and role sessions stored in a local SQLite database.
package main

import (
	"context"
	"fmt"
	"log"

	"tule.dev/identity/internal/app"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() (err error) {
	cfg, cfgErr := app.LoadConfig()
	if cfgErr != nil {
		return fmt.Errorf("failed to load config: %w", cfgErr)
	}

	a, appErr := app.New(cfg)
	if appErr != nil {
		return fmt.Errorf("failed to create application: %w", appErr)
	}

	if runErr := a.Run(context.Background()); runErr != nil {
		return fmt.Errorf("app exited with error: %w", runErr)
	}

	return
}
