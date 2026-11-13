package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/gasmod/gas"
	"tule.dev/policy"

	"tule.dev/identity/internal/contracts"
)

// reportStoredTrust is the ready hook, run once the migrations are applied,
// that logs a warning for each stored trust policy that no longer parses.
func reportStoredTrust(c *gas.ServiceContainer) error {
	store, err := c.Resolve[contracts.IdentityProvider]()
	if err != nil {
		return fmt.Errorf("resolve the store: %w", err)
	}
	logger, err := c.Resolve[gas.Logger]()
	if err != nil {
		return fmt.Errorf("resolve the logger: %w", err)
	}
	return checkStoredTrust(context.Background(), store, logger)
}

// checkStoredTrust logs a warning, naming the role and the parse error, for
// each stored trust policy that tule.dev/policy no longer parses: one an
// earlier release stored before the parser was tightened, such as one
// naming a principal ARN with a region. Such a role cannot be assumed until
// its trust policy is rewritten; the policy is left as it is.
func checkStoredTrust(
	ctx context.Context,
	store contracts.IdentityProvider,
	logger gas.Logger,
) error {
	roles, err := store.AllRoles(ctx)
	if err != nil {
		return fmt.Errorf("read the roles: %w", err)
	}
	for _, r := range roles {
		_, pErr := policy.ParseTrust([]byte(r.TrustPolicy))
		var pe *policy.ParseError
		switch {
		case errors.As(pErr, &pe):
			logger.Warn("the stored trust policy of a role no longer parses; "+
				"the role cannot be assumed until it is rewritten").
				Str("role", r.ARN).Err("error", pErr).Send()
		case pErr != nil:
			return fmt.Errorf("parse the trust policy of %s: %w", r.ARN, pErr)
		}
	}
	return nil
}
