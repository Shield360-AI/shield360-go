package shield360

import "github.com/Shield360-AI/shield360-go/flags"

// Flags is the SDK's feature-flags client. It fetches the environment's flags
// from Config.Shield360URL with Config.Shield360APIKey (or SHIELD360_URL and
// SHIELD360_API_KEY) and evaluates them locally; flags scoped to an app are
// served only when their app is Config.ApplicationName. Polling starts on
// first use. It never panics: until rules arrive, or on any error, callers
// get their default.
//
//	if shield360.Flags().IsEnabled(ctx, "new-checkout", map[string]any{"key": userID}) { ... }
func Flags() *flags.Client { return flags.Default() }
