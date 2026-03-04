package cmd

import (
	"context"
	"fmt"
	"strings"

	"adreaper/internal/output"
	"adreaper/internal/recon"

	"github.com/spf13/cobra"
)

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Display the current user's AD context, group memberships, and privilege level",
	Long: `Queries Active Directory for the authenticated user's object and enumerates:
  - Distinguished Name (DN) in the directory tree
  - All group memberships (direct and inherited)
  - Privilege classification: High (Domain/Enterprise Admin) or Standard User

Useful immediately after authentication to understand what you can enumerate
and whether privilege escalation is needed before proceeding to attack modules.

Required: valid credentials (-u and -p, or --hash for Pass-the-Hash)

Example:
  adreaper whoami -d corp.local --dc-ip 10.10.10.1 -u user -p pass`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}

		ctx := context.Background()
		output.Section("USER CONTEXT: WHOAMI")

		ldapCl, err := recon.NewLDAPClient(opts)
		if err != nil {
			return fmt.Errorf("LDAP connect failed: %w", err)
		}
		defer ldapCl.Close()

		// Search for the current user
		filter := fmt.Sprintf("(sAMAccountName=%s)", opts.Username)
		attrs := []string{"distinguishedName", "objectSid", "memberOf", "userAccountControl", "description"}
		entries, err := ldapCl.Search(ctx, filter, attrs)
		if err != nil || len(entries) == 0 {
			output.Warn("Could not find user object for: %s", opts.Username)
			return nil
		}

		user := entries[0]
		dn := user.DN

		output.Info("Username:    %s", output.SuccessStr(opts.Username))
		output.Info("Domain:      %s", output.InfoStr(opts.Domain))
		output.Info("DN:          %s", dn)

		groups := user.GetAttributeValues("memberOf")
		output.Info("Groups (%d):", len(groups))
		for _, g := range groups {
			// Clean up DN for display
			parts := strings.Split(g, ",")
			if len(parts) > 0 {
				groupName := strings.TrimPrefix(parts[0], "CN=")
				output.Info("  → %s", groupName)
			}
		}

		// Check for high-privilege groups
		isAdmin := false
		for _, g := range groups {
			gl := strings.ToLower(g)
			if strings.Contains(gl, "domain admins") || strings.Contains(gl, "administrators") || strings.Contains(gl, "enterprise admins") {
				isAdmin = true
				break
			}
		}

		if isAdmin {
			output.Success("Privilege Level: HIGH (Administrator)")
		} else {
			output.Info("Privilege Level: Standard User")
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(whoamiCmd)
}
