package cmd

import (
	"context"
	"fmt"
	"strings"

	"adreaper/internal/output"
	"adreaper/internal/recon"
	"adreaper/internal/workspace"

	"github.com/spf13/cobra"
)

var enumCmd = &cobra.Command{
	Use:   "enum",
	Short: "Enumerate Active Directory objects and configurations",
	Long: `The 'enum' module provides LDAP-based enumeration of everything in the target domain.
Run 'adreaper enum <subcommand> --help' for detailed usage and attack-relevant context.

Subcommands:
  users        Enumerate all user accounts (SPN, AS-REP, delegation, password policy)
  computers    Enumerate computer accounts (DCs, LAPS, unconstrained delegation)
  groups       Enumerate groups and memberships (AdminSDHolder-protected groups)
  shares       List SMB shares and access level (read/write)
  acls         Detect dangerous ACLs (GenericAll, WriteDACL, DCSync rights)
  trusts       Map domain trust relationships and SID-filtering status
  domain       Domain metadata: functional level, password policy, MAQ
  adcs         ADCS Certificate Authorities + ESC1-ESC4 template detection
  local-admins Identify which domain users have local admin via GPO (no host scan)
  tree         Visual tree of SMB share filesystem
  all          High-level aggregate counts: users / computers / groups / OUs / GPOs
  dump         Full extraction of all users, computers, and groups in separate tables`,
}

func init() {
	enumCmd.AddCommand(enumUsersCmd)
	enumCmd.AddCommand(enumComputersCmd)
	enumCmd.AddCommand(enumGroupsCmd)
	enumCmd.AddCommand(enumSharesCmd)
	enumCmd.AddCommand(enumACLsCmd)
	enumCmd.AddCommand(enumTrustsCmd)
	enumCmd.AddCommand(enumDomainCmd)
	enumCmd.AddCommand(enumADCSCmd)
	enumCmd.AddCommand(enumLocalAdminsCmd)
	enumCmd.AddCommand(enumTreeCmd)
	enumCmd.AddCommand(enumAllCmd)
	enumCmd.AddCommand(enumDumpCmd)
}

// ── enum users ────────────────────────────────────────────────────────────────

var (
	enumUsersSPNOnly   bool
	enumUsersASREPOnly bool
	enumUsersAdminOnly bool
	enumUsersDeleg     bool
)

var enumUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "Enumerate domain user accounts with attack-relevant flags",
	Long: `Queries LDAP for all user objects and annotates attack-relevant attributes.

User Flags in output:
  [DISABLED]         Account is disabled
  [ADMIN]            adminCount=1 (protected by AdminSDHolder)
  [ASREP]            DONT_REQ_PREAUTH — can be AS-REP roasted without credentials
  [SPN]              Has a ServicePrincipalName — Kerberoasting target
  [UNCONSTRAINED-DELEG] Dangerous: can impersonate ANY user to ANY service
  [CONSTRAINED-DELEG]   Delegated to specific SPNs only
  [NO-PWD-EXP]       PasswordNeverExpires — stale credentials risk

Filter Flags:
  --spn-only         Pull only Kerberoastable accounts → feed to 'attack kerberoast'
  --asrep-only       Pull AS-REP roastable targets   → feed to 'attack asreproast'
  --deleg            Show only accounts with delegation configured
  --admin-only       Show only AdminCount=1 accounts

Examples:
  adreaper enum users -d corp.local --dc-ip 10.10.10.1 -u user -p pass
  adreaper enum users --spn-only -d corp.local --dc-ip 10.10.10.1 -u user -p pass
  adreaper enum users --asrep-only -d corp.local --dc-ip 10.10.10.1 -u user -p pass
  adreaper enum users --deleg -d corp.local --dc-ip 10.10.10.1 -u user -p pass`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		ws, _ := workspace.New(opts.WorkspaceDir, opts.Domain)
		ctx := context.Background()

		output.Section("User Enumeration")
		output.Info("Connecting to LDAP: %s", opts.LDAPAddr())

		ldapCl, err := recon.NewLDAPClient(opts)
		if err != nil {
			return fmt.Errorf("LDAP connect: %w", err)
		}
		defer ldapCl.Close()

		var users []recon.User

		switch {
		case enumUsersSPNOnly:
			output.Info("Querying Kerberoastable users (SPN set, not disabled)...")
			users, err = ldapCl.QuerySPNUsers(ctx)
		case enumUsersASREPOnly:
			output.Info("Querying AS-REP roastable users (no Kerberos pre-auth)...")
			users, err = ldapCl.QueryASREPUsers(ctx)
		default:
			output.Info("Querying all user accounts...")
			users, err = ldapCl.QueryUsers(ctx)
		}
		if err != nil {
			return err
		}

		output.Success("Found %d users", len(users))

		var rows [][]string
		for _, u := range users {
			if enumUsersAdminOnly && !u.AdminCount {
				continue
			}
			if enumUsersDeleg && !u.UnconstrainedDelegation && len(u.ConstrainedDelegation) == 0 {
				continue
			}
			flags := buildUserFlags(u)
			rows = append(rows, []string{u.SAMAccountName, u.UPN, flags, u.Description})
		}

		output.PrintTable([]string{"SAMAccountName", "UPN", "Flags", "Description"}, rows)

		if ws != nil {
			_ = ws.SaveJSON("users.json", users)
		}
		return nil
	},
}

func init() {
	enumUsersCmd.Flags().BoolVar(&enumUsersSPNOnly, "spn-only", false, "Only show Kerberoastable users (SPN set)")
	enumUsersCmd.Flags().BoolVar(&enumUsersASREPOnly, "asrep-only", false, "Only show AS-REP roastable users")
	enumUsersCmd.Flags().BoolVar(&enumUsersAdminOnly, "admin-only", false, "Only show adminCount=1 users")
	enumUsersCmd.Flags().BoolVar(&enumUsersDeleg, "deleg", false, "Only show accounts with delegation configured")

	enumGroupsCmd.Flags().StringVar(&enumGroupsName, "name", "", "Filter by specific group name")

	// Assuming infraScanTarget is defined elsewhere or will be defined.
	// If not, this line will cause a compilation error.
	// enumSharesCmd.Flags().StringVarP(&infraScanTarget, "target", "t", "", "Target host (defaults to --dc-ip)")

	// Assuming infraScanCmd and infraScanNoPing are defined elsewhere or will be defined.
	// If not, these lines will cause a compilation error.
	// infraScanCmd.Flags().BoolVar(&infraScanNoPing, "no-ping", false, "Skip host discovery")
}

func buildUserFlags(u recon.User) string {
	var f string
	if !u.Enabled {
		f += "[DISABLED] "
	}
	if u.AdminCount {
		f += "[ADMIN] "
	}
	if u.NoKerbPreauth {
		f += "[ASREP] "
	}
	if len(u.SPNs) > 0 {
		f += "[SPN] "
	}
	if u.UnconstrainedDelegation {
		f += "[UNCONSTRAINED-DELEG] "
	}
	if len(u.ConstrainedDelegation) > 0 {
		f += "[CONSTRAINED-DELEG] "
	}
	if u.PasswordNeverExpires {
		f += "[NO-PWD-EXP] "
	}
	if f == "" {
		f = "-"
	}
	return f
}

// ── enum computers ───────────────────────────────────────────────────────────

var enumComputersCmd = &cobra.Command{
	Use:   "computers",
	Short: "Enumerate computer accounts (DCs, LAPS, delegation)",
	Long: `Queries LDAP for all computer objects and annotates attack-relevant attributes.

Computer Flags in output:
  [DC]                   Domain Controller
  [UNCONSTRAINED-DELEG]  High-risk: machine can impersonate any user to any service
  [LAPS-READABLE]        LAPS local admin password is readable by your current user

Tip: Workstations with unconstrained delegation are prime coercion targets
(PetitPotam, PrinterBug) to capture Domain Controller machine account TGTs.

Example:
  adreaper enum computers -d corp.local --dc-ip 10.10.10.1 -u user -p pass`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		ctx := context.Background()

		ldapCl, err := recon.NewLDAPClient(opts)
		if err != nil {
			return err
		}
		defer ldapCl.Close()

		comps, err := ldapCl.QueryComputers(ctx)
		if err != nil {
			return err
		}
		output.Success("Found %d computers", len(comps))

		var rows [][]string
		for _, c := range comps {
			flags := ""
			if c.IsDC {
				flags += "[DC] "
			}
			if c.UnconstrainedDelegation {
				flags += "[UNCONSTRAINED-DELEG] "
			}
			if c.LAPSEnabled && c.LAPSPassword != "" {
				flags += "[LAPS-READABLE] "
			}
			if flags == "" {
				flags = "-"
			}
			rows = append(rows, []string{c.SAMAccountName, c.DNSHostName, c.OperatingSystem, flags})
		}
		output.PrintTable([]string{"SAMAccountName", "DNS", "OS", "Flags"}, rows)
		return nil
	},
}

// ── enum groups ──────────────────────────────────────────────────────────────

var (
	enumGroupsName string
)

var enumGroupsCmd = &cobra.Command{
	Use:   "groups",
	Short: "Enumerate security groups and memberships",
	Long: `Lists all AD security groups with member counts and AdminSDHolder protection status.

Search is substring-based on both sAMAccountName and DN:
  --name 'Admin'   matches 'Domain Admins', 'Server Admins', etc.

Localization Note:
  If the domain is in a non-English locale (e.g., Spanish), group names will NOT
  match English terms. Use localized keywords:
    English: 'Admins', 'Users', 'Computers'
    Spanish: 'Admins', 'Usuarios', 'Equipos', 'Dominio'

Examples:
  adreaper enum groups -d corp.local --dc-ip 10.10.10.1 -u user -p pass
  adreaper enum groups --name 'Domain Admins' -d corp.local --dc-ip 10.10.10.1 -u user -p pass
  adreaper enum groups --name Admins -d corp.local --dc-ip 10.10.10.1 -u user -p pass`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		ctx := context.Background()
		output.Section("Group Enumeration")

		ldapCl, err := recon.NewLDAPClient(opts)
		if err != nil {
			return err
		}
		defer ldapCl.Close()

		groups, err := ldapCl.QueryGroups(ctx)
		var rows [][]string
		for _, g := range groups {
			// Substring match for name if requested (check both SAM and DN)
			if enumGroupsName != "" {
				matches := strings.Contains(strings.ToLower(g.SAMAccountName), strings.ToLower(enumGroupsName)) ||
					strings.Contains(strings.ToLower(g.DN), strings.ToLower(enumGroupsName))
				if !matches {
					continue
				}
			}

			admin := "-"
			if g.AdminCount {
				admin = "YES"
			}

			desc := g.Description

			rows = append(rows, []string{g.SAMAccountName, fmt.Sprintf("%d", len(g.Members)), admin, desc})
		}

		if len(rows) == 0 && enumGroupsName != "" {
			output.Warn("Search for group '%s' returned 0 matches (Filtered from %d total groups)", enumGroupsName, len(groups))
			output.Info("Tip: If the lab is in Spanish, try localized terms like 'Usuarios', 'Equipos', or 'Admins'.")
		} else {
			output.Success("Found %d groups (Displaying %d after filters)", len(groups), len(rows))
			output.PrintTable([]string{"Name", "Members", "AdminCount", "Description"}, rows)
		}
		return nil
	},
}

// ── enum shares ──────────────────────────────────────────────────────────────

var enumSharesCmd = &cobra.Command{
	Use:   "shares",
	Short: "Enumerate accessible SMB shares on the DC",
	Long: `Lists all SMB shares on the target Domain Controller and tests read/write access.

  SYSVOL — ALWAYS readable. Contains GPO scripts, GPP passwords, logon scripts.
  NETLOGON — Contains logon scripts. Check for writable scripts.
  C$  / ADMIN$ — Administrative shares. Readable = local admin / Domain Admin.
  Custom shares — Check for sensitive data (backup files, configs, .kdbx, etc.)

Next Steps:
  Use 'enum tree --share SYSVOL' to inspect SYSVOL contents.
  Use 'attack gpp' to automatically decrypt GPP passwords found in SYSVOL.

Example:
  adreaper enum shares -d corp.local --dc-ip 10.10.10.1 -u user -p pass`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		output.Section("SMB Share Enumeration")

		smbCl, err := recon.NewSMBClient(opts)
		if err != nil {
			return err
		}
		defer smbCl.Close()

		shares, err := smbCl.ListShares()
		if err != nil {
			return err
		}
		output.Success("Found %d shares", len(shares))
		var rows [][]string
		for _, s := range shares {
			rows = append(rows, []string{s.Name, s.Remark, s.Access})
		}
		output.PrintTable([]string{"Share", "Remark", "Access"}, rows)
		return nil
	},
}

// ── enum acls ────────────────────────────────────────────────────────────────

var enumACLsCmd = &cobra.Command{
	Use:   "acls",
	Short: "Detect dangerous ACEs on high-value AD objects",
	Long: `Audits Access Control Lists on the highest-value AD objects:
  - Domain object root
  - Domain Admins group
  - AdminSDHolder container

Flagged Permissions (exploitation paths):
  GenericAll       Full control over the object → password reset, SPN add, group join
  WriteDACL        Can modify the object's ACL → grant yourself GenericAll
  WriteOwner       Can take ownership → then WriteDACL → GenericAll
  DS-Replication   DCSync rights → extract all NTLM hashes

Next Steps:
  Use 'attack acl-abuse' to exploit ForceChangePassword or GenericWrite findings.
  Feed findings to BloodHound CE for automated attack path visualization.

Example:
  adreaper enum acls -d corp.local --dc-ip 10.10.10.1 -u user -p pass`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		ctx := context.Background()
		output.Section("ACL Analysis — High-Value Targets")

		ldapCl, err := recon.NewLDAPClient(opts)
		if err != nil {
			return err
		}
		defer ldapCl.Close()

		entries, err := ldapCl.QueryDangerousACLs(ctx)
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			output.Success("No dangerous ACLs found on monitored objects")
			return nil
		}

		output.Warn("Found %d DANGEROUS ACL entries!", len(entries))
		var rows [][]string
		for _, a := range entries {
			rows = append(rows, []string{a.Object, a.Principal, a.Right, a.AceType})
		}
		output.PrintTable([]string{"Object", "Principal", "Right", "Type"}, rows)
		return nil
	},
}

func init() {
	enumACLsCmd.Flags().StringVarP(&aclTarget, "target", "t", "", "Target object to audit (DN or SAM)")
}

// ── enum trusts ──────────────────────────────────────────────────────────────

var enumTrustsCmd = &cobra.Command{
	Use:   "trusts",
	Short: "Map cross-domain trust relationships",
	Long: `Enumerates all Active Directory trust relationships for the target domain.

Columns:
  Partner    Partner domain FQDN
  Direction  Inbound / Outbound / Bidirectional
  Type       ParentChild / External / Forest / MIT
  SID-Filtered  YES = SID history cannot be abused across this trust

Forest trusts with SID Filtering disabled (NO) allow SID history injection
for privilege escalation from a child domain to the forest root.

Example:
  adreaper enum trusts -d corp.local --dc-ip 10.10.10.1 -u user -p pass`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		ctx := context.Background()
		output.Section("Domain Trusts")

		ldapCl, err := recon.NewLDAPClient(opts)
		if err != nil {
			return err
		}
		defer ldapCl.Close()

		trusts, err := ldapCl.QueryTrusts(ctx)
		if err != nil {
			return err
		}
		output.Success("Found %d trust relationships", len(trusts))
		var rows [][]string
		for _, t := range trusts {
			sidFilter := "NO"
			if t.IsSIDFiltered {
				sidFilter = "YES"
			}
			rows = append(rows, []string{t.Partner, t.Direction, t.TrustType, sidFilter})
		}
		output.PrintTable([]string{"Partner", "Direction", "Type", "SID-Filtered"}, rows)
		return nil
	},
}

// ── enum domain ──────────────────────────────────────────────────────────────

var enumDomainCmd = &cobra.Command{
	Use:   "domain",
	Short: "Enumerate domain metadata and password policy",
	Long: `Queries the domain root object for key security configuration values.

Reported Attributes:
  Functional Level        : Determines which Kerberos features are available
  Machine Account Quota   : > 0 means any user can add machines (NoPac prerequisite!)
  Min Password Length     : < 8 = likely weak passwords in use
  Lockout Threshold       : 0 = no lockout, safe to spray aggressively
  Password Complexity     : Enabled/Disabled
  Max Password Age        : 0 = passwords never expire domain-wide

Tip: A lockout threshold of 0 combined with a short password means aggressive
spraying via 'attack spray' is safe without risk of account lockout.

Example:
  adreaper enum domain -d corp.local --dc-ip 10.10.10.1 -u user -p pass`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		ctx := context.Background()
		output.Section("Domain Information")

		ldapCl, err := recon.NewLDAPClient(opts)
		if err != nil {
			return err
		}
		defer ldapCl.Close()

		info, err := ldapCl.QueryDomainInfo(ctx)
		if err != nil {
			return err
		}

		output.Info("Domain:                 %s", info.Name)
		output.Info("Base DN:               %s", info.DN)
		output.Info("Domain Functional Level: %d (%s)", info.FunctionalLevel, flToName(info.FunctionalLevel))
		output.Info("Machine Account Quota: %d", info.MachineAccountQuota)
		fmt.Println()
		output.Info("Password Policy:")
		output.Info("  Min Length:          %d", info.MinPasswordLength)
		output.Info("  Complexity:          %v", info.PasswordComplexity)
		output.Info("  Max Age:             %s", info.MaxPasswordAge)
		output.Info("  Lockout Threshold:   %d", info.LockoutThreshold)
		output.Info("  Lockout Duration:    %s", info.LockoutDuration)

		if info.MachineAccountQuota > 0 {
			output.Warn("ms-DS-MachineAccountQuota = %d — non-admin users can add machines (NoPac prerequisite!)", info.MachineAccountQuota)
		}
		return nil
	},
}

func flToName(level int) string {
	m := map[int]string{
		0: "Windows 2000",
		1: "Windows Server 2003 Interim",
		2: "Windows Server 2003",
		3: "Windows Server 2008",
		4: "Windows Server 2008 R2",
		5: "Windows Server 2012",
		6: "Windows Server 2012 R2",
		7: "Windows Server 2016 or higher", // Ver-7 covers 2019/2022 domain levels
	}
	if n, ok := m[level]; ok {
		return n
	}
	return "Unknown"
}

// ── enum adcs ────────────────────────────────────────────────────────────────

var enumADCSCmd = &cobra.Command{
	Use:   "adcs",
	Short: "Enumerate ADCS Certificate Authorities and vulnerable templates",
	Long: `Enumerates Active Directory Certificate Services (ADCS) infrastructure.

Detects:
  ESC1  Enrollee supplies SAN + Client Auth + No manager approval → impersonate any user
  ESC2  AnyPurpose EKU — effectively ESC1 with broader scope
  ESC3  Enrollment Agent template — request certs on behalf of other users
  ESC4  Write permissions on a template — can modify it to enable ESC1

Requires authentication. Run 'enum shares' first to confirm ADCS is present
(look for 'CertEnroll' share on the DC or a dedicated CA server).

Next Steps:
  Use Certipy for full ESC exploitation: certipy req -u user@corp.local -p pass
  Evidence saved to: workspace/<domain>/adcs_templates.json

Example:
  adreaper enum adcs -d corp.local --dc-ip 10.10.10.1 -u user -p pass`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		if !opts.IsAuthenticated() {
			output.Warn("ADCS enumeration requires authentication. Please provide -u and -p.")
			return fmt.Errorf("authentication required")
		}
		ctx := context.Background()
		output.Section("ADCS Enumeration")

		ldapCl, err := recon.NewLDAPClient(opts)
		if err != nil {
			return err
		}
		defer ldapCl.Close()

		cas, templates, err := ldapCl.QueryADCS(ctx)
		if err != nil {
			output.Warn("ADCS not found or not accessible: %v", err)
			return nil
		}

		output.Success("Found %d Certificate Authorities", len(cas))
		for _, ca := range cas {
			output.Info("  CA: %s (%s)", ca.Name, ca.DNSHostName)
		}

		output.Success("Found %d certificate templates", len(templates))
		var rows [][]string
		for _, t := range templates {
			vulns := buildTemplateVulns(t)
			rows = append(rows, []string{t.Name, t.DisplayName, vulns})
		}
		output.PrintTable([]string{"Name", "DisplayName", "Vulnerabilities"}, rows)

		if ws, _ := workspace.New(opts.WorkspaceDir, opts.Domain); ws != nil {
			_ = ws.SaveJSON("adcs_templates.json", templates)
		}
		return nil
	},
}

func buildTemplateVulns(t recon.CertTemplate) string {
	var v string
	if t.EnrolleeSuppliesSAN && t.ClientAuth && !t.RequiresManagerApproval {
		v += "[ESC1] "
	}
	if t.AnyPurpose && !t.RequiresManagerApproval {
		v += "[ESC2] "
	}
	if t.IsEnrollmentAgent {
		v += "[ESC3] "
	}
	if len(t.WritePermissions) > 0 {
		v += "[ESC4] "
	}
	if v == "" {
		v = "-"
	}
	return v
}

// ── enum tree ────────────────────────────────────────────────────────────────

var (
	enumTreeShare string
	enumTreePath  string
	enumTreeDepth int
)

var enumTreeCmd = &cobra.Command{
	Use:   "tree",
	Short: "Visual filesystem tree for SMB shares",
	Long: `Recursively lists files and directories within an SMB share using a tree layout.
Useful for manual filesystem exploration without transferring files.

Share Modes:
  (no --share flag)       Show share names only (quick overview)
  --share SYSVOL          Walk the SYSVOL share (GPO scripts, GPP files)
  --share 'C$'            Walk the C$ administrative share (requires admin)
  --share all             Walk ALL accessible shares (use with caution on large environments)

Depth Control:
  --depth 3 (default)     Recursive depth limit
  --depth 1               List top-level directories only

Examples:
  adreaper enum tree -d corp.local --dc-ip 10.10.10.1 -u user -p pass
  adreaper enum tree --share SYSVOL --depth 5 -d corp.local --dc-ip 10.10.10.1 -u user -p pass
  adreaper enum tree --share all --depth 2 -d corp.local --dc-ip 10.10.10.1 -u user -p pass`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}

		smbCl, err := recon.NewSMBClient(opts)
		if err != nil {
			return err
		}
		defer smbCl.Close()

		if enumTreeShare == "" {
			output.Section("SMB Global Tree View (Auto-Crawl)")
			output.Info("Crawling all accessible shares with depth %d...", enumTreeDepth)
			shares, err := smbCl.ListShares()
			if err != nil {
				return err
			}

			for _, sh := range shares {
				if sh.Access == "DENIED" || sh.Name == "IPC$" {
					continue
				}
				output.Info("Walking share: %s...", sh.Name)
				tree, _ := smbCl.WalkTree(sh.Name, ".", enumTreeDepth)
				if tree != nil {
					count := countTreeItems(tree)
					output.Info("  [+] Discovered %d items in %s", count, sh.Name)
					output.PrintTree(tree)
				}
			}
			fmt.Println()
			output.Info("Use --share <name> to explore specific contents with more depth.")
			return nil
		}

		// Trim quotes if passed by shell
		enumTreeShare = strings.Trim(enumTreeShare, "'\"")

		if strings.ToLower(enumTreeShare) == "all" {
			output.Section("Exhaustive SMB Tree Recon (All Shares)")
			output.Info("Scanning every accessible share with depth %d...", enumTreeDepth)

			shares, err := smbCl.ListShares()
			if err != nil {
				return err
			}

			for _, sh := range shares {
				if sh.Access == "DENIED" || sh.Name == "IPC$" {
					continue
				}
				output.Info("Walking share: %s...", sh.Name)
				tree, _ := smbCl.WalkTree(sh.Name, ".", enumTreeDepth)
				if tree != nil {
					count := countTreeItems(tree)
					output.Info("  [+] Discovered %d items in %s", count, sh.Name)
					output.PrintTree(tree)
				}
			}
			fmt.Println()
			return nil
		}

		output.Section(fmt.Sprintf("SMB Tree: %s", enumTreeShare))
		output.Info("Connecting to SMB share...")

		if enumTreePath == "" {
			enumTreePath = "."
		}

		tree, err := smbCl.WalkTree(enumTreeShare, enumTreePath, enumTreeDepth)
		if err != nil {
			return fmt.Errorf("walk tree: %w", err)
		}

		if tree == nil {
			output.Warn("No results found or share inaccessible.")
			return nil
		}

		output.PrintTree(tree)
		return nil
	},
}

func init() {
	enumTreeCmd.Flags().StringVarP(&enumTreeShare, "share", "s", "", "SMB share to walk (required)")
	enumTreeCmd.Flags().StringVarP(&enumTreePath, "path", "P", ".", "Starting sub-path within the share")
	enumTreeCmd.Flags().IntVarP(&enumTreeDepth, "depth", "D", 3, "Maximum depth of recursion")
}

// ── enum local-admins ────────────────────────────────────────────────────────

var enumLocalAdminsCmd = &cobra.Command{
	Use:   "local-admins",
	Short: "Identify domain users with local admin rights via GPO (no host scanning)",
	Long: `Analyzes Group Policy Objects (GPO) stored in SYSVOL to identify which domain
users or groups are granted local administrator rights on domain-joined workstations.

Technique:
  Parses 'Restricted Groups' (GptTmpl.inf) and 'Group Policy Preferences' (Groups.xml)
  from SYSVOL. Cross-references SID values to resolve human-readable identities.

Advantages over network-based admin hunting:
  - No traffic to workstations (fully stealth, DC-only)
  - Works even when hosts are offline or firewalled
  - Requires only LDAP + SMB access to the Domain Controller

Requires: valid domain credentials with SYSVOL read access

Example:
  adreaper enum local-admins -d corp.local --dc-ip 10.10.10.1 -u user -p pass`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		if !opts.IsAuthenticated() {
			return fmt.Errorf("local-admin hunting requires valid credentials")
		}

		ctx := context.Background()
		output.Section("Local Admin Hunting (via GPO)")

		ldapCl, err := recon.NewLDAPClient(opts)
		if err != nil {
			return err
		}
		defer ldapCl.Close()

		smbCl, err := recon.NewSMBClient(opts)
		if err != nil {
			return fmt.Errorf("SMB connect (SYSVOL access): %w", err)
		}
		defer smbCl.Close()

		results, err := ldapCl.FindLocalAdmins(ctx, smbCl)
		if err != nil {
			return err
		}

		if len(results) == 0 {
			output.Info("No local administrative mappings found in GPOs")
			return nil
		}

		var rows [][]string
		for _, r := range results {
			rows = append(rows, []string{r.Principal, r.PolicyTarget, r.Source})
		}

		output.PrintTable([]string{"PRINCIPAL (User/Group)", "GPO NAME", "POLICY SOURCE"}, rows)
		return nil
	},
}

// ── enum all ─────────────────────────────────────────────────────────────────

var enumAllCmd = &cobra.Command{
	Use:   "all",
	Short: "High-level domain radiography — aggregate counts of all object types",
	Long: `Performs a single breadth-first sweep of the domain and reports aggregate counts.
Faster than running each 'enum' subcommand individually. Ideal as the first command
after authentication to understand the domain's scale.

Reported Categories:
  Users      All user accounts (including service accounts and disabled)
  Computers  All computer accounts (workstations, servers, DCs)
  Groups     All security and distribution groups
  Trusts     Cross-domain / forest trust relationships
  OUs        Organizational Unit containers
  GPOs       Group Policy Objects

Tip: Combine with '-o output.txt' to capture the overview for your report.

Examples:
  adreaper enum all -d corp.local --dc-ip 10.10.10.1 -u user -p pass
  adreaper enum all -d corp.local --dc-ip 10.10.10.1 -u user -p pass -o overview.txt`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		ctx := context.Background()
		output.Section("Domain-Wide Reconnaissance (Super-Enum)")

		ldapCl, err := recon.NewLDAPClient(opts)
		if err != nil {
			return err
		}
		defer ldapCl.Close()

		output.Info("Performing breadth-first discovery of domain objects...")
		summary, err := ldapCl.QueryAll(ctx)
		if err != nil {
			return err
		}

		output.Success("Aggregate Domain Report Extracted")
		fmt.Println()

		var rows [][]string
		rows = append(rows, []string{"Users", fmt.Sprintf("%d", summary.UserCount), "Personnel/Service identites"})
		rows = append(rows, []string{"Computers", fmt.Sprintf("%d", summary.ComputerCount), "Workstations, Servers, and DCs"})
		rows = append(rows, []string{"Groups", fmt.Sprintf("%d", summary.GroupCount), "Permission containers"})
		rows = append(rows, []string{"Trusts", fmt.Sprintf("%d", summary.TrustCount), "Inter-domain relationships"})
		rows = append(rows, []string{"OUs", fmt.Sprintf("%d", summary.OUCount), "Deployment containers"})
		rows = append(rows, []string{"GPOs", fmt.Sprintf("%d", summary.GPOCount), "Configuration policies"})

		output.PrintTable([]string{"CATEGORY", "COUNT", "DESCRIPTION"}, rows)

		output.Info("Use specific 'enum <category>' commands for detailed attribute inspection.")
		return nil
	},
}

// ── enum dump ─────────────────────────────────────────────────────────────────

var enumDumpCmd = &cobra.Command{
	Use:   "dump",
	Short: "Full AD object extraction — all users, computers, and groups in categorized tables",
	Long: `Performs a complete data extraction of all primary Active Directory objects.
Results are presented in three separate, categorized tables for maximum readability.

Extracted Data:
  Domain Users      : SAMAccountName, UPN, Description
  Domain Computers  : SAMAccountName, DNS Hostname, Operating System
  Domain Groups     : Group Name, Member count, Description

This command is the 'nuclear option' — run it when you want total visibility
before deciding which specific 'enum' subcommand to run for deeper analysis.

Tip: Combine with '-o dump.txt' to save the full object list for offline analysis.

Examples:
  adreaper enum dump -d corp.local --dc-ip 10.10.10.1 -u user -p pass
  adreaper enum dump -d corp.local --dc-ip 10.10.10.1 -u user -p pass -o full_dump.txt`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		ctx := context.Background()
		output.Section("Total AD Object Dump")

		ldapCl, err := recon.NewLDAPClient(opts)
		if err != nil {
			return err
		}
		defer ldapCl.Close()

		output.Info("Extracting all primary directory objects (this may take a moment)...")
		users, comps, groups, err := ldapCl.QueryDump(ctx)
		if err != nil {
			return err
		}

		output.Success("Extraction complete: %d Objects found", len(users)+len(comps)+len(groups))

		// 1. Users Section
		if len(users) > 0 {
			output.Section("Domain Users")
			var userRows [][]string
			for _, u := range users {
				userRows = append(userRows, []string{u.SAMAccountName, u.UPN, u.Description})
			}
			output.PrintTable([]string{"SAMACCOUNTNAME", "UPN", "DESCRIPTION"}, userRows)
		}

		// 2. Computers Section
		if len(comps) > 0 {
			output.Section("Domain Computers")
			var compRows [][]string
			for _, c := range comps {
				compRows = append(compRows, []string{c.SAMAccountName, c.DNSHostName, c.OperatingSystem})
			}
			output.PrintTable([]string{"SAMACCOUNTNAME", "DNS HOSTNAME", "OPERATING SYSTEM"}, compRows)
		}

		// 3. Groups Section
		if len(groups) > 0 {
			output.Section("Domain Groups")
			var groupRows [][]string
			for _, g := range groups {
				groupRows = append(groupRows, []string{g.SAMAccountName, fmt.Sprintf("%d", len(g.Members)), g.Description})
			}
			output.PrintTable([]string{"GROUP NAME", "MEMBERS", "DESCRIPTION"}, groupRows)
		}

		output.Info("Use specific 'enum <category>' commands for deeper attribute analysis.")
		return nil
	},
}

func countTreeItems(node *output.TreeEntry) int {
	if node == nil {
		return 0
	}
	count := 1 // current node
	for _, child := range node.Children {
		count += countTreeItems(child)
	}
	return count
}
