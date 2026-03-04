package cmd

import (
	"fmt"
	"os"

	"adreaper/internal/config"
	"adreaper/internal/output"

	"github.com/spf13/cobra"
)

// opts is shared across all subcommands.
var opts = config.DefaultOptions()

var rootCmd = &cobra.Command{
	Use:   "adreaper",
	Short: "ADReaper v4.0.0 — Active Directory Red Team Toolkit",
	Long: `ADReaper is a professional-grade Active Directory reconnaissance and exploitation toolkit
designed for Red Teams and senior penetration testers.

It provides a modular CLI interface covering the full attack chain:
  1. Infrastructure scanning and OS fingerprinting
  2. LDAP-based AD enumeration (users, groups, computers, trusts, ACLs, ADCS)
  3. Offensive attacks (Kerberoasting, AS-REP Roasting, DCSync, Ticket Forgery, RBCD)
  4. Post-exploitation (GPP decryption, file harvesting, credential relay)
  5. BloodHound CE data collection and Neo4j ingestion
  6. Automated engagement orchestration (autopilot)

Authentication methods:
  - Username + Password       : -u admin -p 'P@ssword'
  - Pass-the-Hash (NTLM)      : --hash aad3b435b51404ee:31d6cfe0d16ae931

Session Logging:
  - Mirror all output to .txt : -o engagement_log

Examples:
  adreaper enum all   -d corp.local --dc-ip 10.10.10.1 -u user -p pass
  adreaper enum dump  -d corp.local --dc-ip 10.10.10.1 -u user -p pass -o dump.txt
  adreaper attack kerberoast -d corp.local --dc-ip 10.10.10.1 -u user -p pass`,
	// Don't validate target for top-level help/version
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the root command.
func Execute() {
	output.PrintBanner()
	if err := rootCmd.Execute(); err != nil {
		output.Error("%v", err)
		os.Exit(1)
	}
}

func init() {

	// ── Target ──────────────────────────────────────────────────────
	rootCmd.PersistentFlags().StringVarP(&opts.Domain, "domain", "d", "", "Target AD domain FQDN          (e.g. corp.local)")
	rootCmd.PersistentFlags().StringVar(&opts.DCIP, "dc-ip", "", "Domain Controller IPv4 address  (e.g. 10.10.10.1)")

	// ── Auth ─────────────────────────────────────────────────────────
	rootCmd.PersistentFlags().StringVarP(&opts.Username, "username", "u", "", "AD username for authentication")
	rootCmd.PersistentFlags().StringVarP(&opts.Password, "password", "p", "", "Plaintext password")
	rootCmd.PersistentFlags().StringVar(&opts.NTHash, "hash", "", "NTLM hash for Pass-the-Hash    (format: LM:NT or just NT)")

	// ── Protocol ─────────────────────────────────────────────────────
	rootCmd.PersistentFlags().BoolVar(&opts.UseLDAPS, "ldaps", false, "Use LDAPS (TLS, port 636) instead of plain LDAP")

	// ── Output ───────────────────────────────────────────────────────
	rootCmd.PersistentFlags().StringVarP(&opts.OutputFile, "output", "o", "", "Mirror all session output to a .txt file (auto-appends .txt if omitted)")
	rootCmd.PersistentFlags().StringVar(&opts.WorkspaceDir, "workspace", "./workspace", "Directory for JSON evidence files (users.json, ADCS, BloodHound data)")
	rootCmd.PersistentFlags().BoolVar(&opts.OutputJSON, "json", false, "Format module output as JSON")
	rootCmd.PersistentFlags().BoolVarP(&opts.Verbose, "verbose", "v", false, "Enable verbose/debug output")

	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if opts.OutputFile != "" {
			if err := output.SetOutputFile(opts.OutputFile); err != nil {
				return fmt.Errorf("set output file: %w", err)
			}
		}
		return nil
	}

	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(enumCmd)
	rootCmd.AddCommand(attackCmd)
	rootCmd.AddCommand(bloodhoundCmd)
	rootCmd.AddCommand(autopilotCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print ADReaper version and build info",
	Run: func(cmd *cobra.Command, args []string) {
		output.PrintBanner()
		fmt.Printf("  ADReaper v%s\n\n", output.Version)
	},
}
