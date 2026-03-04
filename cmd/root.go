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
	Short: "ADReaper — Active Directory Red Team Toolkit",
	Long:  "Expert-level Active Directory pentesting. From enumeration to Domain Admin.",
	// Don't validate target for top-level help/version
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		output.Error("%v", err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(func() {
		if rootCmd.CalledAs() != "version" {
			output.PrintBanner()
		}
	})

	// ── Target ──────────────────────────────────────────────────────
	rootCmd.PersistentFlags().StringVarP(&opts.Domain, "domain", "d", "", "Target domain   (e.g. corp.local)")
	rootCmd.PersistentFlags().StringVar(&opts.DCIP, "dc-ip", "", "Domain Controller IP")

	// ── Auth ─────────────────────────────────────────────────────────
	rootCmd.PersistentFlags().StringVarP(&opts.Username, "username", "u", "", "Username")
	rootCmd.PersistentFlags().StringVarP(&opts.Password, "password", "p", "", "Password")
	rootCmd.PersistentFlags().StringVar(&opts.NTHash, "hash", "", "NTLM hash (LM:NT) for Pass-the-Hash")

	// ── Protocol ─────────────────────────────────────────────────────
	rootCmd.PersistentFlags().BoolVar(&opts.UseLDAPS, "ldaps", false, "Use LDAPS (port 636)")

	// ── Output ───────────────────────────────────────────────────────
	rootCmd.PersistentFlags().StringVarP(&opts.OutputFile, "output", "o", "", "Mirror session output to a .txt file")
	rootCmd.PersistentFlags().StringVar(&opts.WorkspaceDir, "workspace", "./workspace", "Evidence output directory (JSON/JSONL)")
	rootCmd.PersistentFlags().BoolVar(&opts.OutputJSON, "json", false, "Output results as JSON")
	rootCmd.PersistentFlags().BoolVarP(&opts.Verbose, "verbose", "v", false, "Verbose output")

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
	Short: "Print ADReaper version",
	Run: func(cmd *cobra.Command, args []string) {
		output.PrintBanner()
		fmt.Printf("  ADReaper v%s\n\n", output.Version)
	},
}
