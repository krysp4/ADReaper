package cmd

import (
	"context"
	"fmt"

	"adreaper/internal/bloodhound"
	"adreaper/internal/output"
	"adreaper/internal/recon"
	"adreaper/internal/workspace"

	"github.com/spf13/cobra"
)

var bloodhoundCmd = &cobra.Command{
	Use:   "bloodhound",
	Short: "BloodHound data collection and Neo4j ingestion",
}

func init() {
	bloodhoundCmd.AddCommand(bhCollectCmd)
	bloodhoundCmd.AddCommand(bhIngestCmd)
}

// ── bloodhound collect ───────────────────────────────────────────────────────

var bhCollectCmd = &cobra.Command{
	Use:   "collect",
	Short: "Collect AD data in SharpHound-compatible JSON format",
	Long: `Collects all Active Directory data and outputs SharpHound-compatible JSON files:
  - computers.json, users.json, groups.json, domains.json
  Files can be imported directly into BloodHound CE.

Example:
  adreaper bloodhound collect -d corp.local --dc-ip 10.10.10.1 -u admin -p pass`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		ctx := context.Background()
		output.Section("BloodHound Data Collection")

		ldapCl, err := recon.NewLDAPClient(opts)
		if err != nil {
			return fmt.Errorf("LDAP connect: %w", err)
		}
		defer ldapCl.Close()

		collector := bloodhound.NewCollector(ldapCl, opts)
		result, err := collector.Collect(ctx)
		if err != nil {
			return err
		}

		output.Success("Collected: %d users, %d computers, %d groups",
			len(result.Users), len(result.Computers), len(result.Groups))

		ws, err := workspace.New(opts.WorkspaceDir, opts.Domain)
		if err != nil {
			return err
		}

		files, err := collector.SaveJSON(ws.Dir, result)
		if err != nil {
			return err
		}

		output.Success("BloodHound JSON files saved:")
		for _, f := range files {
			output.Info("  %s", f)
		}

		output.Info("Import with: bloodhound-ce import <dir> or drag & drop into BloodHound CE UI")
		return nil
	},
}

// ── bloodhound ingest ────────────────────────────────────────────────────────

var (
	bhNeo4jURI  string
	bhNeo4jUser string
	bhNeo4jPass string
)

var bhIngestCmd = &cobra.Command{
	Use:   "ingest",
	Short: "Ingest collected data directly into Neo4j / BloodHound CE",
	Long: `Connects to a running Neo4j instance (BloodHound CE) and ingests all AD data.
Requires a prior 'bloodhound collect' run.

Example:
  adreaper bloodhound ingest --neo4j-uri bolt://localhost:7687 --neo4j-user neo4j --neo4j-pass bloodhound`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		ctx := context.Background()
		output.Section("Neo4j Ingestion")

		if bhNeo4jURI == "" {
			return fmt.Errorf("--neo4j-uri is required")
		}

		opts.Neo4jURI = bhNeo4jURI
		opts.Neo4jUser = bhNeo4jUser
		opts.Neo4jPassword = bhNeo4jPass

		ldapCl, err := recon.NewLDAPClient(opts)
		if err != nil {
			return err
		}
		defer ldapCl.Close()

		collector := bloodhound.NewCollector(ldapCl, opts)
		result, err := collector.Collect(ctx)
		if err != nil {
			return err
		}

		ingestor, err := bloodhound.NewNeo4jIngestor(opts)
		if err != nil {
			return fmt.Errorf("neo4j connect: %w", err)
		}
		defer ingestor.Close(ctx)

		output.Info("Ingesting %d users...", len(result.Users))
		if err := ingestor.IngestUsers(ctx, result.Users); err != nil {
			return err
		}
		output.Info("Ingesting %d computers...", len(result.Computers))
		if err := ingestor.IngestComputers(ctx, result.Computers); err != nil {
			return err
		}
		output.Info("Ingesting %d groups...", len(result.Groups))
		if err := ingestor.IngestGroups(ctx, result.Groups); err != nil {
			return err
		}

		output.Success("Neo4j ingestion complete. Open BloodHound CE to explore attack paths.")
		return nil
	},
}

func init() {
	bhIngestCmd.Flags().StringVar(&bhNeo4jURI, "neo4j-uri", "bolt://localhost:7687", "Neo4j Bolt URI")
	bhIngestCmd.Flags().StringVar(&bhNeo4jUser, "neo4j-user", "neo4j", "Neo4j username")
	bhIngestCmd.Flags().StringVar(&bhNeo4jPass, "neo4j-pass", "bloodhound", "Neo4j password")
}
