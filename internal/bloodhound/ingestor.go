package bloodhound

import (
	"context"
	"fmt"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"adreaper/internal/config"
	"adreaper/internal/recon"
)

// Neo4jIngestor ingests AD data directly into a Neo4j database (BloodHound CE).
type Neo4jIngestor struct {
	driver neo4j.DriverWithContext
}

// NewNeo4jIngestor opens a Neo4j driver connection.
func NewNeo4jIngestor(opts *config.Options) (*Neo4jIngestor, error) {
	uri := opts.Neo4jURI
	if uri == "" {
		uri = "bolt://localhost:7687"
	}
	driver, err := neo4j.NewDriverWithContext(
		uri,
		neo4j.BasicAuth(opts.Neo4jUser, opts.Neo4jPassword, ""),
	)
	if err != nil {
		return nil, fmt.Errorf("neo4j driver: %w", err)
	}
	ctx := context.Background()
	if err := driver.VerifyConnectivity(ctx); err != nil {
		driver.Close(ctx)
		return nil, fmt.Errorf("neo4j connectivity: %w", err)
	}
	return &Neo4jIngestor{driver: driver}, nil
}

// Close releases the Neo4j driver.
func (n *Neo4jIngestor) Close(ctx context.Context) {
	if n.driver != nil {
		_ = n.driver.Close(ctx)
	}
}

// IngestUsers creates User nodes in Neo4j.
func (n *Neo4jIngestor) IngestUsers(ctx context.Context, users []recon.User) error {
	session := n.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	for _, u := range users {
		_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
			_, err := tx.Run(ctx,
				`MERGE (u:User {objectid: $dn})
				 SET u.name = $name,
				     u.samaccountname = $sam,
				     u.enabled = $enabled,
				     u.admincount = $admincount,
				     u.hasspn = $hasspn,
				     u.dontreqpreauth = $asrep,
				     u.unconstraineddelegation = $unconstrained,
				     u.passwordneverexpires = $nopwdexp,
				     u.description = $desc,
				     u.domain = $domain`,
				map[string]any{
					"dn":            u.DN,
					"name":          u.SAMAccountName,
					"sam":           u.SAMAccountName,
					"enabled":       u.Enabled,
					"admincount":    u.AdminCount,
					"hasspn":        len(u.SPNs) > 0,
					"asrep":         u.NoKerbPreauth,
					"unconstrained": u.UnconstrainedDelegation,
					"nopwdexp":      u.PasswordNeverExpires,
					"desc":          u.Description,
					"domain":        u.UPN,
				},
			)
			return nil, err
		})
		if err != nil {
			return fmt.Errorf("ingest user %s: %w", u.SAMAccountName, err)
		}
	}
	return nil
}

// IngestComputers creates Computer nodes in Neo4j.
func (n *Neo4jIngestor) IngestComputers(ctx context.Context, comps []recon.Computer) error {
	session := n.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	for _, c := range comps {
		_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
			_, err := tx.Run(ctx,
				`MERGE (c:Computer {objectid: $id})
				 SET c.name = $name,
				     c.operatingsystem = $os,
				     c.enabled = $enabled,
				     c.isdc = $isdc,
				     c.unconstraineddelegation = $unconstrained,
				     c.haslaps = $haslaps`,
				map[string]any{
					"id":            c.SAMAccountName,
					"name":          c.DNSHostName,
					"os":            c.OperatingSystem,
					"enabled":       c.Enabled,
					"isdc":          c.IsDC,
					"unconstrained": c.UnconstrainedDelegation,
					"haslaps":       c.LAPSEnabled,
				},
			)
			return nil, err
		})
		if err != nil {
			return fmt.Errorf("ingest computer %s: %w", c.SAMAccountName, err)
		}
	}
	return nil
}

// IngestGroups creates Group nodes and MemberOf relationships in Neo4j.
func (n *Neo4jIngestor) IngestGroups(ctx context.Context, groups []recon.Group) error {
	session := n.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	for _, g := range groups {
		_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
			// Create group node
			_, err := tx.Run(ctx,
				`MERGE (g:Group {objectid: $dn})
				 SET g.name = $name, g.admincount = $admin, g.description = $desc`,
				map[string]any{
					"dn":    g.DN,
					"name":  g.SAMAccountName,
					"admin": g.AdminCount,
					"desc":  g.Description,
				},
			)
			if err != nil {
				return nil, err
			}
			// Create MemberOf relationships
			for _, memberDN := range g.Members {
				_, err = tx.Run(ctx,
					`MERGE (m {objectid: $memberDN})
					 MERGE (g:Group {objectid: $groupDN})
					 MERGE (m)-[:MemberOf]->(g)`,
					map[string]any{"memberDN": memberDN, "groupDN": g.DN},
				)
				if err != nil {
					return nil, err
				}
			}
			return nil, nil
		})
		if err != nil {
			return fmt.Errorf("ingest group %s: %w", g.SAMAccountName, err)
		}
	}
	return nil
}
