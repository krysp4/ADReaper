package bloodhound

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"adreaper/internal/config"
	"adreaper/internal/output"
	"adreaper/internal/recon"
)

// CollectionResult holds all collected AD objects for BloodHound ingestion.
type CollectionResult struct {
	Users      []recon.User
	Computers  []recon.Computer
	Groups     []recon.Group
	OUs        []recon.OU
	GPOs       []recon.GPO
	Containers []recon.Container
	Domain     *recon.DomainInfo
	Trusts     []recon.Trust
	Collected  time.Time
}

// Collector collects AD data in SharpHound-compatible format.
type Collector struct {
	ldap *recon.LDAPClient
	opts *config.Options
}

// NewCollector creates a BloodHound collector using an existing LDAP client.
func NewCollector(ldap *recon.LDAPClient, opts *config.Options) *Collector {
	return &Collector{ldap: ldap, opts: opts}
}

// Collect gathers all AD data needed for BloodHound graph analysis.
func (c *Collector) Collect(ctx context.Context) (*CollectionResult, error) {
	result := &CollectionResult{Collected: time.Now()}

	output.Info("Collecting users...")
	users, err := c.ldap.QueryUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("user collection: %w", err)
	}
	result.Users = users

	output.Info("Collecting computers...")
	comps, err := c.ldap.QueryComputers(ctx)
	if err != nil {
		return nil, fmt.Errorf("computer collection: %w", err)
	}
	result.Computers = comps

	output.Info("Collecting groups...")
	groups, err := c.ldap.QueryGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("group collection: %w", err)
	}
	result.Groups = groups

	output.Info("Collecting domain info...")
	domain, err := c.ldap.QueryDomainInfo(ctx)
	if err != nil {
		output.Warn("Domain info collection failed: %v", err)
	} else {
		result.Domain = domain
	}

	output.Info("Collecting trusts...")
	trusts, err := c.ldap.QueryTrusts(ctx)
	if err != nil {
		output.Warn("Trust collection failed: %v", err)
	} else {
		result.Trusts = trusts
	}

	output.Info("Collecting OUs...")
	ous, _ := c.ldap.QueryOUs(ctx)
	result.OUs = ous

	output.Info("Collecting GPOs...")
	gpos, _ := c.ldap.QueryGPOs(ctx)
	result.GPOs = gpos

	output.Info("Collecting Containers...")
	containers, _ := c.ldap.QueryContainers(ctx)
	result.Containers = containers

	return result, nil
}

// ── SharpHound-compatible JSON output ────────────────────────────────────────
// BloodHound CE accepts JSON files with specific structure exported by SharpHound.
// We replicate the format for compatibility.

type bhMeta struct {
	Methods int    `json:"methods"`
	Type    string `json:"type"`
	Count   int    `json:"count"`
	Version int    `json:"version"`
}

type bhUsersFile struct {
	Data []bhUser `json:"data"`
	Meta bhMeta   `json:"meta"`
}

type bhUser struct {
	Properties       map[string]any `json:"Properties"`
	SPNTargets       []any          `json:"SPNTargets"`
	HasSIDHistory    []any          `json:"HasSIDHistory"`
	IsDeleted        bool           `json:"IsDeleted"`
	IsACLProtected   bool           `json:"IsACLProtected"`
	ObjectIdentifier string         `json:"ObjectIdentifier"`
}

type bhComputersFile struct {
	Data []bhComputer `json:"data"`
	Meta bhMeta       `json:"meta"`
}

type bhComputer struct {
	Properties       map[string]any `json:"Properties"`
	ObjectIdentifier string         `json:"ObjectIdentifier"`
	IsACLProtected   bool           `json:"IsACLProtected"`
}

type bhGroupsFile struct {
	Data []bhGroup `json:"data"`
	Meta bhMeta    `json:"meta"`
}

type bhGroup struct {
	Properties       map[string]any `json:"Properties"`
	Members          []bhMember     `json:"Members"`
	ObjectIdentifier string         `json:"ObjectIdentifier"`
	IsACLProtected   bool           `json:"IsACLProtected"`
}

type bhMember struct {
	ObjectIdentifier string `json:"ObjectIdentifier"`
	ObjectType       string `json:"ObjectType"`
}

type bhOUsFile struct {
	Data []bhOU `json:"data"`
	Meta bhMeta `json:"meta"`
}

type bhOU struct {
	Properties       map[string]any `json:"Properties"`
	ObjectIdentifier string         `json:"ObjectIdentifier"`
	IsACLProtected   bool           `json:"IsACLProtected"`
}

type bhGPOsFile struct {
	Data []bhGPO `json:"data"`
	Meta bhMeta  `json:"meta"`
}

type bhGPO struct {
	Properties       map[string]any `json:"Properties"`
	ObjectIdentifier string         `json:"ObjectIdentifier"`
	IsACLProtected   bool           `json:"IsACLProtected"`
}

type bhContainersFile struct {
	Data []bhContainer `json:"data"`
	Meta bhMeta        `json:"meta"`
}

type bhContainer struct {
	Properties       map[string]any `json:"Properties"`
	ObjectIdentifier string         `json:"ObjectIdentifier"`
	IsACLProtected   bool           `json:"IsACLProtected"`
}

// SaveJSON writes SharpHound-compatible JSON files to the given directory.
func (c *Collector) SaveJSON(dir string, result *CollectionResult) ([]string, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	var files []string
	ts := time.Now().Format("20060102150405")

	// ── Users ──
	bhUsers := make([]bhUser, 0, len(result.Users))
	for _, u := range result.Users {
		bhUsers = append(bhUsers, bhUser{
			ObjectIdentifier: u.DN,
			Properties: map[string]any{
				"name":                    u.SAMAccountName + "@" + c.opts.Domain,
				"domain":                  c.opts.Domain,
				"distinguishedname":       u.DN,
				"enabled":                 u.Enabled,
				"admincount":              u.AdminCount,
				"hasspn":                  len(u.SPNs) > 0,
				"dontreqpreauth":          u.NoKerbPreauth,
				"unconstraineddelegation": u.UnconstrainedDelegation,
				"passwordneverexpires":    u.PasswordNeverExpires,
				"lastlogon":               u.LastLogon.Unix(),
				"pwdlastset":              u.PasswordLastSet.Unix(),
				"description":             u.Description,
				"displayname":             u.DisplayName,
				"title":                   u.Title,
				"department":              u.Department,
				"mail":                    u.Mail,
				"objectsid":               u.SID,
			},
		})
	}
	usersFile := fmt.Sprintf("%s_%s_users.json", ts, c.opts.Domain)
	if err := writeJSON(filepath.Join(dir, usersFile), bhUsersFile{
		Data: bhUsers,
		Meta: bhMeta{Type: "users", Count: len(bhUsers), Version: 5},
	}); err != nil {
		return nil, err
	}
	files = append(files, usersFile)

	// ── Computers ──
	bhComps := make([]bhComputer, 0, len(result.Computers))
	for _, comp := range result.Computers {
		bhComps = append(bhComps, bhComputer{
			ObjectIdentifier: comp.SAMAccountName + "@" + c.opts.Domain,
			Properties: map[string]any{
				"name":                    comp.DNSHostName,
				"domain":                  c.opts.Domain,
				"operatingsystem":         comp.OperatingSystem,
				"enabled":                 comp.Enabled,
				"isdc":                    comp.IsDC,
				"unconstraineddelegation": comp.UnconstrainedDelegation,
				"haslaps":                 comp.LAPSEnabled,
				"lastlogon":               comp.LastLogon.Unix(),
				"displayname":             comp.DisplayName,
				"objectsid":               comp.SID,
			},
		})
	}
	compsFile := fmt.Sprintf("%s_%s_computers.json", ts, c.opts.Domain)
	if err := writeJSON(filepath.Join(dir, compsFile), bhComputersFile{
		Data: bhComps,
		Meta: bhMeta{Type: "computers", Count: len(bhComps), Version: 5},
	}); err != nil {
		return nil, err
	}
	files = append(files, compsFile)

	// ── Groups ──
	bhGroups := make([]bhGroup, 0, len(result.Groups))
	for _, g := range result.Groups {
		members := make([]bhMember, 0, len(g.Members))
		for _, m := range g.Members {
			members = append(members, bhMember{ObjectIdentifier: m, ObjectType: "Base"})
		}
		bhGroups = append(bhGroups, bhGroup{
			ObjectIdentifier: g.DN,
			Members:          members,
			Properties: map[string]any{
				"name":        g.SAMAccountName + "@" + c.opts.Domain,
				"domain":      c.opts.Domain,
				"admincount":  g.AdminCount,
				"description": g.Description,
			},
		})
	}
	groupsFile := fmt.Sprintf("%s_%s_groups.json", ts, c.opts.Domain)
	if err := writeJSON(filepath.Join(dir, groupsFile), bhGroupsFile{
		Data: bhGroups,
		Meta: bhMeta{Type: "groups", Count: len(bhGroups), Version: 5},
	}); err != nil {
		return nil, err
	}
	files = append(files, groupsFile)

	// ── OUs ──
	bhOUs := make([]bhOU, 0, len(result.OUs))
	for _, ou := range result.OUs {
		bhOUs = append(bhOUs, bhOU{
			ObjectIdentifier: ou.GUID,
			Properties: map[string]any{
				"name":              ou.Name,
				"distinguishedname": ou.DN,
				"domain":            c.opts.Domain,
			},
		})
	}
	ousFile := fmt.Sprintf("%s_%s_ous.json", ts, c.opts.Domain)
	if err := writeJSON(filepath.Join(dir, ousFile), bhOUsFile{
		Data: bhOUs,
		Meta: bhMeta{Type: "ous", Count: len(bhOUs), Version: 5},
	}); err != nil {
		return nil, err
	}
	files = append(files, ousFile)

	// ── GPOs ──
	bhGPOs := make([]bhGPO, 0, len(result.GPOs))
	for _, gpo := range result.GPOs {
		bhGPOs = append(bhGPOs, bhGPO{
			ObjectIdentifier: gpo.GUID,
			Properties: map[string]any{
				"name":              gpo.DisplayName,
				"distinguishedname": gpo.DN,
				"domain":            c.opts.Domain,
				"gpcpath":           gpo.Path,
			},
		})
	}
	gposFile := fmt.Sprintf("%s_%s_gpos.json", ts, c.opts.Domain)
	if err := writeJSON(filepath.Join(dir, gposFile), bhGPOsFile{
		Data: bhGPOs,
		Meta: bhMeta{Type: "gpos", Count: len(bhGPOs), Version: 5},
	}); err != nil {
		return nil, err
	}
	files = append(files, gposFile)

	// ── Containers ──
	bhConts := make([]bhContainer, 0, len(result.Containers))
	for _, cont := range result.Containers {
		bhConts = append(bhConts, bhContainer{
			ObjectIdentifier: cont.GUID,
			Properties: map[string]any{
				"name":              cont.Name,
				"distinguishedname": cont.DN,
				"domain":            c.opts.Domain,
			},
		})
	}
	contsFile := fmt.Sprintf("%s_%s_containers.json", ts, c.opts.Domain)
	if err := writeJSON(filepath.Join(dir, contsFile), bhContainersFile{
		Data: bhConts,
		Meta: bhMeta{Type: "containers", Count: len(bhConts), Version: 5},
	}); err != nil {
		return nil, err
	}
	files = append(files, contsFile)

	return files, nil
}

func writeJSON(path string, v any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
