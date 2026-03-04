package config

import (
	"fmt"
	"strings"
	"time"
)

// Options holds all global connection and authentication parameters.
type Options struct {
	// Target
	Domain string
	DCIP   string
	DCFQDN string

	// Authentication
	Username string
	Password string
	NTHash   string // format: LM:NT or just NT

	// LDAP
	UseLDAPS    bool
	LDAPPort    int
	LDAPTimeout time.Duration

	// Kerberos
	KDCAddr string

	// SMB
	SMBPort int

	// BloodHound / Neo4j
	Neo4jURI      string
	Neo4jUser     string
	Neo4jPassword string

	// Output
	WorkspaceDir string
	OutputFile   string
	OutputJSON   bool
	Verbose      bool
}

// DefaultOptions returns safe defaults.
func DefaultOptions() *Options {
	return &Options{
		LDAPPort:     389,
		LDAPTimeout:  15 * time.Second,
		SMBPort:      445,
		WorkspaceDir: "./workspace",
	}
}

// Validate checks required fields and auto-fills derived values.
func (o *Options) Validate() error {
	if o.Domain == "" || strings.HasPrefix(o.Domain, "-") {
		return fmt.Errorf("--domain is required and must not be a flag name")
	}
	if o.DCIP == "" || strings.HasPrefix(o.DCIP, "-") {
		return fmt.Errorf("--dc-ip is required and must not be a flag name")
	}
	if o.KDCAddr == "" {
		o.KDCAddr = o.DCIP
	}
	if o.UseLDAPS && o.LDAPPort == 389 {
		o.LDAPPort = 636
	}
	return nil
}

// LDAPAddr returns the full LDAP connection URL.
func (o *Options) LDAPAddr() string {
	if o.UseLDAPS {
		return fmt.Sprintf("ldaps://%s:%d", o.DCIP, o.LDAPPort)
	}
	return fmt.Sprintf("ldap://%s:%d", o.DCIP, o.LDAPPort)
}

// BaseDN converts "corp.local" → "DC=corp,DC=local".
func (o *Options) BaseDN() string {
	parts := strings.Split(strings.ToLower(o.Domain), ".")
	dcs := make([]string, len(parts))
	for i, p := range parts {
		dcs[i] = "DC=" + p
	}
	return strings.Join(dcs, ",")
}

// IsAuthenticated returns true if credentials are provided.
func (o *Options) IsAuthenticated() bool {
	return o.Username != "" && (o.Password != "" || o.NTHash != "")
}

// NTLMNTHash extracts the NT part from "LM:NT" or plain "NT".
func (o *Options) NTLMNTHash() string {
	if o.NTHash == "" {
		return ""
	}
	parts := strings.SplitN(o.NTHash, ":", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return o.NTHash
}
