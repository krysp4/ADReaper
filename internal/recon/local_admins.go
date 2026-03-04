package recon

import (
	"context"
	"fmt"
	"strings"
)

// LocalAdminResult maps a machine (or OU) to the users/groups that have admin rights.
type LocalAdminResult struct {
	PolicyTarget string // GPO Name or Affected Container
	Principal    string // User or Group SID/Name
	Machine      string // Target Machine (if specified in GPP)
	Source       string // "Restricted Groups" or "Group Policy Preferences"
}

// FindLocalAdmins crawls GPOs in SYSVOL to identify administrative mappings.
func (c *LDAPClient) FindLocalAdmins(ctx context.Context, smb *SMBClient) ([]LocalAdminResult, error) {
	gpos, err := c.QueryGPOs(ctx)
	if err != nil {
		return nil, fmt.Errorf("query GPOs: %w", err)
	}

	var results []LocalAdminResult

	for _, gpo := range gpos {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		// 1. Check Restricted Groups (GptTmpl.inf)
		// Path: \\domain.local\SYSVOL\domain.local\Policies\{GUID}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
		relPath := strings.TrimPrefix(gpo.Path, fmt.Sprintf("\\\\%s\\sysvol\\", strings.ToLower(c.opts.Domain)))
		relPath = strings.TrimPrefix(relPath, "SYSVOL\\") // handle variations

		infPath := relPath + "\\Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf"
		infData, err := smb.ReadSYSVOL(infPath)
		if err == nil {
			results = append(results, parseRestrictedGroups(gpo.DisplayName, string(infData))...)
		}

		// 2. Check Group Policy Preferences (Groups.xml)
		// Path: \\domain.local\SYSVOL\domain.local\Policies\{GUID}\Machine\Preferences\Groups\Groups.xml
		xmlPath := relPath + "\\Machine\\Preferences\\Groups\\Groups.xml"
		xmlData, err := smb.ReadSYSVOL(xmlPath)
		if err == nil {
			results = append(results, parseGPPGroups(gpo.DisplayName, string(xmlData))...)
		}
	}

	return results, nil
}

// parseRestrictedGroups looks for "[Group Membership]" section in GptTmpl.inf
func parseRestrictedGroups(gpoName, content string) []LocalAdminResult {
	var results []LocalAdminResult
	lines := strings.Split(content, "\n")
	inSection := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "[group membership]") {
			inSection = true
			continue
		}
		if strings.HasPrefix(line, "[") {
			inSection = false
		}

		if inSection && strings.Contains(line, "=") {
			// Format: *S-1-5-32-544__Memberof =
			// Or: *S-1-5-32-544__Members = *S-1-5-21...
			parts := strings.Split(line, "=")
			key := strings.TrimSpace(parts[0])
			val := ""
			if len(parts) > 1 {
				val = strings.TrimSpace(parts[1])
			}

			if strings.Contains(strings.ToLower(key), "s-1-5-32-544") || strings.Contains(strings.ToLower(key), "administrators") {
				// This policy modifies the local Administrators group
				principals := strings.Split(val, ",")
				for _, p := range principals {
					p = strings.Trim(strings.TrimSpace(p), "*")
					if p != "" {
						results = append(results, LocalAdminResult{
							PolicyTarget: gpoName,
							Principal:    p,
							Source:       "Restricted Groups (GptTmpl.inf)",
						})
					}
				}
			}
		}
	}
	return results
}

// parseGPPGroups parses Groups.xml (minimal parser for speed)
func parseGPPGroups(gpoName, content string) []LocalAdminResult {
	var results []LocalAdminResult
	// Minimalist XML parsing for "Local Group" members
	// Example: <UserLocalGroup ... name="Administrators (built-in)"> ... <Properties ... groupName="Administrators"> ... <FilterRunOnce /> <Members> <Member name="LAB\cgarcia" ... />

	// Split by <UserLocalGroup to identify individual group policies
	groups := strings.Split(content, "<UserLocalGroup")
	for _, groupBlock := range groups {
		if !strings.Contains(strings.ToLower(groupBlock), "administrators") {
			continue
		}

		// Extract members
		memberParts := strings.Split(groupBlock, "<Member")
		for _, m := range memberParts {
			if strings.Contains(m, "name=\"") {
				name := extractAttr(m, "name")
				if name != "" {
					results = append(results, LocalAdminResult{
						PolicyTarget: gpoName,
						Principal:    name,
						Source:       "Group Policy Preferences (Groups.xml)",
					})
				}
			}
		}
	}
	return results
}

func extractAttr(content, attr string) string {
	key := attr + "=\""
	idx := strings.Index(content, key)
	if idx == -1 {
		return ""
	}
	start := idx + len(key)
	end := strings.Index(content[start:], "\"")
	if end == -1 {
		return ""
	}
	return content[start : start+end]
}
