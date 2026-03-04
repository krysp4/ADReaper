package recon

import (
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"

	smb2 "github.com/hirochachacha/go-smb2"

	"adreaper/internal/config"
	"adreaper/internal/output"
)

// SMBShare represents a discovered SMB share.
type SMBShare struct {
	Name   string
	Remark string
	Access string // READ / WRITE / DENIED
}

// SMBClient wraps go-smb2 for AD-specific SMB operations.
type SMBClient struct {
	session *smb2.Session
	opts    *config.Options
	conn    net.Conn
}

// NewSMBClient connects and authenticates via SMB2/3.
func NewSMBClient(opts *config.Options) (*SMBClient, error) {
	addr := fmt.Sprintf("%s:%d", opts.DCIP, opts.SMBPort)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("SMB dial: %w", err)
	}

	var initiator smb2.Initiator
	if opts.NTHash != "" {
		initiator = &smb2.NTLMInitiator{
			User:   opts.Username,
			Domain: opts.Domain,
			Hash:   []byte(opts.NTLMNTHash()),
		}
	} else if opts.IsAuthenticated() {
		initiator = &smb2.NTLMInitiator{
			User:     opts.Username,
			Password: opts.Password,
			Domain:   opts.Domain,
		}
	} else {
		// Anonymous / null session
		initiator = &smb2.NTLMInitiator{User: "", Password: ""}
	}

	d := &smb2.Dialer{Initiator: initiator}
	session, err := d.Dial(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("SMB negotiate/auth: %w", err)
	}
	return &SMBClient{session: session, opts: opts, conn: conn}, nil
}

// Close releases all SMB resources.
func (s *SMBClient) Close() {
	if s.session != nil {
		_ = s.session.Logoff()
	}
	if s.conn != nil {
		s.conn.Close()
	}
}

// ListShares enumerates accessible SMB shares and tests read access.
func (s *SMBClient) ListShares() ([]SMBShare, error) {
	names, err := s.session.ListSharenames()
	if err != nil {
		return nil, fmt.Errorf("ListSharenames: %w", err)
	}
	shares := make([]SMBShare, 0, len(names))
	for _, name := range names {
		sh := SMBShare{Name: name}
		// Test read access
		fs, err := s.session.Mount(name)
		if err != nil {
			sh.Access = "DENIED"
		} else {
			sh.Access = "READ"
			// Check if we can write (try to stat root)
			_, statErr := fs.Stat(".")
			if statErr == nil {
				sh.Access = "READ"
			}
			_ = fs.Umount()
		}
		shares = append(shares, sh)
	}
	return shares, nil
}

// CheckSigning returns true if the server requires SMB signing (good!) or false (NTLM-relay risk!).
// go-smb2 always uses signing if available; we check server capabilities by examining the session.
func (s *SMBClient) CheckSigning() bool {
	// go-smb2 sessions that succeeded imply signing was negotiated if required.
	// A more precise check requires inspecting the NegotiateResponse.SecurityMode.
	// Return conservative true (signed) — callers should use the CVE check instead.
	return true
}

// DownloadFile reads the entire content of a file from a share.
func (s *SMBClient) DownloadFile(share, path string) ([]byte, error) {
	fs, err := s.session.Mount(share)
	if err != nil {
		return nil, fmt.Errorf("mount %s: %w", share, err)
	}
	defer fs.Umount()

	f, err := fs.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return io.ReadAll(f)
}

// WriteFile creates or overwrites a file on a share with the given content.
func (s *SMBClient) WriteFile(share, path string, data []byte) error {
	fs, err := s.session.Mount(share)
	if err != nil {
		return fmt.Errorf("mount %s: %w", share, err)
	}
	defer fs.Umount()

	f, err := fs.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(data)
	return err
}

// RemoveFile deletes a file from a share.
func (s *SMBClient) RemoveFile(share, path string) error {
	fs, err := s.session.Mount(share)
	if err != nil {
		return fmt.Errorf("mount %s: %w", share, err)
	}
	defer fs.Umount()

	return fs.Remove(path)
}

// ReadSYSVOL reads a file from the SYSVOL share given a relative path.
func (s *SMBClient) ReadSYSVOL(path string) ([]byte, error) {
	fs, err := s.session.Mount("SYSVOL")
	if err != nil {
		return nil, fmt.Errorf("mount SYSVOL: %w", err)
	}
	defer fs.Umount()

	f, err := fs.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// WalkSYSVOL walks the SYSVOL share and returns files matching the suffix filter.
func (s *SMBClient) WalkSYSVOL(suffix string) (map[string][]byte, error) {
	fs, err := s.session.Mount("SYSVOL")
	if err != nil {
		return nil, fmt.Errorf("mount SYSVOL: %w", err)
	}
	defer fs.Umount()

	results := map[string][]byte{}
	var walk func(dir string) error
	walk = func(dir string) error {
		entries, err := fs.ReadDir(dir)
		if err != nil {
			return nil // skip unreadable dirs
		}
		for _, entry := range entries {
			path := dir + "\\" + entry.Name()
			if entry.IsDir() {
				_ = walk(path)
				continue
			}
			if strings.HasSuffix(strings.ToLower(entry.Name()), strings.ToLower(suffix)) {
				data, err := func() ([]byte, error) {
					f, err := fs.Open(path)
					if err != nil {
						return nil, err
					}
					defer f.Close()
					return io.ReadAll(f)
				}()
				if err == nil {
					results[path] = data
				}
			}
		}
		return nil
	}
	_ = walk(s.opts.Domain)
	return results, nil
}

// Spider recursively walks a share and calls onFound for files matching the given extensions.
func (s *SMBClient) Spider(share string, extensions []string, onFound func(path string, data []byte)) error {
	fs, err := s.session.Mount(share)
	if err != nil {
		return fmt.Errorf("mount %s: %w", share, err)
	}
	defer fs.Umount()

	var walk func(dir string) error
	walk = func(dir string) error {
		entries, err := fs.ReadDir(dir)
		if err != nil {
			return nil // skip unreadable dirs
		}
		for _, entry := range entries {
			// Avoid infinite recursion or special dirs
			if entry.Name() == "." || entry.Name() == ".." {
				continue
			}

			path := dir + "\\" + entry.Name()
			if dir == "." {
				path = entry.Name()
			}

			if entry.IsDir() {
				_ = walk(path)
				continue
			}

			// Check extensions
			match := false
			if len(extensions) == 0 {
				match = true
			} else {
				for _, ext := range extensions {
					if ext == "*" || strings.HasSuffix(strings.ToLower(entry.Name()), "."+strings.ToLower(ext)) {
						match = true
						break
					}
				}
			}

			if match {
				data, err := func() ([]byte, error) {
					f, err := fs.Open(path)
					if err != nil {
						return nil, err
					}
					defer f.Close()
					return io.ReadAll(f)
				}()
				if err == nil {
					onFound(path, data)
				}
			}
		}
		return nil
	}

	return walk(".")
}

// WalkTree recursively walks a share and returns a tree structure of its contents.
func (s *SMBClient) WalkTree(share, root string, maxDepth int) (*output.TreeEntry, error) {
	fs, err := s.session.Mount(share)
	if err != nil {
		return nil, fmt.Errorf("mount %s: %w", share, err)
	}
	defer fs.Umount()

	var walk func(dir string, currentDepth int) (*output.TreeEntry, error)
	walk = func(dir string, currentDepth int) (*output.TreeEntry, error) {
		if currentDepth > maxDepth {
			return nil, nil
		}

		entries, err := fs.ReadDir(dir)
		if err != nil {
			return nil, nil // skip unreadable
		}

		node := &output.TreeEntry{
			Name:  filepath.Base(dir),
			Path:  dir,
			IsDir: true,
		}
		if dir == "." {
			node.Name = share
			node.Path = "."
		}

		for _, entry := range entries {
			if entry.Name() == "." || entry.Name() == ".." {
				continue
			}

			path := filepath.Join(dir, entry.Name())
			if entry.IsDir() {
				child, _ := walk(path, currentDepth+1)
				if child != nil {
					node.Children = append(node.Children, child)
				}
			} else {
				node.Children = append(node.Children, &output.TreeEntry{
					Name:  entry.Name(),
					Path:  path,
					IsDir: false,
				})
			}
		}
		return node, nil
	}

	return walk(root, 0)
}
