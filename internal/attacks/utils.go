package attacks

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// LoadUsersFile reads a file with one username per line.
func LoadUsersFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("could not open users file '%s': %w", path, err)
	}
	defer f.Close()

	var users []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			users = append(users, line)
		}
	}
	return users, scanner.Err()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
