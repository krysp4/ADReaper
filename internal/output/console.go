package output

import (
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
)

const Version = "4.0.0"

var (
	sessionLog  *os.File
	infoCol     = color.New(color.FgCyan).SprintFunc()
	successCol  = color.New(color.FgGreen, color.Bold).SprintFunc()
	warnCol     = color.New(color.FgYellow, color.Bold).SprintFunc()
	errCol      = color.New(color.FgRed, color.Bold).SprintFunc()
	criticalCol = color.New(color.BgRed, color.FgWhite, color.Bold).SprintFunc()
)

// TreeEntry represents a file or directory in a tree structure.
type TreeEntry struct {
	Name     string
	Path     string
	IsDir    bool
	Children []*TreeEntry
}

// PrintBanner displays the tool's ASCII banner.
func PrintBanner() {
	banner := `
 █████╗ ██████╗ ██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗ 
██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
███████║██║  ██║██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
██╔══██║██║  ██║██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
██║  ██║██████╔╝██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║
╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
                                              @adreaper v4.0.0
`
	fmt.Println(color.HiRedString(banner))
	logToFile(banner)
}

// SetOutputFile initializes the global session log file.
func SetOutputFile(path string) error {
	if !strings.HasSuffix(strings.ToLower(path), ".txt") {
		path += ".txt"
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	sessionLog = f
	return nil
}

func logToFile(format string, a ...interface{}) {
	if sessionLog == nil {
		return
	}
	msg := fmt.Sprintf(format, a...)
	// Basic ANSI strip (regex could be better but this covers fatih/color)
	msg = stripANSI(msg)
	fmt.Fprintln(sessionLog, msg)
}

func stripANSI(str string) string {
	// Simple ANSI escape sequence remover
	// Could use a more robust regex if needed
	return strings.NewReplacer(
		"\x1b[1m", "", "\x1b[0m", "",
		"\x1b[31m", "", "\x1b[32m", "",
		"\x1b[33m", "", "\x1b[34m", "",
		"\x1b[35m", "", "\x1b[36m", "",
		"\x1b[37m", "", "\x1b[91m", "",
		"\x1b[92m", "", "\x1b[93m", "",
		"\x1b[94m", "", "\x1b[95m", "",
		"\x1b[96m", "", "\x1b[97m", "",
	).Replace(str)
}

// Info prints an informational message.
func Info(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	fmt.Printf("[%s] %s\n", infoCol("*"), msg)
	logToFile("[*] %s", msg)
}

// Success prints a success message.
func Success(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	fmt.Printf("[%s] %s\n", successCol("+"), msg)
	logToFile("[+] %s", msg)
}

// Warn prints a warning message.
func Warn(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	fmt.Printf("[%s] %s\n", warnCol("!"), msg)
	logToFile("[!] %s", msg)
}

// Error prints an error message.
func Error(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	fmt.Fprintf(os.Stderr, "[%s] %s\n", errCol("-"), msg)
	logToFile("[-] %s", msg)
}

// Critical prints a critical error/finding message.
func Critical(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	fmt.Printf("[%s] %s\n", criticalCol("CRITICAL"), msg)
	logToFile("[CRITICAL] %s", msg)
}

// SuccessStr returns a string formatted with the success color.
func SuccessStr(s string) string {
	return successCol(s)
}

// InfoStr returns a string formatted with the info color.
func InfoStr(s string) string {
	return infoCol(s)
}

// CriticalStr returns a string formatted with the critical color.
func CriticalStr(s string) string {
	return criticalCol(s)
}

// WarnStr returns a string formatted with the warn color.
func WarnStr(s string) string {
	return warnCol(s)
}

// Section prints a header for a new logical section.
func Section(name string) {
	fmt.Println()
	color.New(color.FgHiBlue, color.Bold).Printf("── %s ", strings.ToUpper(name))
	color.New(color.FgCyan).Println(strings.Repeat("─", 60-len(name)))
	logToFile("\n%s\n%s", strings.ToUpper(name), strings.Repeat("-", 60))
}

// PrintTree visualizes a recursive TreeEntry structure.
func PrintTree(node *TreeEntry) {
	if node == nil {
		return
	}
	fmt.Println()
	printNode(node, "", true)
}

func printNode(node *TreeEntry, indent string, isLast bool) {
	marker := "├── "
	if isLast {
		marker = "└── "
	}

	name := node.Name
	if node.IsDir {
		name = color.New(color.FgHiBlue, color.Bold).Sprint(name + "/")
	}

	fmt.Printf("%s%s%s\n", indent, marker, name)

	newIndent := indent
	if isLast {
		newIndent += "    "
	} else {
		newIndent += "│   "
	}

	for i, child := range node.Children {
		lastChild := i == len(node.Children)-1
		printNode(child, newIndent, lastChild)
	}
}

// PrintTable renders a slice of string slices as a formatted table with professional alignment.
func PrintTable(header []string, data [][]string) {
	if len(header) == 0 {
		return
	}

	// 1. Calculate max width for each column
	widths := make([]int, len(header))
	for i, h := range header {
		widths[i] = len(h)
	}
	for _, row := range data {
		for i, val := range row {
			if i < len(widths) {
				if len(val) > widths[i] {
					widths[i] = len(val)
				}
			}
		}
	}

	fmt.Println()
	// 2. Print Header
	headerColor := color.New(color.FgHiCyan, color.Bold)
	for i, h := range header {
		fmt.Print(headerColor.Sprint(h))
		fmt.Print(strings.Repeat(" ", widths[i]-len(h)+4)) // 4 spaces padding
	}
	fmt.Println()

	// 3. Print Separator
	separatorColor := color.New(color.FgHiBlack)
	totalWidth := 0
	for _, w := range widths {
		totalWidth += w + 4
	}
	fmt.Println(separatorColor.Sprint(strings.Repeat("─", totalWidth)))

	// 4. Print Data
	for _, row := range data {
		line := ""
		for i, val := range row {
			if i < len(widths) {
				cell := val + strings.Repeat(" ", widths[i]-len(val)+4)
				fmt.Print(cell)
				line += cell
			}
		}
		fmt.Println()
		logToFile(line)
	}
}

// PrintProgressBar renders a professional status bar.
func PrintProgressBar(current, total int) {
	if total <= 0 {
		return
	}
	percent := float64(current) / float64(total) * 100
	width := 20
	completed := int(float64(width) * (float64(current) / float64(total)))
	if completed > width {
		completed = width
	}

	bar := strings.Repeat("█", completed) + strings.Repeat("░", width-completed)

	fmt.Printf("[%s] Progress: [%s] %.1f%% (%d/%d ports)",
		infoCol("*"),
		color.HiCyanString(bar),
		percent,
		current,
		total,
	)
}

// Finding prints a formatted vulnerability finding.
func Finding(severity, title, evidence string) {
	fmt.Printf("[%s] %s\n", criticalCol(severity), color.HiWhiteString(title))
	if evidence != "" {
		for _, line := range strings.Split(evidence, "\n") {
			fmt.Printf("    %s %s\n", infoCol(">"), line)
		}
	}
}
