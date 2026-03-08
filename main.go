package main

import (
	"fmt"

	"adreaper/cmd"
)

func main() {
	cmd.Execute()

	fmt.Printf("\n[!] Press Enter to exit ADReaper...\n")
	fmt.Scanln()
}
