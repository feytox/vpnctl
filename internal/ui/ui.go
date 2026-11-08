// Package ui prints messages and asks confirmations in the terminal.
package ui

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

var (
	Red, Green, Yellow, Dim, Bold, Reset string

	// AssumeYes answers yes to every Confirm (the -y flag).
	AssumeYes bool
)

func init() {
	if fi, err := os.Stdout.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 && os.Getenv("NO_COLOR") == "" {
		Red, Green, Yellow, Dim, Bold, Reset = "\033[31m", "\033[32m", "\033[33m", "\033[2m", "\033[1m", "\033[0m"
	}
}

func Info(format string, a ...any) { fmt.Printf(format+"\n", a...) }
func OK(format string, a ...any)   { fmt.Printf(Green+"+"+Reset+" "+format+"\n", a...) }

func Warn(format string, a ...any) {
	fmt.Fprintf(os.Stderr, Yellow+"!"+Reset+" "+format+"\n", a...)
}

func Die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, Red+"x"+Reset+" "+format+"\n", a...)
	os.Exit(1)
}

func Header(s string) { fmt.Printf("\n%s%s%s\n", Bold, s, Reset) }

// KV prints an aligned key-value line; fmt pads by runes, so Cyrillic keys stay aligned.
func KV(k, v string) { fmt.Printf("  %-14s %s\n", k, v) }

// Mark colours s green when good, red otherwise.
func Mark(s string, good bool) string {
	if good {
		return Green + s + Reset
	}
	return Red + s + Reset
}

func Confirm(q string) bool {
	if AssumeYes {
		return true
	}
	fmt.Printf("%s [y/N] ", q)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes" || line == "д" || line == "да"
}
