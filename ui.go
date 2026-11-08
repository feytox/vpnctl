package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

var (
	cRed, cGreen, cYellow, cDim, cBold, cReset string
	assumeYes                                  bool
)

func init() {
	if fi, err := os.Stdout.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 && os.Getenv("NO_COLOR") == "" {
		cRed, cGreen, cYellow, cDim, cBold, cReset = "\033[31m", "\033[32m", "\033[33m", "\033[2m", "\033[1m", "\033[0m"
	}
}

func info(format string, a ...any) { fmt.Printf(format+"\n", a...) }
func ok(format string, a ...any)   { fmt.Printf(cGreen+"+"+cReset+" "+format+"\n", a...) }
func warn(format string, a ...any) {
	fmt.Fprintf(os.Stderr, cYellow+"!"+cReset+" "+format+"\n", a...)
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, cRed+"x"+cReset+" "+format+"\n", a...)
	os.Exit(1)
}

func header(s string) { fmt.Printf("\n%s%s%s\n", cBold, s, cReset) }

// fmt pads by runes, so Cyrillic keys stay aligned.
func kv(k, v string) { fmt.Printf("  %-14s %s\n", k, v) }

func confirm(q string) bool {
	if assumeYes {
		return true
	}
	fmt.Printf("%s [y/N] ", q)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes" || line == "д" || line == "да"
}
