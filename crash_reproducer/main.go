package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// main handles CLI args and calls ReproduceCrash.
func main() {
	typeName := flag.String("type", "", "Type name (e.g. ExecutionPayloadMonolith)")
	scenarioPath := flag.String("scenario", "", "Path to crash_xxx.json")
	flag.Parse()

	if *typeName == "" {
		fmt.Fprintln(os.Stderr, "[ERROR] Please specify -type=...")
		os.Exit(1)
	}
	if *scenarioPath == "" {
		fmt.Fprintln(os.Stderr, "[ERROR] Please specify -scenario=crash_xxx.json")
		os.Exit(1)
	}

	// Convert "crash_foo.json" => "reproduce_foo.json"
	outLogPath := convertCrashToReproduce(*scenarioPath)

	fmt.Printf("[INFO] Start reproduction: type=%s, scenario=%s\n", *typeName, *scenarioPath)
	fmt.Printf("[INFO] Will produce log => %s\n", outLogPath)

	if err := ReproduceCrash(*typeName, *scenarioPath, outLogPath); err != nil {
		fmt.Fprintf(os.Stderr, "[FAIL] ReproduceCrash error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[DONE] Reproduction complete. Log: %s\n", outLogPath)
}

// convertCrashToReproduce removes "crash_" prefix and adds "reproduce_".
func convertCrashToReproduce(crashFile string) string {
	base := filepath.Base(crashFile)
	// Unconditional TrimPrefix
	base = strings.TrimPrefix(base, "crash_")
	return "reproduce_" + base
}
