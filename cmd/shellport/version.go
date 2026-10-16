package main

import (
	"errors"
	"flag"
	"fmt"
	"runtime"
	"runtime/debug"
)

// Release packaging sets these for every platform using Go linker flags.
var version = "dev"
var commit = "unknown"

func runVersion(args []string) error {
	flags := flag.NewFlagSet("version", flag.ContinueOnError)
	flags.Usage = func() { fmt.Fprintln(flags.Output(), "Usage: shellport version (or shellport --version)") }
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("version takes no arguments")
	}
	fmt.Println(versionDescription())
	return nil
}

func versionDescription() string {
	revision, modified := commit, false
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" && revision == "unknown" {
				revision = setting.Value
			}
			if setting.Key == "vcs.modified" && setting.Value == "true" {
				modified = true
			}
		}
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	if modified {
		revision += "+modified"
	}
	return fmt.Sprintf("Shellport %s (commit %s; %s/%s)", version, revision, runtime.GOOS, runtime.GOARCH)
}
