/*
 * SPDX-FileCopyrightText: 2025 Olison Sturm
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Package cmd provides the command-line interface for converting OCM components to SBOMs.
package cmd

import (
	"fmt"
	"os"
	"runtime/debug"

	"github.com/spf13/cobra"
)

var version = "dev"

// rootCmd represents the base command when called without any subcommands
// Test case: go run main.go convert ./example-ocm/ctf//github.com/olison/parent -f cyclonedx-json -o sbom.cdx.json --merge-tool native
var rootCmd = &cobra.Command{
	Use:     "ocm-sbom",
	Short:   "OCM SBOM CLI",
	Long:    `OCM SBOM CLI is a command-line tool for converting OCM components to various SBOM formats like CycloneDX and SPDX.`,
	Version: readModuleVersion(),
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func readModuleVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && len(s.Value) >= 7 {
				return fmt.Sprintf("devel+%s", s.Value[:7])
			}
		}
	}
	return version
}
