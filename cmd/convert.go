package cmd

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/olisonsturm/ocm-sbom/converter"
	"github.com/spf13/cobra"
)

// Global variables for flags
var (
	formatStr       string
	outputFilePath  string
	mergeToolChoice string
	ctfPath         string
	componentName   string
)

// convertCmd represents the convert command
var convertCmd = &cobra.Command{
	Use:   "convert [CTF_PATH]//[COMPONENT_NAME]",
	Short: "Converts OCM component descriptor to SBOM (CycloneDX/SPDX)",
	Long: `The convert command takes an OCM component descriptor from a CTF folder, 
processes it to generate a merged SBOM, and can convert it to desired formats.

Example:
  ocm convert ./ctf//github.com/olison/parent --format cyclonedx-json --output my-app.cdx.json
  ocm convert ./ctf//github.com/olison/parent -f spdx-json -o my-app.spdx.json`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("exactly one argument is required in the format [CTF_PATH]//[COMPONENT_NAME]")
		}

		parts := strings.Split(args[0], "//")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return fmt.Errorf("invalid argument format. Expected [CTF_PATH]//[COMPONENT_NAME]")
		}

		ctfPath = parts[0]
		componentName = parts[1]
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		// Validate required flags and arguments
		if ctfPath == "" || componentName == "" {
			return fmt.Errorf("CTF path and component name are required")
		}
		if formatStr == "" {
			return fmt.Errorf("--format or -f flag is required (e.g., --format cyclonedx-json)")
		}
		if outputFilePath == "" {
			return fmt.Errorf("--output or -o flag is required to specify the output file path")
		}

		// List of supported formats
		targetFormats := strings.Split(formatStr, ",")
		var parsedFormats []converter.SBOMFormat
		for _, f := range targetFormats {
			switch strings.ToLower(strings.TrimSpace(f)) {
			case "cyclonedx-json":
				parsedFormats = append(parsedFormats, converter.FormatCycloneDXJSON)
			case "spdx-json":
				parsedFormats = append(parsedFormats, converter.FormatSPDXJSON)
			case "cyclonedx-yaml":
				parsedFormats = append(parsedFormats, converter.FormatCycloneDXYAML)
			case "spdx-yaml":
				parsedFormats = append(parsedFormats, converter.FormatSPDXYAML)
			default:
				return fmt.Errorf("unsupported SBOM format '%s'. Supported: cyclonedx-json, spdx-json, cyclonedx-yaml, spdx-yaml", f)
			}
		}

		// Converter
		conv, err := converter.NewCLIConverter("", "", "", "", "")
		if err != nil {
			return fmt.Errorf("failed to initialize SBOM converter: %w", err)
		}
		defer conv.CleanupTempDir() // Aufräumen der temporären Dateien

		log.Printf("Processing OCM component: %s from CTF: %s\n", componentName, ctfPath)
		log.Printf("Target formats: %v\n", parsedFormats)
		log.Printf("Output path: %s\n", outputFilePath)
		log.Printf("Merge tool: %s", mergeToolChoice)

		// convert
		for _, format := range parsedFormats {
			currentOutputFilePath := outputFilePath
			if len(parsedFormats) > 1 {
				ext := ""
				switch format {
				case converter.FormatCycloneDXJSON:
					ext = ".cdx.json"
				case converter.FormatSPDXJSON:
					ext = ".spdx.json"
				case converter.FormatCycloneDXYAML:
					ext = ".cdx.yaml"
				case converter.FormatSPDXYAML:
					ext = ".spdx.yaml"
				}
				currentOutputFilePath = fmt.Sprintf("%s%s", strings.TrimSuffix(outputFilePath, filepath.Ext(outputFilePath)), ext)
			}

			log.Printf("Generating SBOM for format: %s to %s\n", format, currentOutputFilePath)

			sbomContent, err := conv.ConvertOCMToSBOM(
				ctfPath,
				componentName,
				parsedFormats[0],
				mergeToolChoice,
			)
			if err != nil {
				return fmt.Errorf("error processing SBOM for format %s: %w", format, err)
			}

			// Write result in a file
			err = os.WriteFile(currentOutputFilePath, sbomContent, 0644)
			if err != nil {
				return fmt.Errorf("failed to write SBOM to %s: %w", currentOutputFilePath, err)
			}
			log.Printf("Successfully generated %s SBOM to %s\n", format, currentOutputFilePath)
		}

		log.Println("OCM to SBOM conversion process completed.")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(convertCmd)

	// Defined Flags
	convertCmd.Flags().StringVarP(&formatStr, "format", "f", "cyclonedx-json", "Target SBOM formats (e.g., 'cyclonedx-json','spdx-json','cyclonedx-yaml','spdx-yaml')")
	convertCmd.Flags().StringVarP(&outputFilePath, "output", "o", "output-sbom", "Output file path for the merged/converted SBOM (e.g., 'sbom.cdx.json').")

	// Tools to choose from
	convertCmd.Flags().StringVarP(&mergeToolChoice, "merge-tool", "mt", "native", "Tool to use for merging SBOMs ('native','cyclonedx-cli','hoppr')")

	// Mandatory Flags
	// convertCmd.MarkFlagRequired("format")
	// convertCmd.MarkFlagRequired("output")
}
