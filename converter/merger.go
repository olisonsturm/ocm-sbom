package converter

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
)

// Merger handles the merging of multiple SBOM files.
type Merger struct {
	cliConverter *CLIConverter
}

// NewMerger creates a new Merger.
func NewMerger(cliConverter *CLIConverter) *Merger {
	return &Merger{cliConverter: cliConverter}
}

// Merge takes a directory of individual SBOMs and a list of their paths
// and merges them using the specified tool. It returns the path to the merged SBOM.
func (m *Merger) Merge(individualSBOMsDir string, individualSBOMPaths []string, mergeTool string, componentName string, componentVersion string) (string, error) {
	if len(individualSBOMPaths) == 0 {
		return "", fmt.Errorf("no SBOMs provided to merge")
	}

	// Save merged SBOM in the same directory as individual SBOMs with a descriptive name
	safeComponentName := sanitizeFilename(componentName)
	mergedSBOMPath := filepath.Join(individualSBOMsDir, fmt.Sprintf("merged-component-%s.json", safeComponentName))
	var mergeErr error

	switch strings.ToLower(mergeTool) {
	case "native":
		log.Println("Executing native Go merge...")
		var boms []cyclonedx.BOM

		// Read and decode each input SBOM file
		for _, path := range individualSBOMPaths {
			file, err := os.Open(path)
			if err != nil {
				return "", fmt.Errorf("failed to open sbom file %s: %w", path, err)
			}

			bom := cyclonedx.BOM{}
			decoder := cyclonedx.NewBOMDecoder(file, cyclonedx.BOMFileFormatJSON)
			if err = decoder.Decode(&bom); err != nil && err != io.EOF {
				return "", fmt.Errorf("failed to decode sbom file %s: %w", path, err)
			}
			boms = append(boms, bom)
		}
		// Prepare options and call the native Merge function
		opts := MergeOptions{
			BOMs:    boms,
			Name:    componentName,
			Version: componentVersion,
			Group:   "",
		}

		mergedBom, err := CycloneDXMerge(opts)
		if err != nil {
			return "", fmt.Errorf("native merge failed: %w", err)
		}
		// Encode the resulting BOM to the output file
		outputFile, err := os.Create(mergedSBOMPath)
		if err != nil {
			return "", fmt.Errorf("failed to create merged sbom file: %w", err)
		}
		encoder := json.NewEncoder(outputFile)
		encoder.SetIndent("", "  ") // for pretty printing
		mergeErr = encoder.Encode(mergedBom)
	case "hoppr":
		if m.cliConverter.HopprCLIPath == "" {
			return "", fmt.Errorf("hoppr (hopctl) CLI path not set or found")
		}
		mergeArgs := []string{"merge", "--sbom-dir", individualSBOMsDir, "--output-file", mergedSBOMPath, "--deep-merge"}
		log.Printf("Executing Hoppr merge: %s %s", m.cliConverter.HopprCLIPath, strings.Join(mergeArgs, " "))
		_, mergeErr = m.cliConverter.runCommand(m.cliConverter.HopprCLIPath, mergeArgs...)
	case "cyclonedx-cli":
		if m.cliConverter.CycloneDXCLIPath == "" {
			return "", fmt.Errorf("CycloneDX CLI path not set or found")
		}
		// Build merge command: cyclonedx merge --input-files file1 file2 file3 --output-format json --output-file whatever.json
		mergeArgs := []string{"merge", "--input-files"}
		mergeArgs = append(mergeArgs, individualSBOMPaths...)
		mergeArgs = append(mergeArgs, "--output-format", "json", "--output-file", mergedSBOMPath)
		mergeArgs = append(mergeArgs, "--hierarchical", "--name", componentName, "--version", componentVersion)
		log.Printf("Executing CycloneDX CLI merge: %s %s", m.cliConverter.CycloneDXCLIPath, strings.Join(mergeArgs, " "))
		_, mergeErr = m.cliConverter.runCommand(m.cliConverter.CycloneDXCLIPath, mergeArgs...)
	default:
		return "", fmt.Errorf("unsupported merge tool: %s, choose 'hoppr' or 'cyclonedx-cli'", mergeTool)
	}

	if mergeErr != nil {
		return "", fmt.Errorf("error merging SBOMs with %s: %w", mergeTool, mergeErr)
	}

	log.Printf("SBOMs successfully merged to: %s", mergedSBOMPath)
	return mergedSBOMPath, nil
}
