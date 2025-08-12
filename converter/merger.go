package converter

import (
	"fmt"
	"log"
	"path/filepath"
	"strings"
)

// Merger handles the merging of multiple SBOM files.
type Merger struct {
	cliConverter *CLIConverter
}

// NewMerger creates a new Merger.
func NewMerger(cliConverter *CLIConverter) *Merger {
	return &Merger{cliConverter: cliConverter}
}

// Merge takes a directory of individual SBOMs and a list of their paths,
// and merges them using the specified tool. It returns the path to the merged SBOM.
func (m *Merger) Merge(individualSBOMsDir string, individualSBOMPaths []string, mergeTool string, componentName string) (string, error) {
	if len(individualSBOMPaths) == 0 {
		return "", fmt.Errorf("no SBOMs provided to merge")
	}

	// Save merged SBOM in the same directory as individual SBOMs with a descriptive name
	safeComponentName := sanitizeFilename(componentName)
	mergedSBOMPath := filepath.Join(individualSBOMsDir, fmt.Sprintf("merged-component-%s.json", safeComponentName))
	var mergeErr error

	switch strings.ToLower(mergeTool) {
	case "hoppr":
		if m.cliConverter.HopprCLIPath == "" {
			return "", fmt.Errorf("Hoppr (hopctl) CLI path not set or found")
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
