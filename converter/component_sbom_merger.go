/*
 * SPDX-FileCopyrightText: 2025 Olison Sturm
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package converter

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
)

// ComponentSbomMerger handles the merging of multiple SBOM files.
type ComponentSbomMerger struct {
	cliConverter *CLIConverter
}

// NewComponentSbomMerger creates a new ComponentSbomMerger.
func NewComponentSbomMerger(cliConverter *CLIConverter) *ComponentSbomMerger {
	return &ComponentSbomMerger{cliConverter: cliConverter}
}

// ComponentSbomMerge takes a directory of resource SBOMs and a list of their paths
// and merges them using the specified tool. It returns the path to the merged SBOM.
func (m *ComponentSbomMerger) ComponentSbomMerge(componentResourceSbomDir string, resourceSbomPaths []string, mergeTool string, componentName string, componentVersion string) (string, error) {
	if len(resourceSbomPaths) == 0 {
		return "", fmt.Errorf("no SBOMs provided to merge")
	}

	// Save merged SBOM in the same directory as individual SBOMs with a descriptive name
	safeComponentName := sanitizeFilename(componentName)
	mergedSbomPath := filepath.Join(componentResourceSbomDir, fmt.Sprintf("merged-component-%s.json", safeComponentName))
	var mergeErr error

	switch strings.ToLower(mergeTool) {
	case "native":
		log.Println("Executing native Go merge...")
		var boms []cyclonedx.BOM

		// Read and decode each input SBOM file
		for _, path := range resourceSbomPaths {
			file, err := os.Open(path)
			if err != nil {
				return "", fmt.Errorf("failed to open sbom file %s: %w", path, err)
			}

			bom := cyclonedx.BOM{}
			decoder := cyclonedx.NewBOMDecoder(file, cyclonedx.BOMFileFormatJSON)
			if err = decoder.Decode(&bom); err != nil && err != io.EOF {
				file.Close()
				return "", fmt.Errorf("failed to decode sbom file %s: %w", path, err)
			}
			file.Close()

			// Validate BOM has required metadata
			if bom.Metadata == nil || bom.Metadata.Component == nil {
				return "", fmt.Errorf("invalid BOM in file %s: missing metadata component", path)
			}

			boms = append(boms, bom)
		}

		// Prepare options and call the native merge function
		opts := CycloneDxMergeOptions{
			BOMs:      boms,
			Name:      componentName,
			Version:   componentVersion,
			Group:     "",
			MergeMode: MergeModeHierarchical,
		}

		mergedBom, err := CycloneDXMerge(opts)
		if err != nil {
			return "", fmt.Errorf("native merge failed: %w", err)
		}

		// Set proper BOM specification version and format
		mergedBom.BOMFormat = "CycloneDX"
		mergedBom.SpecVersion = cyclonedx.SpecVersion1_6

		// Validate merged BOM
		if mergedBom.Metadata == nil || mergedBom.Metadata.Component == nil {
			return "", fmt.Errorf("merged BOM is invalid: missing metadata component")
		}

		// Create output file and encode using CycloneDX encoder
		outputFile, err := os.Create(mergedSbomPath)
		if err != nil {
			return "", fmt.Errorf("failed to create merged sbom file: %w", err)
		}

		encoder := cyclonedx.NewBOMEncoder(outputFile, cyclonedx.BOMFileFormatJSON)
		encoder.SetPretty(true)
		mergeErr = encoder.Encode(mergedBom)

		// Close and sync file
		if closeErr := outputFile.Close(); closeErr != nil {
			return "", fmt.Errorf("failed to close output file: %w", closeErr)
		}

		if mergeErr != nil {
			return "", fmt.Errorf("failed to encode merged BOM: %w", mergeErr)
		}
	case "hoppr":
		panic("hoppr merge not implemented yet")
		if m.cliConverter.HopprCLIPath == "" {
			return "", fmt.Errorf("hoppr (hopctl) CLI path not set or found")
		}
		mergeArgs := []string{"merge", "--sbom-dir", componentResourceSbomDir, "--output-file", mergedSbomPath, "--deep-merge"}
		log.Printf("Executing Hoppr merge: %s %s", m.cliConverter.HopprCLIPath, strings.Join(mergeArgs, " "))
		_, mergeErr = m.cliConverter.runCommand(m.cliConverter.HopprCLIPath, mergeArgs...)
	case "cyclonedx-cli":
		if m.cliConverter.CycloneDXCLIPath == "" {
			return "", fmt.Errorf("CycloneDX CLI path not set or found")
		}
		// Build merge command: cyclonedx merge --input-files file1 file2 file3 --output-format json --output-file whatever.json
		mergeArgs := []string{"merge", "--input-files"}
		mergeArgs = append(mergeArgs, resourceSbomPaths...)
		mergeArgs = append(mergeArgs, "--output-format", "json", "--output-file", mergedSbomPath)
		mergeArgs = append(mergeArgs, "--hierarchical", "--name", componentName, "--version", componentVersion)
		log.Printf("Executing CycloneDX CLI merge: %s %s", m.cliConverter.CycloneDXCLIPath, strings.Join(mergeArgs, " "))
		_, mergeErr = m.cliConverter.runCommand(m.cliConverter.CycloneDXCLIPath, mergeArgs...)
	default:
		return "", fmt.Errorf("unsupported merge tool: %s, choose 'hoppr' or 'cyclonedx-cli'", mergeTool)
	}

	if mergeErr != nil {
		return "", fmt.Errorf("error merging SBOMs with %s: %w", mergeTool, mergeErr)
	}

	log.Printf("SBOMs successfully merged to: %s", mergedSbomPath)
	return mergedSbomPath, nil
}
