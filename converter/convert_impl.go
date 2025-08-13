package converter

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"ocm.software/open-component-model/bindings/go/oci"
)

// ConvertOCMToSBOM orchestrates reading components from a CTF, generating SBOMs for their
// resources via Syft, merging a per-component via CycloneDX CLI (default), and optionally
// converting the final output format.
func (c *CLIConverter) ConvertOCMToSBOM(cftPath string, componentName string, targetFormat SBOMFormat, mergeTool string) ([]byte, error) {
	repo, err := createRepository(cftPath)
	if err != nil {
		return nil, fmt.Errorf("error creating repository: %w", err)
	}

	// Step 1: process all components recursively starting at the given component (use version 1.0.0 for now)
	allComponentSBOMPaths, err := c.processAllComponents(repo, componentName, "1.0.0", targetFormat)
	if err != nil {
		return nil, fmt.Errorf("error processing components: %w", err)
	}

	if len(allComponentSBOMPaths) == 0 {
		log.Println("No SBOMs were generated for any components. Result will be empty.")
		return []byte{}, nil
	}

	// Step 2: merge per-component SBOMs into final SBOM if there are multiple
	finalMergedSBOMPath := ""
	if len(allComponentSBOMPaths) > 1 {
		log.Printf("Merging %d component SBOMs into final SBOM", len(allComponentSBOMPaths))
		merger := NewMerger(c)
		// For a final merge of multiple components, use a generic name
		finalMergedSBOMPath, err = merger.ComponentSbomMerge(c.TempDir, allComponentSBOMPaths, mergeTool, "final-merged-components", "1.0.0")
		if err != nil {
			return nil, fmt.Errorf("error during final merge: %w", err)
		}
	} else {
		finalMergedSBOMPath = allComponentSBOMPaths[0]
	}
	log.Printf("Final merged SBOM at: %s", finalMergedSBOMPath)

	// Step 3: optionally convert to the desired output format
	return c.convertFinalSBOM(finalMergedSBOMPath, targetFormat)
}

// processAllComponents traverses the component hierarchy and generates a merged SBOM for each component.
func (c *CLIConverter) processAllComponents(repo oci.ComponentVersionRepository, componentName, componentVersion string, outputFormat SBOMFormat) ([]string, error) {
	var allComponentSBOMPaths []string
	processed := make(map[string]bool)
	queue := []struct{ ComponentName, Version string }{{ComponentName: componentName, Version: componentVersion}}

	processor := NewComponentProcessor(c)

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]
		id := fmt.Sprintf("%s:%s", curr.ComponentName, curr.Version)
		if processed[id] {
			log.Printf("Component %s already processed, skipping", id)
			continue
		}

		log.Printf("Processing component: %s", id)
		runtimeDesc, err := repo.GetComponentVersion(context.Background(), curr.ComponentName, curr.Version)
		if err != nil {
			log.Printf("Warning: could not get component version for %s: %v", id, err)
			processed[id] = true
			continue
		}

		// Process the current component using the runtime descriptor
		mergedSBOMPath, err := processor.ProcessComponent(runtimeDesc, outputFormat)
		if err != nil {
			log.Printf("Warning: error processing component %s: %v", id, err)
		}
		if mergedSBOMPath != "" {
			allComponentSBOMPaths = append(allComponentSBOMPaths, mergedSBOMPath)
			log.Printf("SBOM for component %s at %s", id, mergedSBOMPath)
		}

		processed[id] = true

		// Enqueue referenced components using fully-qualified component name from runtime descriptor
		for _, ref := range runtimeDesc.Component.References {
			refID := fmt.Sprintf("%s:%s", ref.Component, ref.Version)
			if !processed[refID] {
				log.Printf("Queue referenced component %s", refID)
				queue = append(queue, struct{ ComponentName, Version string }{ComponentName: ref.Component, Version: ref.Version})
			}
		}
	}

	return allComponentSBOMPaths, nil
}

// convertFinalSBOM converts the final SBOM into the target format when required.
func (c *CLIConverter) convertFinalSBOM(sourceSBOMPath string, targetFormat SBOMFormat) ([]byte, error) {
	// If CycloneDX JSON is desired, we can just read the merged file directly.
	if strings.ToLower(string(targetFormat)) == "cyclonedx-json" {
		log.Println("No format conversion needed; reading merged SBOM directly")
		return os.ReadFile(sourceSBOMPath)
	}

	if c.CycloneDXCLIPath == "" {
		return nil, fmt.Errorf("CycloneDX CLI path not set or found, but required for conversion")
	}

	convertedSBOMPath := filepath.Join(c.TempDir, "final_converted_sbom.json")
	outputFormatArg := string(targetFormat)
	outputVersion := "1.4" // default for CycloneDX

	if strings.HasSuffix(outputFormatArg, "-yaml") {
		convertedSBOMPath = filepath.Join(c.TempDir, "final_converted_sbom.yaml")
		outputFormatArg = "yaml"
	} else if strings.HasSuffix(outputFormatArg, "-json") {
		outputFormatArg = "json"
	}

	if strings.HasPrefix(string(targetFormat), "spdx") {
		outputVersion = "2.3" // default for SPDX
	}

	args := []string{
		"convert",
		"--input-file", sourceSBOMPath,
		"--output-file", convertedSBOMPath,
		"--output-format", outputFormatArg,
		"--output-version", outputVersion,
	}
	log.Printf("Running CycloneDX CLI convert: %s %s", c.CycloneDXCLIPath, strings.Join(args, " "))
	if _, err := c.runCommand(c.CycloneDXCLIPath, args...); err != nil {
		return nil, fmt.Errorf("failed to convert SBOM to %s: %w", targetFormat, err)
	}
	return os.ReadFile(convertedSBOMPath)
}
