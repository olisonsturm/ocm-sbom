package converter

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/anchore/clio"
	"ocm.software/open-component-model/bindings/go/descriptor/runtime"
)

// ComponentProcessor handles the processing of a single OCM component.
type ComponentProcessor struct {
	cliConverter *CLIConverter
}

// NewComponentProcessor creates a new ComponentProcessor.
func NewComponentProcessor(cliConverter *CLIConverter) *ComponentProcessor {
	return &ComponentProcessor{cliConverter: cliConverter}
}

// ProcessComponent generates and merges SBOMs for a given component version.
// It returns the path to the merged SBOM (CycloneDX JSON).
func (p *ComponentProcessor) ProcessComponent(descriptor *runtime.Descriptor, outputFormat SBOMFormat) (string, error) {
	log.Printf("Processing component: %s:%s", descriptor.Component.Name, descriptor.Component.Version)

	// temporary directory for individual SBOMs for this component
	componentNameSafe := sanitizeFilename(descriptor.Component.Name)
	individualSBOMsDir, err := os.MkdirTemp(p.cliConverter.TempDir, "ocm-"+componentNameSafe+"-sboms-*")
	if err != nil {
		return "", fmt.Errorf("failed creating temp directory for individual SBOMs: %w", err)
	}

	individualSBOMPaths, err := p.generateIndividualSBOMs(descriptor, individualSBOMsDir, outputFormat)
	if err != nil {
		return "", err
	}

	if len(individualSBOMPaths) == 0 {
		log.Printf("No OCI Image resources found or no SBOMs could be generated for component %s/%s", descriptor.Component.Name, descriptor.Component.Version)
		return "", nil // nothing to merge
	}

	// Generate the root OCM component SBOM that references all resource SBOMs
	// rootSBOMGenerator: = NewRootSBOMGenerator(p.cliConverter)
	// rootSBOMPath, err := rootSBOMGenerator.GenerateRootSBOM(descriptor, individualSBOMPaths, individualSBOMsDir)
	// if err != nil {
	// 	return "", fmt.Errorf("failed to generate root SBOM for component %s/%s: %w", descriptor.Component.Name, descriptor.Component.Version, err)
	// }

	// Prepare all SBOM paths for merging (root SBOM first, then resource SBOMs)
	// IMPORTANT: Root OCM meta SBOM must be first in the list!
	// allSBOMPaths: = []string{rootSBOMPath}
	// allSBOMPaths = append(allSBOMPaths, individualSBOMPaths...)
	allSBOMPaths := individualSBOMPaths

	log.Printf("Merging the following %d SBOMs", len(individualSBOMPaths))
	for i, path := range allSBOMPaths {
		log.Printf("  %d: %s", i+1, path)
	}

	// Merge the SBOMs using the Merger, saving in the same individualSBOMsDir
	merger := NewMerger(p.cliConverter)
	mergedSBOMPath, err := merger.Merge(individualSBOMsDir, allSBOMPaths, "cyclonedx-cli", descriptor.Component.Name, descriptor.Component.Version)
	if err != nil {
		return "", fmt.Errorf("failed to merge SBOMs for component %s/%s: %w", descriptor.Component.Name, descriptor.Component.Version, err)
	}

	return mergedSBOMPath, nil
}

// generateIndividualSBOMs generates SBOMs for each relevant resource in a component.
func (p *ComponentProcessor) generateIndividualSBOMs(descriptor *runtime.Descriptor, individualSBOMsDir string, outputFormat SBOMFormat) ([]string, error) {
	var individualSBOMPaths []string
	for _, res := range descriptor.Component.Resources {
		var accessMap map[string]interface{}
		if res.Access != nil {
			rawBytes, err := json.Marshal(res.Access)
			if err != nil {
				log.Printf("Warning: could not serialize access data for resource %s: %v", res.Name, err)
				continue
			}
			if len(rawBytes) > 0 {
				if err := json.Unmarshal(rawBytes, &accessMap); err != nil {
					log.Printf("Warning: could not parse access data for resource %s: %v", res.Name, err)
					continue
				}
			}
		}
		if accessMap == nil {
			accessMap = make(map[string]interface{})
		}
		if imageRef, ok := accessMap["imageReference"].(string); ok && res.Type == "ociImage" {
			log.Printf("Generating SBOM with Syft for OCI Image resource: %s", imageRef)

			// Set desired output format (single)
			format := []string{string(outputFormat)}
			// Create a temporary file for the SBOM
			safeImageRef := sanitizeFilename(imageRef)
			safeResName := sanitizeFilename(res.Name)
			tempFilename := fmt.Sprintf("%s-%s-sbom.json", safeImageRef, safeResName)
			tempSBOMPath := filepath.Join(individualSBOMsDir, tempFilename)

			// Create syft scanner with custom config
			config := DefaultScanConfig()
			id := clio.Identification{
				Name:    "ocm-syft-scanner",
				Version: "1.0.0-dev",
			}
			// set desired output format (single)
			config.OutputFormats = format
			s := NewScanner(config, id)

			// Save the SBOM to a temporary file
			s.SetOutputFile(tempSBOMPath)

			// Scan and write to the custom file path
			if err := s.ScanToWriter(context.Background(), imageRef); err != nil {
				return nil, fmt.Errorf("failed to generate SBOM for resource %s (%s): %w", res.Name, imageRef, err)
			}

			log.Printf("SBOM generated and saved for resource %s at %s", imageRef, tempSBOMPath)

			individualSBOMPaths = append(individualSBOMPaths, tempSBOMPath)
		}
	}
	return individualSBOMPaths, nil
}
