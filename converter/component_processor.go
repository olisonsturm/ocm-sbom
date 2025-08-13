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
	componentResourceSbomDir, err := os.MkdirTemp(p.cliConverter.TempDir, "ocm-"+componentNameSafe+"-sboms-*")
	if err != nil {
		return "", fmt.Errorf("failed creating temp directory for individual SBOMs: %w", err)
	}

	componentResourceSbomFullPaths, err := p.generateComponentResourceSboms(descriptor, componentResourceSbomDir, outputFormat)
	if err != nil {
		return "", err
	}

	if len(componentResourceSbomFullPaths) == 0 {
		log.Printf("No OCI Image resources found or no SBOMs could be generated for component %s/%s", descriptor.Component.Name, descriptor.Component.Version)
		return "", nil // nothing to merge
	}

	log.Printf("Merging the following %d SBOMs", len(componentResourceSbomFullPaths))
	for i, path := range componentResourceSbomFullPaths {
		log.Printf("  %d: %s", i+1, path)
	}

	// ComponentSbomMerge the SBOMs using the ComponentSbomMerger, saving in the same componentResourceSbomDir
	merger := NewMerger(p.cliConverter)
	mergedSBOMPath, err := merger.ComponentSbomMerge(componentResourceSbomDir, componentResourceSbomFullPaths, "cyclonedx-cli", descriptor.Component.Name, descriptor.Component.Version)
	if err != nil {
		return "", fmt.Errorf("failed to merge SBOMs for component %s/%s: %w", descriptor.Component.Name, descriptor.Component.Version, err)
	}

	// TODO: use cyclonedx_processor.go to generate the final SBOM with appending component metadata

	return mergedSBOMPath, nil
}

// generateComponentResourceSboms generates SBOMs for each relevant resource in a component.
func (p *ComponentProcessor) generateComponentResourceSboms(descriptor *runtime.Descriptor, componentResourceSbomDir string, outputFormat SBOMFormat) ([]string, error) {
	var componentResourceSbomFullPaths []string
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
			tempComponentResourceSbomFullPath := filepath.Join(componentResourceSbomDir, tempFilename)

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
			s.SetOutputFile(tempComponentResourceSbomFullPath)

			// Scan and write to the custom file path
			if err := s.ScanToWriter(context.Background(), imageRef); err != nil {
				return nil, fmt.Errorf("failed to generate SBOM for resource %s (%s): %w", res.Name, imageRef, err)
			}

			log.Printf("SBOM generated and saved for resource %s at %s", imageRef, tempComponentResourceSbomFullPath)

			componentResourceSbomFullPaths = append(componentResourceSbomFullPaths, tempComponentResourceSbomFullPath)
		}
	}
	return componentResourceSbomFullPaths, nil
}
