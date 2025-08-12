package converter

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

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
func (p *ComponentProcessor) ProcessComponent(descriptor *runtime.Descriptor) (string, error) {
	log.Printf("Processing component: %s:%s", descriptor.Component.Name, descriptor.Component.Version)

	// temporary directory for individual SBOMs for this component
	componentNameSafe := sanitizeFilename(descriptor.Component.Name)
	individualSBOMsDir, err := os.MkdirTemp(p.cliConverter.TempDir, "ocm-"+componentNameSafe+"-sboms-*")
	if err != nil {
		return "", fmt.Errorf("failed creating temp directory for individual SBOMs: %w", err)
	}

	individualSBOMPaths, err := p.generateIndividualSBOMs(descriptor, individualSBOMsDir)
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
func (p *ComponentProcessor) generateIndividualSBOMs(descriptor *runtime.Descriptor, individualSBOMsDir string) ([]string, error) {
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

			sbomData, genErr := p.cliConverter.generateSBOMWithSyft(imageRef, "cyclonedx-json")
			if genErr != nil {
				log.Printf("Error generating SBOM for image %s: %v", imageRef, genErr)
				continue
			}
			safeImageRef := sanitizeFilename(imageRef)
			safeResName := sanitizeFilename(res.Name)
			tempFilename := fmt.Sprintf("%s-%s-sbom.json", safeImageRef, safeResName)
			tempSBOMPath := filepath.Join(individualSBOMsDir, tempFilename)
			if writeErr := os.WriteFile(tempSBOMPath, []byte(sbomData), 0644); writeErr != nil {
				log.Printf("Warning: could not save individual SBOM to %s: %v", tempSBOMPath, writeErr)
				continue
			}
			individualSBOMPaths = append(individualSBOMPaths, tempSBOMPath)
			log.Printf("SBOM generated and saved for resource %s at %s", imageRef, tempSBOMPath)
		}
	}
	return individualSBOMPaths, nil
}
