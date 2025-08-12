package converter

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"ocm.software/open-component-model/bindings/go/descriptor/runtime"
)

// CycloneDXBOM represents a CycloneDX SBOM structure
type CycloneDXBOM struct {
	Schema       string                `json:"$schema"`
	BomFormat    string                `json:"bomFormat"`
	SpecVersion  string                `json:"specVersion"`
	SerialNumber string                `json:"serialNumber"`
	Version      int                   `json:"version"`
	Metadata     CycloneDXMetadata     `json:"metadata"`
	Components   []CycloneDXComponent  `json:"components,omitempty"`
	Dependencies []CycloneDXDependency `json:"dependencies,omitempty"`
}

type CycloneDXMetadata struct {
	Timestamp string             `json:"timestamp"`
	Component CycloneDXComponent `json:"component"`
}

type CycloneDXComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	BomRef  string `json:"bom-ref"`
}

type CycloneDXDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

// RootSBOMGenerator generates the root OCM component SBOM
type RootSBOMGenerator struct {
	cliConverter *CLIConverter
}

// NewRootSBOMGenerator creates a new RootSBOMGenerator
func NewRootSBOMGenerator(cliConverter *CLIConverter) *RootSBOMGenerator {
	return &RootSBOMGenerator{cliConverter: cliConverter}
}

// GenerateRootSBOM creates a root SBOM for the OCM component that references all resource SBOMs
func (g *RootSBOMGenerator) GenerateRootSBOM(descriptor *runtime.Descriptor, resourceSBOMPaths []string, individualSBOMsDir string) (string, error) {
	log.Printf("Generating root SBOM for component: %s:%s", descriptor.Component.Name, descriptor.Component.Version)

	// Extract bom-ref values from all resource SBOMs
	resourceBomRefs, resourceComponents, err := g.extractResourceBomRefs(resourceSBOMPaths)
	if err != nil {
		return "", fmt.Errorf("failed to extract bom-ref values from resource SBOMs: %w", err)
	}

	// Generate the root SBOM
	rootSBOM := g.createRootSBOM(descriptor, resourceComponents, resourceBomRefs)

	// Save the root SBOM to the individualSBOMsDir instead of general temp directory
	rootSBOMPath := filepath.Join(individualSBOMsDir, fmt.Sprintf("root_ocm_meta_%s.json",
		sanitizeFilename(descriptor.Component.Name)))

	rootSBOMData, err := json.MarshalIndent(rootSBOM, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal root SBOM: %w", err)
	}

	if err := os.WriteFile(rootSBOMPath, rootSBOMData, 0644); err != nil {
		return "", fmt.Errorf("failed to write root SBOM to file: %w", err)
	}

	log.Printf("Root SBOM generated at: %s", rootSBOMPath)
	return rootSBOMPath, nil
}

// extractResourceBomRefs reads each resource SBOM and extracts the bom-ref from metadata.component
func (g *RootSBOMGenerator) extractResourceBomRefs(sbomPaths []string) ([]string, []CycloneDXComponent, error) {
	var bomRefs []string
	var components []CycloneDXComponent

	for _, sbomPath := range sbomPaths {
		log.Printf("Extracting bom-ref from: %s", sbomPath)

		sbomData, err := os.ReadFile(sbomPath)
		if err != nil {
			log.Printf("Warning: could not read SBOM file %s: %v", sbomPath, err)
			continue
		}

		var sbom CycloneDXBOM
		if err := json.Unmarshal(sbomData, &sbom); err != nil {
			log.Printf("Warning: could not parse SBOM file %s: %v", sbomPath, err)
			continue
		}

		if sbom.Metadata.Component.BomRef != "" {
			bomRefs = append(bomRefs, sbom.Metadata.Component.BomRef)
			components = append(components, sbom.Metadata.Component)
			log.Printf("Extracted bom-ref: %s from %s", sbom.Metadata.Component.BomRef, sbomPath)
		} else {
			log.Printf("Warning: no bom-ref found in metadata.component for %s", sbomPath)
		}
	}

	return bomRefs, components, nil
}

// createRootSBOM creates the root SBOM structure
func (g *RootSBOMGenerator) createRootSBOM(descriptor *runtime.Descriptor, resourceComponents []CycloneDXComponent, resourceBomRefs []string) *CycloneDXBOM {
	// Generate UUID for serial number
	serialUUID, _ := uuid.NewRandom()

	// Create the main component bom-ref
	mainComponentBomRef := fmt.Sprintf("ocm:component/%s@%s", descriptor.Component.Name, descriptor.Component.Version)

	rootSBOM := &CycloneDXBOM{
		Schema:       "http://cyclonedx.org/schema/bom-1.6.schema.json",
		BomFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		SerialNumber: fmt.Sprintf("urn:uuid:%s", serialUUID.String()),
		Version:      1,
		Metadata: CycloneDXMetadata{
			Timestamp: time.Now().Format("2006-01-02T15:04:05-07:00"),
			Component: CycloneDXComponent{
				Type:    "application",
				Name:    descriptor.Component.Name,
				Version: descriptor.Component.Version,
				BomRef:  mainComponentBomRef,
			},
		},
		Components: resourceComponents,
	}

	// Add dependencies if there are resource components
	if len(resourceBomRefs) > 0 {
		dependency := CycloneDXDependency{
			Ref:       mainComponentBomRef,
			DependsOn: resourceBomRefs,
		}
		rootSBOM.Dependencies = []CycloneDXDependency{dependency}
	}

	return rootSBOM
}
