package converter

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/CycloneDX/cyclonedx-go"
)

// CycloneDxMergeOptions holds the parameters for the ComponentSbomMerge function.
type CycloneDxMergeOptions struct {
	BOMs    []cyclonedx.BOM
	Group   string
	Name    string
	Version string
}

// ErrMissingMetadataComponent indicates that a BOM is missing its required metadata component
var ErrMissingMetadataComponent = errors.New("required metadata (top level) component is missing from BOM")

// CycloneDXMerge orchestrates the hierarchical merging of BOMs based on the provided options.
func CycloneDXMerge(options CycloneDxMergeOptions) (*cyclonedx.BOM, error) {
	// Hierarchical merge requires a name and version for the top-level component.
	if options.Name == "" || options.Version == "" {
		return nil, errors.New("name and version must be specified for a hierarchical merge")
	}

	// Create the top-level component (bomSubject) for the merged BOM.
	bomSubject := &cyclonedx.Component{
		Type:    cyclonedx.ComponentTypeApplication,
		Group:   options.Group,
		Name:    options.Name,
		Version: options.Version,
	}

	// Perform the hierarchical merge.
	outputBom, err := HierarchicalMerge(options.BOMs, bomSubject)
	if err != nil {
		return nil, fmt.Errorf("hierarchical merge failed: %w", err)
	}

	// Finalize BOM metadata.
	outputBom.Version = 1
	if outputBom.Metadata == nil {
		outputBom.Metadata = &cyclonedx.Metadata{}
	}
	// The SerialNumber and Timestamp are typically set upon the final generation.

	return outputBom, nil
}

// HierarchicalMerge performs a hierarchical merge for multiple BOMs.
// To retain system component hierarchy, top level BOM metadata
// component must be included in each BOM.
func HierarchicalMerge(boms []cyclonedx.BOM, bomSubject *cyclonedx.Component) (*cyclonedx.BOM, error) {
	result := &cyclonedx.BOM{}

	// Initialize metadata if bomSubject is provided
	if bomSubject != nil {
		if bomSubject.BOMRef == "" {
			bomSubject.BOMRef = componentBOMRefNamespace(bomSubject)
		}
		result.Metadata = &cyclonedx.Metadata{
			Component: bomSubject,
			Tools:     &cyclonedx.ToolsChoice{},
		}
	}

	// Initialize all lists as non-nil
	result.Components = &[]cyclonedx.Component{}
	result.Services = &[]cyclonedx.Service{}
	result.ExternalReferences = &[]cyclonedx.ExternalReference{}
	result.Dependencies = &[]cyclonedx.Dependency{}
	result.Compositions = &[]cyclonedx.Composition{}
	result.Vulnerabilities = &[]cyclonedx.Vulnerability{}

	result.Declarations = &cyclonedx.Declarations{
		Assessors:    &[]cyclonedx.Assessor{},
		Attestations: &[]cyclonedx.Attestation{},
		Claims:       &[]cyclonedx.Claim{},
		Evidence:     &[]cyclonedx.DeclarationEvidence{},
		Targets: &cyclonedx.Targets{
			Components:    &[]cyclonedx.Component{},
			Organizations: &[]cyclonedx.OrganizationalEntity{},
			Services:      &[]cyclonedx.Service{},
		},
	}

	result.Definitions = &cyclonedx.Definitions{
		Standards: &[]cyclonedx.StandardDefinition{},
	}

	var bomSubjectDependencies []cyclonedx.Dependency

	for _, bom := range boms {
		// Validate BOM has required metadata component
		if bom.Metadata == nil || bom.Metadata.Component == nil {
			serialNumber := "unknown"
			if bom.SerialNumber != "" {
				serialNumber = bom.SerialNumber
			}
			return nil, fmt.Errorf("%w (BOM: %s)", ErrMissingMetadataComponent, serialNumber)
		}

		// ComponentSbomMerge metadata tools - only if tools exist and result metadata is not nil
		if result.Metadata != nil && bom.Metadata.Tools != nil {
			// Handle Tools list (legacy)
			if bom.Metadata.Tools.Components != nil && len(*bom.Metadata.Tools.Components) > 0 {
				if result.Metadata.Tools.Components == nil {
					result.Metadata.Tools.Components = &[]cyclonedx.Component{}
				}
				*result.Metadata.Tools.Components = append(*result.Metadata.Tools.Components, *bom.Metadata.Tools.Components...)
			}

			// Handle Tools Components
			if bom.Metadata.Tools.Components != nil && len(*bom.Metadata.Tools.Components) > 0 {
				if result.Metadata.Tools.Components == nil {
					result.Metadata.Tools.Components = &[]cyclonedx.Component{}
				}
				for _, component := range *bom.Metadata.Tools.Components {
					// Apply namespace to component
					namespaceComponentBOMRefs(componentBOMRefNamespace(bom.Metadata.Component), &component)
					if !containsComponent(*result.Metadata.Tools.Components, component) {
						*result.Metadata.Tools.Components = append(*result.Metadata.Tools.Components, component)
					}
				}
			}

			// Handle Tools Services
			if bom.Metadata.Tools.Services != nil && len(*bom.Metadata.Tools.Services) > 0 {
				if result.Metadata.Tools.Services == nil {
					result.Metadata.Tools.Services = &[]cyclonedx.Service{}
				}
				for _, service := range *bom.Metadata.Tools.Services {
					service.BOMRef = namespacedBOMRef(bom.Metadata.Component, service.BOMRef)
					if !containsService(*result.Metadata.Tools.Services, service) {
						*result.Metadata.Tools.Services = append(*result.Metadata.Tools.Services, service)
					}
				}
			}
		}

		// Process main component
		thisComponent := bom.Metadata.Component
		if thisComponent.Components == nil {
			thisComponent.Components = &[]cyclonedx.Component{}
		}
		if bom.Components != nil {
			*thisComponent.Components = append(*thisComponent.Components, *bom.Components...)
		}

		// Add namespace to existing BOM refs (this modifies the original component!)
		namespaceComponentBOMRefs(componentBOMRefNamespace(thisComponent), thisComponent)

		// Ensure BOM ref is set and add top level dependency reference
		if thisComponent.BOMRef == "" {
			thisComponent.BOMRef = componentBOMRefNamespace(thisComponent)
		}
		bomSubjectDependencies = append(bomSubjectDependencies, cyclonedx.Dependency{Ref: thisComponent.BOMRef})

		*result.Components = append(*result.Components, *thisComponent)

		// ComponentSbomMerge services
		if bom.Services != nil {
			for _, service := range *bom.Services {
				service.BOMRef = namespacedBOMRef(bom.Metadata.Component, service.BOMRef)
				*result.Services = append(*result.Services, service)
			}
		}

		// ComponentSbomMerge external references
		if bom.ExternalReferences != nil {
			*result.ExternalReferences = append(*result.ExternalReferences, *bom.ExternalReferences...)
		}

		// ComponentSbomMerge dependencies
		if bom.Dependencies != nil {
			namespaceDependencyBOMRefs(componentBOMRefNamespace(thisComponent), *bom.Dependencies)
			*result.Dependencies = append(*result.Dependencies, *bom.Dependencies...)
		}

		// ComponentSbomMerge compositions
		if bom.Compositions != nil {
			namespaceCompositions(componentBOMRefNamespace(bom.Metadata.Component), *bom.Compositions)
			*result.Compositions = append(*result.Compositions, *bom.Compositions...)
		}

		// ComponentSbomMerge vulnerabilities - NOTE: uses result.Metadata.Component namespace, not thisComponent!
		if bom.Vulnerabilities != nil {
			var namespaceForVulns string
			if result.Metadata != nil && result.Metadata.Component != nil {
				namespaceForVulns = componentBOMRefNamespace(result.Metadata.Component)
			} else {
				namespaceForVulns = componentBOMRefNamespace(bom.Metadata.Component)
			}
			namespaceVulnerabilitiesRefs(namespaceForVulns, *bom.Vulnerabilities)
			*result.Vulnerabilities = append(*result.Vulnerabilities, *bom.Vulnerabilities...)
		}

		// Define local helper functions
		namespaceBOMRefs := func(refs interface{}) {
			namespaceBOMRefsWithComponent(thisComponent, refs)
		}
		namespaceReference := func(refs interface{}, propertyName string) {
			namespaceProperty(componentBOMRefNamespace(thisComponent), refs, propertyName)
		}

		// ComponentSbomMerge definitions
		if bom.Definitions != nil && bom.Definitions.Standards != nil {
			// Namespace all references
			namespaceBOMRefs(*bom.Definitions.Standards)
			for i := range *bom.Definitions.Standards {
				standard := &(*bom.Definitions.Standards)[i]
				if standard.Requirements != nil {
					namespaceBOMRefs(*standard.Requirements)
				}
				if standard.Levels != nil {
					namespaceBOMRefs(*standard.Levels)
					namespaceReference(*standard.Levels, "Requirements")
				}
			}
			*result.Definitions.Standards = append(*result.Definitions.Standards, *bom.Definitions.Standards...)
		}

		// ComponentSbomMerge declarations
		if bom.Declarations != nil {
			// Assessors
			if bom.Declarations.Assessors != nil {
				namespaceBOMRefs(*bom.Declarations.Assessors)
				*result.Declarations.Assessors = append(*result.Declarations.Assessors, *bom.Declarations.Assessors...)
			}

			// Attestations
			if bom.Declarations.Attestations != nil {
				namespaceReference(*bom.Declarations.Attestations, "Assessor")
				for _, attestation := range *bom.Declarations.Attestations {
					if attestation.Map != nil {
						namespaceReference(*attestation.Map, "Claims")
						namespaceReference(*attestation.Map, "CounterClaims")
						namespaceReference(*attestation.Map, "Requirement")

						// Handle conformance mitigation strategies
						for _, m := range *attestation.Map {
							if m.Conformance != nil {
								namespaceReference([]interface{}{m.Conformance}, "MitigationStrategies")
							}
						}
					}
				}
				*result.Declarations.Attestations = append(*result.Declarations.Attestations, *bom.Declarations.Attestations...)
			}

			// Claims
			if bom.Declarations.Claims != nil {
				namespaceBOMRefs(*bom.Declarations.Claims)
				namespaceReference(*bom.Declarations.Claims, "Evidence")
				namespaceReference(*bom.Declarations.Claims, "CounterEvidence")
				namespaceReference(*bom.Declarations.Claims, "Target")
				*result.Declarations.Claims = append(*result.Declarations.Claims, *bom.Declarations.Claims...)
			}

			// Evidence
			if bom.Declarations.Evidence != nil {
				namespaceBOMRefs(*bom.Declarations.Evidence)
				*result.Declarations.Evidence = append(*result.Declarations.Evidence, *bom.Declarations.Evidence...)
			}

			// Targets
			if result.Declarations.Targets != nil {
				namespaceBOMRefs(*result.Declarations.Targets.Organizations)
				namespaceBOMRefs(*result.Declarations.Targets.Components)
				namespaceBOMRefs(*result.Declarations.Targets.Services)
			}

			if bom.Declarations.Targets != nil {
				if bom.Declarations.Targets.Organizations != nil {
					*result.Declarations.Targets.Organizations = append(*result.Declarations.Targets.Organizations, *bom.Declarations.Targets.Organizations...)
				}
				if bom.Declarations.Targets.Components != nil {
					*result.Declarations.Targets.Components = append(*result.Declarations.Targets.Components, *bom.Declarations.Targets.Components...)
				}
				if bom.Declarations.Targets.Services != nil {
					*result.Declarations.Targets.Services = append(*result.Declarations.Targets.Services, *bom.Declarations.Targets.Services...)
				}
			}
		}
	}

	// Add final dependency structure if bomSubject exists
	if bomSubject != nil {
		refs := make([]string, len(bomSubjectDependencies))
		for i, dep := range bomSubjectDependencies {
			refs[i] = dep.Ref
		}
		*result.Dependencies = append(*result.Dependencies, cyclonedx.Dependency{
			Ref:          result.Metadata.Component.BOMRef,
			Dependencies: &refs,
		})
	}

	// Cleanup empty top level elements
	if result.Metadata != nil && result.Metadata.Tools != nil && result.Metadata.Tools.Components != nil && len(*result.Metadata.Tools.Components) == 0 {
		result.Metadata.Tools.Components = nil
	}
	if len(*result.Components) == 0 {
		result.Components = nil
	}
	if len(*result.Services) == 0 {
		result.Services = nil
	}
	if len(*result.ExternalReferences) == 0 {
		result.ExternalReferences = nil
	}
	if len(*result.Dependencies) == 0 {
		result.Dependencies = nil
	}
	if len(*result.Compositions) == 0 {
		result.Compositions = nil
	}
	if len(*result.Vulnerabilities) == 0 {
		result.Vulnerabilities = nil
	}

	return result, nil
}

// Helper functions

// componentBOMRefNamespace generates a namespace for a component's BOM reference
func componentBOMRefNamespace(component *cyclonedx.Component) string {
	if component == nil {
		return ""
	}

	if component.Group != "" {
		return fmt.Sprintf("%s.%s@%s", component.Group, component.Name, component.Version)
	}
	return fmt.Sprintf("%s@%s", component.Name, component.Version)
}

// namespacedBOMRef creates a namespaced BOM reference
func namespacedBOMRef(component *cyclonedx.Component, bomRef string) string {
	if bomRef == "" {
		return ""
	}
	return namespacedBOMRefWithNamespace(componentBOMRefNamespace(component), bomRef)
}

// namespacedBOMRefWithNamespace creates a namespaced BOM reference with namespace string
func namespacedBOMRefWithNamespace(bomRefNamespace, bomRef string) string {
	if bomRef == "" {
		return ""
	}
	if bomRefNamespace == "" {
		return bomRef
	}
	return fmt.Sprintf("%s:%s", bomRefNamespace, bomRef)
}

// namespaceBOMRefsWithComponent adds namespace to objects with BOM references
func namespaceBOMRefsWithComponent(bomSubject *cyclonedx.Component, references interface{}) {
	if references == nil {
		return
	}
	namespace := componentBOMRefNamespace(bomSubject)
	namespaceBOMRefs(namespace, references)
}

// namespaceBOMRefs adds namespace to objects that implement BOM reference interface
func namespaceBOMRefs(namespace string, items interface{}) {
	if namespace == "" || items == nil {
		return
	}

	v := reflect.ValueOf(items)
	if v.Kind() != reflect.Slice {
		return
	}

	for i := 0; i < v.Len(); i++ {
		item := v.Index(i)
		if item.Kind() == reflect.Ptr {
			item = item.Elem()
		}

		if item.Kind() == reflect.Struct {
			bomRefField := item.FieldByName("BOMRef")
			if bomRefField.IsValid() && bomRefField.CanSet() && bomRefField.Kind() == reflect.String {
				currentRef := bomRefField.String()
				if currentRef != "" {
					bomRefField.SetString(namespacedBOMRefWithNamespace(namespace, currentRef))
				}
			}
		}
	}
}

// namespaceProperty applies a namespace transformation to a specified property
func namespaceProperty(namespace string, items interface{}, propertyName string) {
	if namespace == "" || items == nil || propertyName == "" {
		return
	}

	v := reflect.ValueOf(items)
	if v.Kind() != reflect.Slice {
		return
	}

	for i := 0; i < v.Len(); i++ {
		item := v.Index(i)
		if item.Kind() == reflect.Ptr {
			item = item.Elem()
		}

		if item.Kind() != reflect.Struct {
			continue
		}

		propField := item.FieldByName(propertyName)
		if !propField.IsValid() || !propField.CanSet() {
			continue
		}

		switch propField.Kind() {
		case reflect.String:
			currentValue := propField.String()
			if currentValue != "" {
				propField.SetString(namespacedBOMRefWithNamespace(namespace, currentValue))
			}
		case reflect.Slice:
			if propField.Type().Elem().Kind() == reflect.String {
				if propField.IsNil() {
					continue
				}
				currentSlice := propField.Interface().([]string)
				updatedSlice := make([]string, len(currentSlice))
				for j, s := range currentSlice {
					updatedSlice[j] = namespacedBOMRefWithNamespace(namespace, s)
				}
				propField.Set(reflect.ValueOf(updatedSlice))
			}
		case reflect.Ptr:
			if propField.Type().Elem().Kind() == reflect.Slice {
				if propField.IsNil() {
					continue
				}
				sliceVal := propField.Elem()
				if sliceVal.Type().Elem().Kind() == reflect.String {
					currentSlice := sliceVal.Interface().([]string)
					updatedSlice := make([]string, len(currentSlice))
					for j, s := range currentSlice {
						updatedSlice[j] = namespacedBOMRefWithNamespace(namespace, s)
					}
					sliceVal.Set(reflect.ValueOf(updatedSlice))
				}
			}
		}
	}
}

// namespaceComponentBOMRefs adds namespace to component BOM references using stack
func namespaceComponentBOMRefs(bomRefNamespace string, topComponent *cyclonedx.Component) {
	if topComponent == nil || bomRefNamespace == "" {
		return
	}

	components := []*cyclonedx.Component{topComponent}

	for len(components) > 0 {
		currentComponent := components[len(components)-1]
		components = components[:len(components)-1]

		if currentComponent.Components != nil {
			for i := range *currentComponent.Components {
				components = append(components, &(*currentComponent.Components)[i])
			}
		}

		currentComponent.BOMRef = namespacedBOMRefWithNamespace(bomRefNamespace, currentComponent.BOMRef)
	}
}

// namespaceDependencyBOMRefs adds namespace to dependency BOM references using stack
func namespaceDependencyBOMRefs(bomRefNamespace string, dependencies []cyclonedx.Dependency) {
	if bomRefNamespace == "" {
		return
	}

	pendingDependencies := make([]*cyclonedx.Dependency, len(dependencies))
	for i := range dependencies {
		pendingDependencies[i] = &dependencies[i]
	}

	for len(pendingDependencies) > 0 {
		dependency := pendingDependencies[len(pendingDependencies)-1]
		pendingDependencies = pendingDependencies[:len(pendingDependencies)-1]

		if dependency.Dependencies != nil {
			for j := range *dependency.Dependencies {
				(*dependency.Dependencies)[j] = namespacedBOMRefWithNamespace(bomRefNamespace, (*dependency.Dependencies)[j])
			}
		}

		dependency.Ref = namespacedBOMRefWithNamespace(bomRefNamespace, dependency.Ref)
	}
}

// namespaceCompositions adds namespace to composition BOM references
func namespaceCompositions(bomRefNamespace string, compositions []cyclonedx.Composition) {
	if bomRefNamespace == "" {
		return
	}

	for i := range compositions {
		if compositions[i].Assemblies != nil {
			for j := range *compositions[i].Assemblies {
				currentRef := string((*compositions[i].Assemblies)[j])
				(*compositions[i].Assemblies)[j] = cyclonedx.BOMReference(namespacedBOMRefWithNamespace(bomRefNamespace, currentRef))
			}
		}

		if compositions[i].Dependencies != nil {
			for j := range *compositions[i].Dependencies {
				currentRef := string((*compositions[i].Dependencies)[j])
				(*compositions[i].Dependencies)[j] = cyclonedx.BOMReference(namespacedBOMRefWithNamespace(bomRefNamespace, currentRef))
			}
		}
	}
}

// namespaceVulnerabilitiesRefs adds namespace to vulnerability BOM references using stack
func namespaceVulnerabilitiesRefs(bomRefNamespace string, vulnerabilities []cyclonedx.Vulnerability) {
	if bomRefNamespace == "" {
		return
	}

	pendingVulnerabilities := make([]*cyclonedx.Vulnerability, len(vulnerabilities))
	for i := range vulnerabilities {
		pendingVulnerabilities[i] = &vulnerabilities[i]
	}

	for len(pendingVulnerabilities) > 0 {
		vulnerability := pendingVulnerabilities[len(pendingVulnerabilities)-1]
		pendingVulnerabilities = pendingVulnerabilities[:len(pendingVulnerabilities)-1]

		vulnerability.BOMRef = namespacedBOMRefWithNamespace(bomRefNamespace, vulnerability.BOMRef)

		if vulnerability.Affects != nil {
			for j := range *vulnerability.Affects {
				affect := &(*vulnerability.Affects)[j]
				affect.Ref = bomRefNamespace
			}
		}
	}
}

// containsComponent checks if a component already exists in the slice
func containsComponent(components []cyclonedx.Component, target cyclonedx.Component) bool {
	for _, comp := range components {
		if comp.BOMRef == target.BOMRef {
			return true
		}
	}
	return false
}

// containsService checks if a service already exists in the slice
func containsService(services []cyclonedx.Service, target cyclonedx.Service) bool {
	for _, svc := range services {
		if svc.BOMRef == target.BOMRef {
			return true
		}
	}
	return false
}
