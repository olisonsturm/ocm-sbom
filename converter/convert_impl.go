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

	// Process all components recursively starting at the given component (use version 1.0.0 for now) TODO: support version selection
	allComponentSBOMPaths, err := c.processAllComponents(repo, componentName, "1.0.0", targetFormat)
	if err != nil {
		return nil, fmt.Errorf("error processing components: %w", err)
	}
	if len(allComponentSBOMPaths) == 0 {
		log.Println("No SBOMs were generated for any components. Result will be empty.")
		return []byte{}, nil
	}

	// The first entry is the fully merged SBOM for the root component (parent stays root).
	rootComponentSbomPath := allComponentSBOMPaths[0]
	log.Printf("Final merged SBOM at: %s", rootComponentSbomPath)

	// Optionally convert to the desired output format
	return c.convertFinalSBOM(rootComponentSbomPath, targetFormat)
}

// processAllComponents traverses the component hierarchy, generates SBOMs for each component's
// resources, then merges bottom-up so each parent includes its children. The returned slice's
// first element is the root component's fully merged SBOM path.
// go
func (c *CLIConverter) processAllComponents(repo oci.ComponentVersionRepository, componentName, componentVersion string, outputFormat SBOMFormat) ([]string, error) {
	type void = struct{}

	processor := NewComponentProcessor(c)
	merger := NewComponentSbomMerger(c)

	// Graph and bookkeeping
	type compKey struct{ Name, Version string }
	id := func(n, v string) string { return fmt.Sprintf("%s:%s", n, v) }

	rootID := id(componentName, componentVersion)

	visited := make(map[string]bool)
	queue := []compKey{{Name: componentName, Version: componentVersion}}

	// Store descriptors, child relations, reverse parent relations, and per-node SBOM paths
	descriptors := make(map[string]interface{})   // kept for future use; not needed for name/version
	childrenOf := make(map[string][]string)       // parentID -> []childID
	parentsOf := make(map[string]map[string]void) // childID -> set(parentID)
	resourceSBOMPath := make(map[string]string)   // nodeID -> path of SBOM for that node's resources
	resultPath := make(map[string]string)         // nodeID -> merged (node + subtree) SBOM path
	remainingChildren := make(map[string]int)     // nodeID -> remaining children to be processed
	allNodes := make(map[string]void)

	ctx := context.Background()

	// 1) Build graph (BFS) and generate resource-only SBOMs for each component
	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]
		currID := id(curr.Name, curr.Version)
		if visited[currID] {
			continue
		}
		visited[currID] = true

		log.Printf("Processing component (graph build): %s", currID)
		runtimeDesc, err := repo.GetComponentVersion(ctx, curr.Name, curr.Version)
		if err != nil {
			log.Printf("Warning: could not get component version for %s: %v", currID, err)
			// Skip if descriptor cannot be obtained
			continue
		}

		// Generate and store resource-only SBOM for this component
		mergedSBOMPath, err := processor.ProcessComponent(runtimeDesc, outputFormat)
		if err != nil {
			log.Printf("Warning: error processing component %s: %v", currID, err)
			// Keep going; if no SBOM, children might still produce results
		}
		if mergedSBOMPath != "" {
			resourceSBOMPath[currID] = mergedSBOMPath
			log.Printf("SBOM for component %s at %s", currID, mergedSBOMPath)
		}

		// Remember descriptor and children
		descriptors[currID] = runtimeDesc
		allNodes[currID] = struct{}{}

		for _, ref := range runtimeDesc.Component.References {
			childID := id(ref.Component, ref.Version)
			childrenOf[currID] = append(childrenOf[currID], childID)

			if _, ok := parentsOf[childID]; !ok {
				parentsOf[childID] = make(map[string]void)
			}
			parentsOf[childID][currID] = struct{}{}

			if !visited[childID] {
				queue = append(queue, compKey{Name: ref.Component, Version: ref.Version})
			}
		}
	}

	if len(allNodes) == 0 {
		log.Printf("No components discovered from root %s:%s", componentName, componentVersion)
		return nil, nil
	}

	// Initialize remaining children counts
	for nid := range allNodes {
		remainingChildren[nid] = len(childrenOf[nid])
	}

	// 2) Bottom-up merging: process leaves first, propagate upwards
	processed := make(map[string]bool)
	batch := make([]string, 0)
	for nid := range allNodes {
		if remainingChildren[nid] == 0 {
			batch = append(batch, nid)
		}
	}

	for len(processed) < len(allNodes) && len(batch) > 0 {
		next := make([]string, 0)
		for _, nid := range batch {
			if processed[nid] {
				continue
			}

			// Files to merge: this component's resource SBOM + all children's merged SBOMs
			files := make([]string, 0, 1+len(childrenOf[nid]))
			if p := resourceSBOMPath[nid]; p != "" {
				files = append(files, p)
			}
			for _, cid := range childrenOf[nid] {
				if cp := resultPath[cid]; cp != "" {
					files = append(files, cp)
				}
			}

			// If no files collected, nothing to produce
			if len(files) == 0 {
				log.Printf("Warning: no SBOM inputs collected for %s; skipping merge for this node", nid)
				processed[nid] = true
				for parentID := range parentsOf[nid] {
					remainingChildren[parentID]--
					if remainingChildren[parentID] == 0 && !processed[parentID] {
						next = append(next, parentID)
					}
				}
				continue
			}

			// If only one file, it is already the final SBOM for this node
			finalPath := files[0]
			if len(files) > 1 {
				// Derive component name/version from node ID "name:version" to avoid invalid type assertion
				compName, compVersion := "", ""
				if parts := strings.SplitN(nid, ":", 2); len(parts) == 2 {
					compName, compVersion = parts[0], parts[1]
				} else if len(parts) == 1 {
					compName = parts[0]
				}

				outPath, err := merger.ComponentSbomMerge(c.TempDir, files, "cyclonedx-cli", compName, compVersion)
				if err != nil {
					log.Printf("Warning: merge failed for %s, using first input: %v", nid, err)
				} else {
					finalPath = outPath
				}
			}

			resultPath[nid] = finalPath
			processed[nid] = true

			// Notify parents
			for parentID := range parentsOf[nid] {
				remainingChildren[parentID]--
				if remainingChildren[parentID] == 0 && !processed[parentID] {
					next = append(next, parentID)
				}
			}
		}
		batch = next
	}

	// 3) The root's merged SBOM already contains the full hierarchy; return it first.
	rootMerged := resultPath[rootID]
	if rootMerged == "" {
		// Fallback: if root had no result, return any path we created
		for _, p := range resultPath {
			rootMerged = p
			break
		}
	}
	if rootMerged == "" {
		log.Printf("No merged SBOM produced for root %s", rootID)
		return nil, nil
	}

	// Keep return type the same; ensure the root SBOM is first.
	return []string{rootMerged}, nil
}

// processAllComponentsOld traverses the component hierarchy and generates a merged SBOM for each component.
func (c *CLIConverter) processAllComponentsOld(repo oci.ComponentVersionRepository, componentName, componentVersion string, outputFormat SBOMFormat) ([]string, error) {
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
	outputVersion := "1.6" // default for CycloneDX

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
