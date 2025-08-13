package converter

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"strings"
)

type MetadataConfig struct {
	ComponentName    string `json:"component_name"`
	ComponentVersion string `json:"component_version"`
	ComponentType    string `json:"component_type"`
	BomRef           string `json:"bom_ref"`
}

type SBOM struct {
	Metadata struct {
		Component struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Type    string `json:"type"`
			BomRef  string `json:"bom-ref"`
		} `json:"component"`
	} `json:"metadata"`
}

// Ruft Syft auf, um ein SBOM für eine gegebene Image-Referenz zu generieren.
// outputFormat sollte ein Syft-kompatibles Format sein (z.B. "cyclonedx-json", "spdx-json").
// Deprecated: generateSBOMWithSyft is deprecated.
// Use NewScanner or NewScannerWithDefaults from converter/syft_scan.go and call Scan() or ScanToWriter() instead.
func (c *CLIConverter) generateSBOMWithSyft(imageRef string, outputFormat string) (string, error) {
	panic("generateSBOMWithSyft is deprecated. Use NewScanner or NewScannerWithDefaults from converter/syft_scan.go and call Scan() or ScanToWriter() instead.")
	if c.SyftCLIPath == "" {
		return "", fmt.Errorf("Syft CLI Pfad nicht gesetzt oder gefunden")
	}

	// Perform Syft command to generate SBOM
	cmd := exec.Command(c.SyftCLIPath, imageRef, "-o", outputFormat)

	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &outBuf

	log.Printf("Führe Syft aus: %s %s\n", c.SyftCLIPath, strings.Join(cmd.Args, " "))

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("Syft Ausführung fehlgeschlagen für %s: %w\nAusgabe:\n%s", imageRef, err, outBuf.String())
	}

	return outBuf.String(), nil
}
