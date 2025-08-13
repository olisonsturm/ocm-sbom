package converter

import (
	"fmt"
	"io"
	"os"

	"github.com/CycloneDX/cyclonedx-go"
)

// CycloneDXProcessor abstracts parsing, editing, and writing CycloneDX SBOMs.
type CycloneDXProcessor interface {
	Parse(path string) (*cyclonedx.BOM, error)
	Edit(b *cyclonedx.BOM, opts CycloneDXProcessorOptions) error
	Write(b *cyclonedx.BOM, path string, format cyclonedx.BOMFileFormat) error
}

// CycloneDXProcessorOptions contains minimal fields used to edit the SBOMs root component.
type CycloneDXProcessorOptions struct {
	Group      string
	Name       string
	Version    string
	Properties []cyclonedx.Property
}

type cyclonedxProcessorImpl struct{}

func NewCycloneDXProcessor() CycloneDXProcessor {
	return &cyclonedxProcessorImpl{}
}

// Parse reads a BOM from r, auto-detecting JSON or XML.
func (p *cyclonedxProcessorImpl) Parse(path string) (*cyclonedx.BOM, error) {

	sbomFile, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open sbom file %s: %w", path, err)
	}
	bom := cyclonedx.BOM{}
	decoder := cyclonedx.NewBOMDecoder(sbomFile, cyclonedx.BOMFileFormatJSON)
	if err = decoder.Decode(&bom); err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to decode sbom file %s: %w", path, err)
	}

	//format := sniffCycloneDXFormat(r)
	//if _, err := r.Seek(0, io.SeekStart); err != nil {
	//	return nil, err
	//}
	//dec := cyclonedx.NewBOMDecoder(r, format)
	//var bom cyclonedx.BOM
	//if err := dec.Decode(&bom); err != nil && err != io.EOF {
	//	return nil, err
	//}
	return &bom, nil
}

// Edit updates the root component metadata (group/name/version/properties).
func (p *cyclonedxProcessorImpl) Edit(b *cyclonedx.BOM, opts CycloneDXProcessorOptions) error {
	if b == nil {
		return nil
	}
	if b.Metadata == nil {
		b.Metadata = &cyclonedx.Metadata{}
	}
	if b.Metadata.Component == nil {
		b.Metadata.Component = &cyclonedx.Component{
			Type: cyclonedx.ComponentTypeApplication,
		}
	}
	root := b.Metadata.Component

	if opts.Group != "" {
		root.Group = opts.Group
	}
	if opts.Name != "" {
		root.Name = opts.Name
	}
	if opts.Version != "" {
		root.Version = opts.Version
	}
	if len(opts.Properties) > 0 {
		props := opts.Properties // avoid taking address of range variable
		root.Properties = &props
	}
	return nil
}

// Write serializes the BOM to w in the given format.
func (p *cyclonedxProcessorImpl) Write(bom *cyclonedx.BOM, path string, format cyclonedx.BOMFileFormat) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create sbom file %s: %w", path, err)
	}
	defer file.Close()
	encoder := cyclonedx.NewBOMEncoder(file, format)
	encoder.SetPretty(true)
	return encoder.Encode(bom)
}

// sniffCycloneDXFormat peeks at the first non-whitespace byte to guess JSON vs. XML.
func sniffCycloneDXFormat(r io.ReadSeeker) cyclonedx.BOMFileFormat {
	buf := make([]byte, 128)
	n, _ := r.Read(buf)
	for i := 0; i < n; i++ {
		switch buf[i] {
		case ' ', '\t', '\n', '\r':
			continue
		case '<':
			return cyclonedx.BOMFileFormatXML
		default:
			return cyclonedx.BOMFileFormatJSON
		}
	}
	// Default to JSON if inconclusive.
	return cyclonedx.BOMFileFormatJSON
}
