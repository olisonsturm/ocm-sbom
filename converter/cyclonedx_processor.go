package converter

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
)

type CycloneDXProcessor interface {
	Parse(path string) (*cyclonedx.BOM, error)
	Edit(b *cyclonedx.BOM, opts CycloneDXProcessorOptions) error
	Write(b *cyclonedx.BOM, path string, format cyclonedx.BOMFileFormat) error
}

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

// Parse reads a BOM from path, auto-detecting JSON or XML.
func (p *cyclonedxProcessorImpl) Parse(path string) (*cyclonedx.BOM, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open sbom file %s: %w", path, err)
	}
	defer f.Close()

	format := sniffCycloneDXFormat(f)
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to rewind sbom file %s: %w", path, err)
	}

	var bom cyclonedx.BOM
	dec := cyclonedx.NewBOMDecoder(f, format)
	if err := dec.Decode(&bom); err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to decode sbom file %s: %w", path, err)
	}
	return &bom, nil
}

func (p *cyclonedxProcessorImpl) Edit(b *cyclonedx.BOM, opts CycloneDXProcessorOptions) error {
	if b == nil {
		return nil
	}
	if b.Metadata == nil {
		b.Metadata = &cyclonedx.Metadata{}
	}
	if b.Metadata.Component == nil {
		b.Metadata.Component = &cyclonedx.Component{Type: cyclonedx.ComponentTypeApplication}
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
		props := opts.Properties
		root.Properties = &props
	}
	return nil
}

func (p *cyclonedxProcessorImpl) Write(bom *cyclonedx.BOM, path string, format cyclonedx.BOMFileFormat) error {
	if bom == nil {
		return fmt.Errorf("cannot write SBOM: input BOM is nil")
	}
	if format == 0 {
		format = guessFormatFromExt(path)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("failed to open sbom file %s for writing: %w", path, err)
	}
	defer file.Close()

	enc := cyclonedx.NewBOMEncoder(file, format)
	enc.SetPretty(true)
	return enc.Encode(bom)
}

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
	return cyclonedx.BOMFileFormatJSON
}

func guessFormatFromExt(path string) cyclonedx.BOMFileFormat {
	l := strings.ToLower(path)
	if strings.HasSuffix(l, ".xml") {
		return cyclonedx.BOMFileFormatXML
	}
	return cyclonedx.BOMFileFormatJSON
}
