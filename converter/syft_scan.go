/*
 * SPDX-FileCopyrightText: 2025 Olison Sturm
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package converter

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/anchore/clio"
	"github.com/anchore/go-collections"
	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/cyclonedxxml"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/spdxtagvalue"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/sourceproviders"
)

// ScanConfig holds the configuration for scanning using only public Syft APIs
type ScanConfig struct {
	// Output configuration
	OutputFormats []string
	OutputFile    string

	// Catalog configuration (subset we actually use)
	Catalog CatalogConfig
}

type CatalogConfig struct {
	From       []string
	Platform   string
	Exclusions []string
	Source     struct {
		Name     string
		Version  string
		BasePath string
		// Optional nested structs preserved for future use; not used here
		Image struct {
			DefaultPullSource string
		}
		File struct {
			Digests []string
		}
	}
}

// DefaultScanConfig returns a ScanConfig with default values
func DefaultScanConfig() *ScanConfig {
	return &ScanConfig{
		OutputFormats: []string{"cyclonedx-json"},
		OutputFile:    "",
		Catalog:       CatalogConfig{},
	}
}

// Scanner provides scanning functionality
type Scanner struct {
	config *ScanConfig
	id     clio.Identification
}

// NewScanner creates a new Scanner instance
func NewScanner(config *ScanConfig, id clio.Identification) *Scanner {
	if config == nil {
		config = DefaultScanConfig()
	}
	return &Scanner{
		config: config,
		id:     id,
	}
}

// NewScannerWithDefaults creates a new Scanner with default configuration and identification
func NewScannerWithDefaults() *Scanner {
	id := clio.Identification{
		Name:    "syft-scanner",
		Version: "dev",
	}
	return NewScanner(DefaultScanConfig(), id)
}

// Scan runs the scanning process on the given input
func (s *Scanner) Scan(ctx context.Context, userInput string) (*sbom.SBOM, error) {
	return s.runScan(ctx, userInput)
}

// ScanToWriter runs the scanning process and writes the result to the configured output file
func (s *Scanner) ScanToWriter(ctx context.Context, userInput string) error {
	sb, err := s.runScan(ctx, userInput)
	if err != nil {
		return err
	}
	if sb == nil {
		return fmt.Errorf("no SBOM produced for %q", userInput)
	}

	// pick first requested output format or default
	formatName := "cyclonedx-json"
	if len(s.config.OutputFormats) > 0 && s.config.OutputFormats[0] != "" {
		formatName = s.config.OutputFormats[0]
	}

	// open output destination
	if s.config.OutputFile == "" {
		return fmt.Errorf("no output file configured")
	}
	f, err := os.Create(s.config.OutputFile)
	if err != nil {
		return fmt.Errorf("failed to open output file: %w", err)
	}
	defer func() { _ = f.Close() }()

	enc, err := encoderFor(formatName)
	if err != nil {
		return err
	}
	b, err := format.Encode(*sb, enc)
	if err != nil {
		return fmt.Errorf("failed to encode SBOM: %w", err)
	}
	if _, err := f.Write(b); err != nil {
		return fmt.Errorf("failed to write SBOM file: %w", err)
	}
	return nil
}

// runScan performs the actual scanning logic
func (s *Scanner) runScan(ctx context.Context, userInput string) (*sbom.SBOM, error) {
	if err := s.validateConfig(); err != nil {
		return nil, err
	}

	sources := s.config.Catalog.From
	if len(sources) == 0 {
		// extract a scheme if it matches any provider tag; this is a holdover for compatibility, using the --from flag is recommended
		explicitSource, newUserInput := stereoscope.ExtractSchemeSource(userInput, allSourceProviderTags()...)
		if explicitSource != "" {
			sources = append(sources, explicitSource)
			userInput = newUserInput
		}
	}

	src, err := s.getSource(ctx, userInput, sources...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = src.Close() }()

	return s.generateSBOM(ctx, src)
}

// validateConfig validates the scanner configuration
func (s *Scanner) validateConfig() error {
	// No validation needed since we don't use config files
	return nil
}

// getSource creates a source from the user input
func (s *Scanner) getSource(ctx context.Context, userInput string, sources ...string) (source.Source, error) {
	opts := &s.config.Catalog

	cfg := syft.DefaultGetSourceConfig().
		WithAlias(source.Alias{
			Name:    opts.Source.Name,
			Version: opts.Source.Version,
		}).
		WithExcludeConfig(source.ExcludeConfig{Paths: opts.Exclusions}).
		WithBasePath(opts.Source.BasePath).
		WithSources(sources...)

	var err error
	var platform *image.Platform
	if opts.Platform != "" {
		platform, err = image.NewPlatform(opts.Platform)
		if err != nil {
			return nil, fmt.Errorf("invalid platform: %w", err)
		}
		cfg = cfg.WithPlatform(platform)
	}

	src, err := syft.GetSource(ctx, userInput, cfg)
	if err != nil {
		return nil, fmt.Errorf("could not determine source: %w", err)
	}
	return src, nil
}

// generateSBOM creates an SBOM from the source
func (s *Scanner) generateSBOM(ctx context.Context, src source.Source) (*sbom.SBOM, error) {
	// Use default public CreateSBOM config; do not rely on internal options.
	return syft.CreateSBOM(ctx, src, syft.DefaultCreateSBOMConfig())
}

// SetOutputFormat sets the output format for the scanner
func (s *Scanner) SetOutputFormat(formatName string) {
	s.config.OutputFormats = []string{formatName}
}

// SetOutputFile sets the output file for the scanner
func (s *Scanner) SetOutputFile(file string) {
	s.config.OutputFile = file
}

// SetPlatform sets the platform for container image scanning
func (s *Scanner) SetPlatform(platform string) {
	s.config.Catalog.Platform = platform
}

// SetSources sets the sources for the scanner
func (s *Scanner) SetSources(sources []string) {
	s.config.Catalog.From = sources
}

// SetExclusions sets the exclusion paths for the scanner
func (s *Scanner) SetExclusions(exclusions []string) {
	s.config.Catalog.Exclusions = exclusions
}

// GetConfig returns the current scanner configuration
func (s *Scanner) GetConfig() *ScanConfig {
	return s.config
}

// encoderFor maps a user format string to a Syft encoder
func encoderFor(name string) (sbom.FormatEncoder, error) {
	switch strings.ToLower(name) {
	case "cyclonedx-json", "cdx-json", "cyclonedx":
		cfg := cyclonedxjson.DefaultEncoderConfig()
		return cyclonedxjson.NewFormatEncoderWithConfig(cfg)
	case "cyclonedx-xml", "cdx-xml":
		cfg := cyclonedxxml.DefaultEncoderConfig()
		return cyclonedxxml.NewFormatEncoderWithConfig(cfg)
	case "spdx-json", "spdx":
		cfg := spdxjson.DefaultEncoderConfig()
		return spdxjson.NewFormatEncoderWithConfig(cfg)
	case "spdx-tag-value", "spdx-tv", "spdxtagvalue":
		cfg := spdxtagvalue.DefaultEncoderConfig()
		return spdxtagvalue.NewFormatEncoderWithConfig(cfg)
	case "syft-json":
		cfg := syftjson.DefaultEncoderConfig()
		return syftjson.NewFormatEncoderWithConfig(cfg)
	default:
		return nil, fmt.Errorf("unsupported output format: %s", name)
	}
}

func trimOperation(x string) string {
	return strings.TrimLeft(x, "+-")
}

func allSourceProviderTags() []string {
	return collections.TaggedValueSet[source.Provider]{}.Join(sourceproviders.All("", nil)...).Tags()
}
