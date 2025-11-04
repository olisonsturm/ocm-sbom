/*
 * SPDX-FileCopyrightText: 2025 Olison Sturm
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package converter

import (
	"io"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/reader"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/writer"
)

// ProtobomProcessor abstracts parsing, editing, and writing SBOMs.
type ProtobomProcessor interface {
	Parse(r io.ReadSeeker) (*sbom.Document, error)
	Edit(doc *sbom.Document, opts ProcessorOptions) error
	Write(doc *sbom.Document, w io.Writer, format formats.Format) error
}

// ProcessorOptions contains minimal fields used to edit the SBOM's root node.
type ProcessorOptions struct {
	Name       string
	Version    string
	Properties []*sbom.Property
}

type protobomProcessorImpl struct{}

func NewProtobomProcessor() ProtobomProcessor {
	return &protobomProcessorImpl{}
}

func (e *protobomProcessorImpl) Parse(r io.ReadSeeker) (*sbom.Document, error) {
	rd := reader.New()
	return rd.ParseStream(r)
}

func (e *protobomProcessorImpl) Edit(doc *sbom.Document, opts ProcessorOptions) error {
	if doc == nil {
		return nil
	}
	rootNodes := doc.GetRootNodes()
	if len(rootNodes) == 0 {
		return nil
	}
	root := doc.GetNodeList().GetNodeByID(rootNodes[0].GetId())

	if opts.Name != "" {
		root.Name = opts.Name
	}
	if opts.Version != "" {
		root.Version = opts.Version
	}
	if len(opts.Properties) > 0 {
		root.Properties = opts.Properties
	}
	return nil
}

func (e *protobomProcessorImpl) Write(doc *sbom.Document, w io.Writer, format formats.Format) error {
	wr := writer.New()
	return wr.WriteStreamWithOptions(doc, w, &writer.Options{Format: format})
}
