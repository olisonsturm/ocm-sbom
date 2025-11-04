# OCM → CycloneDX mapping CLI

A Go/Cobra CLI for mapping OCM component descriptors to CycloneDX Software Bills of Materials.

## About this project

A CLI tool to convert a Software Bill of Delivery so basically Open Component Model (OCM) components to Software Bill of Materials (SBOM) formats by now CycloneDX BOM. This tool is for the OCM ecosystem and is designed to help users generate SBOMs for their OCM components. This project is part of ongoing research and builds upon work conducted in the context of a bachelor thesis of @olisonsturm.

Check out the [OCM Toolset](https://github.com/open-component-model/ocm) and the [OCM Specification](https://github.com/open-component-model/ocm-spec) for more information about the Open Component Model.

## Requirements and Setup

### Installation

To install the tool, you can use the following command:

```bash
go install github.com/olisonsturm/ocm-sbom@latest
```

### Usage

After installation, you can use the tool to generate SBOMs for your OCM components.
The basic command structure is as follows:

```bash
ocm-sbom [command] [flags]
```

## Support, Feedback, Contributing

This project is open to feature requests/suggestions, bug reports etc. via [GitHub issues](https://github.com/open-component-model/<your-project>/issues). Contribution and feedback are encouraged and always welcome. For more information about how to contribute, the project structure, as well as additional contribution information, see our [Contribution Guidelines](CONTRIBUTING.md).

## Code of Conduct

We as members, contributors, and leaders pledge to make participation in our community a harassment-free experience for everyone. By participating in this project, you agree to abide by its [Code of Conduct](CODE_OF_CONDUCT.md) at all times.

## Licensing

Copyright 2025 SAP SE or an SAP affiliate company and Open Component Model contributors. Please see our [LICENSE](LICENSE) for copyright and license information. Detailed information including third-party components and their licensing/copyright information is available [via the REUSE tool](https://api.reuse.software/info/github.com/open-component-model/<your-project>).
