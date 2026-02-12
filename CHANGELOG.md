# Changelog

All notable changes to the TrendAI Security Scanner extension will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.5] - 2026-02-11

### Added
- Demo GIF in README showcasing extension functionality

## [0.1.4] - 2026-02-11

### Fixed
- SVG icons now visible in dark mode (updated black fills to brand colors)
- Status bar issue count now matches results panel count

## [0.1.3] - 2026-02-11

### Added
- Technology-specific SVG icons in results panel for cloud providers (AWS, Azure, GCP), programming languages (Python, Go, Ruby, Java, Node.js), and tools (Docker, Terraform, OpenAI/AI)
- Visual identification of findings by technology type

### Changed
- Icons now use actual SVG files from resources/icons folder instead of inline data URIs
- Improved icon rendering with consistent sizing

## [0.1.2] - 2026-02-11

### Added
- TrendAI branded logo in results panel header

### Changed
- Updated results panel styling with improved header layout

## [0.1.1] - 2026-02-10

### Changed
- Minor UI improvements
- Package updates

## [0.1.0] - 2026-02-10

### Added
- Initial release
- Vulnerability scanning for application dependencies
- Secret detection with exact line/column locations
- Malware scanning for container images
- IaC template scanning (Terraform and CloudFormation)
- Docker build and scan workflow
- LLM application scanner
- Results tree view in Activity Bar
- Interactive results dashboard
- Code actions for quick fixes
- Configurable severity thresholds
- Multi-region support for Vision One API
- Automatic TMAS binary download
- Scan on save option
