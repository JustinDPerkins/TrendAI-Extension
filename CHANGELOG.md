# Changelog

All notable changes to the TrendAI Security Scanner extension will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.7] - 2026-02-19

### Added
- **LLM Scan: Technique Selection** - Choose attack techniques (Ignore instructions, DAN, Encrypt response, Payload splitting)
- **LLM Scan: Modifier Selection** - Choose attack modifiers (Base64 Encoding, Best-of-N Scrambling)
- **Named Scan Configs** - Save LLM scan configurations with custom names for easy reuse
- **Config Reuse** - Load and rerun previous scan configs without reconfiguring
- **Scan History** - All scan results saved to `.trendai-scans/results/` folder
- **IaC Results Persistence** - IaC scan results now saved to disk for later viewing
- **Show Results Dashboard** - Now loads historical results from saved scan files

### Changed
- **Compact LLM Results UI** - Replaced large card layout with compact table view
- **3-Column Conversation View** - Attack Prompt, Model Response, and Evaluation displayed side-by-side
- **Reduced UI Padding** - Smaller stats, headers, and table cells for denser information display
- **Organized Folder Structure** - Results in `results/`, configs in `saved-configs/`
- **Single Config Format** - YAML only (no duplicate JSON), used by both TMAS CLI and extension

### Fixed
- **Clear Results** - Now properly clears the results panel in addition to diagnostics
- **Show Results** - Dashboard now displays saved results instead of empty panel
- **Excluded Dependency Folders** - Scan results now filter out `.terraform`, `node_modules`, `.git`, and other dependency directories to avoid false positives from downloaded binaries

## [0.1.6] - 2026-02-11

### Fixed
- Demo GIF now displays correctly on VS Code Marketplace (uses absolute URL)

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
