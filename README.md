# SBOM License Enrichment Tool

This repository provides a Python script to enrich CycloneDX SBOM files with accurate license information from multiple sources. It resolves `UNKNOWN` licenses and prepares data for audits or compliance reviews.
This tool enriches CycloneDX SBOM files with license data from GitHub, npm, and pkg.go.dev, using overrides and PURL fallback for improved accuracy.

## Features
- Enriches SBOM data using:
  - Overrides file (`license_overrides.json`) with wildcard support
  - GitHub API (optional `GITHUB_TOKEN` for rate limits)
  - pkg.go.dev and npm registry lookups
- Marks vendor/replaced modules as `Proprietary`
- Resolves UNKNOWN licenses from multiple sources
- Adds PURL fallback to improve detection
- Outputs enriched data in JSON and CSV formats
- Provides summary of resolved vs unknown vs proprietary licenses

## License Resolution Order
1. Check `license_overrides.json`
2. Query GitHub API (if URL matches)
3. Query npm registry or pkg.go.dev
4. Default to `Proprietary` for vendor/replaced modules
5. Mark as `UNKNOWN` if none found

## Files
- enrich_sbom_licenses.py: Main script
- license_overrides.json: Override mappings for known modules
- sbom-cyclonedx.json: Input SBOM (user provided)
- sbom-cyclonedx-enriched.json: Enriched output
- sbom-license-enriched.csv: License report

## Usage
```bash
python3 enrich_sbom_licenses.py
```

**Outputs:**
- `sbom-cyclonedx-enriched.json`
- `sbom-license-enriched.csv`


## Final Workflow (Stable)

### 1. Overview
This workflow enriches a CycloneDX SBOM with license information by querying:
- GitHub API
- npm registry
- pkg.go.dev
- External overrides (JSON with wildcards)

The script is optimized for performance (parallel lookups) and stability.

---

### 2. Prerequisites
- Python 3.9+
- `.env` file with GitHub token:
  ```
  GITHUB_TOKEN=<your-token-here>
  ```
- `license_overrides.json` for custom license mappings.

---

### 3. Usage
Run the enrichment process:

```bash
python3 enrich_sbom_licenses.py
```

Outputs:
- `sbom-cyclonedx-enriched.json`
- `sbom-license-enriched.csv`

---

### 4. Overrides
- Use `license_overrides.json` for static mappings.
- Supports wildcards (e.g., `github.com/org/*`).

---

### 5. Summary of Results
- **Resolved licenses**: Total/X5
- **Unknowns**: ##
- **Proprietaruy: ##

---

### 6. Notes
- Internal files like `go.mod` and `bun.lock` are auto-marked as Proprietary.
- Stable script locked; only update overrides for new unknowns.
- `.env` is ignored via `.gitignore`.
