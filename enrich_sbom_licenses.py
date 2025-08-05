#!/usr/bin/env python3

"""
Stable SBOM License Enricher with Normalization:
- Resolves UNKNOWN licenses using GitHub API, npm registry, pkg.go.dev
- Supports external license overrides with wildcards
- Uses caching + parallel requests for performance
- Marks internal/replaced modules as Proprietary
- Adds fallback license resolution using PURLs
- Normalizes license strings (e.g., 'SEE LICENSE', dict types) to clean SPDX IDs
"""

import json, csv, os, requests, re, fnmatch
from dotenv import load_dotenv
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------- CONFIG ----------------
INPUT_FILE = "sbom-cyclonedx.json"
OUTPUT_CSV = "sbom-license-enriched.csv"
OUTPUT_JSON = "sbom-cyclonedx-enriched.json"
OVERRIDES_FILE = "license_overrides.json"
MAX_WORKERS = 10
# -----------------------------------------

# Load GitHub token
load_dotenv()
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

headers = {
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "SBOM-License-Enricher"
}
if GITHUB_TOKEN:
    headers["Authorization"] = f"token {GITHUB_TOKEN}"

# Go vanity mapping
VANITY_MAPPINGS = {
    "golang.org/x/": "github.com/golang/",
    "go.uber.org/": "github.com/uber-go/",
    "go.etcd.io/": "github.com/etcd-io/"
}

# Cache for resolved licenses
cache = {}

# ---------------- Overrides Loader ----------------
def load_overrides():
    if os.path.exists(OVERRIDES_FILE):
        with open(OVERRIDES_FILE, "r") as f:
            return json.load(f)
    return {}

overrides = load_overrides()

# ---------------- License Normalization ----------------
def normalize_license(license_str):
    """
    Normalize license strings:
    - Handle dicts from npm ({"type": "MIT", "url": "..."}).
    - Convert 'SEE LICENSE' to UNKNOWN.
    - Fix lowercase variants (e.g., 'mit' → 'MIT').
    """
    if not license_str:
        return "UNKNOWN"

    # If npm returns a dict
    if isinstance(license_str, dict) and "type" in license_str:
        license_str = license_str["type"]

    # Strip whitespace
    license_str = str(license_str).strip()

    # Map "SEE LICENSE" to UNKNOWN
    if "SEE LICENSE" in license_str.upper():
        return "UNKNOWN"

    # Normalize case for known SPDX
    mapping = {
        "unlicense": "Unlicense",
        "mit": "MIT",
        "apache-2.0": "Apache-2.0",
        "bsd-3-clause": "BSD-3-Clause",
        "bsd-2-clause": "BSD-2-Clause",
        "mpl-2.0": "MPL-2.0",
        "gpl-3.0": "GPL-3.0",
        "lgpl-3.0": "LGPL-3.0"
    }
    return mapping.get(license_str.lower(), license_str)

# ---------------- Helper Functions ----------------
def is_internal(pkg_name):
    """Identify internal/modules"""
    return (
        "modules/" in pkg_name or 
        "vendor/" in pkg_name or
        #"company" in pkg_name or
        pkg_name.strip() == "" or
        pkg_name.endswith(".go.mod") or
        pkg_name.endswith("requirements.txt") or
        pkg_name.endswith("package-lock.json") or
        pkg_name.endswith("bun.lock") or
        pkg_name == "go.mod"
    )

def map_vanity_to_github(pkg_name):
    """Map Go vanity URLs to GitHub repos"""
    for vanity, github_prefix in VANITY_MAPPINGS.items():
        if pkg_name.startswith(vanity):
            return pkg_name.replace(vanity, github_prefix)
    return pkg_name

def github_license_lookup(pkg_name):
    """Query GitHub API for license"""
    pkg_name = map_vanity_to_github(pkg_name)
    if pkg_name.startswith("github.com/"):
        parts = pkg_name.split("/")
        if len(parts) >= 3:
            api_url = f"https://api.github.com/repos/{parts[1]}/{parts[2]}"
            try:
                r = requests.get(api_url, headers=headers, timeout=10)
                if r.status_code == 200:
                    return normalize_license(r.json().get("license", {}).get("spdx_id", "UNKNOWN"))
            except Exception:
                pass
    return "UNKNOWN"

def npm_license_lookup(pkg_name):
    """Query npm registry for license (supports no-dash names)"""
    try:
        r = requests.get(f"https://registry.npmjs.org/{pkg_name}", timeout=10)
        if r.status_code == 200:
            data = r.json()
            latest_ver = data.get("dist-tags", {}).get("latest")
            if latest_ver and latest_ver in data.get("versions", {}):
                return normalize_license(data["versions"][latest_ver].get("license", "UNKNOWN"))
            return normalize_license(data.get("license", "UNKNOWN"))
    except Exception:
        pass
    return "UNKNOWN"

def pkg_go_dev_license_lookup(pkg_name):
    """Scrape pkg.go.dev for license info"""
    try:
        url = f"https://pkg.go.dev/{pkg_name}?tab=licenses"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, "html.parser")
            text = soup.get_text()
            matches = re.findall(
                r"(MIT|Apache-2\.0|BSD-3-Clause|BSD-2-Clause|MPL-2\.0|GPL-3\.0|LGPL-3\.0)",
                text, re.IGNORECASE
            )
            if matches:
                return normalize_license(matches[0].upper().replace(" ", "-"))
    except Exception:
        pass
    return "UNKNOWN"

def normalize_from_purl(purl):
    """Normalize PURL (e.g., pkg:npm/hasown@2.0.2) -> hasown"""
    try:
        purl_body = purl.split("/", 1)[1] if "/" in purl else purl
        purl_body = purl_body.split("@")[0]
        return purl_body
    except Exception:
        return None

# ---------------- Core Resolution ----------------
def resolve_license(name):
    # Check cache
    if name in cache:
        return cache[name]

    # 1. Check overrides
    for pattern, license_val in overrides.items():
        if fnmatch.fnmatch(name, pattern):
            cache[name] = license_val
            return license_val

    # 2. Proprietary
    if is_internal(name):
        cache[name] = "Proprietary"
        return "Proprietary"

    # 3. GitHub / vanity mapping
    if name.startswith("github.com/") or any(name.startswith(v) for v in VANITY_MAPPINGS.keys()):
        lic = github_license_lookup(name)
        if lic != "UNKNOWN":
            cache[name] = lic
            return lic
        lic = pkg_go_dev_license_lookup(name)
        cache[name] = lic
        return lic

    # 4. Go modules (pkg.go.dev)
    if name.startswith(("google.golang.org/", "gopkg.in/", "go.opencensus.io", "go.opentelemetry.io", "cloud.google.com/", "k8s.io/", "sigs.k8s.io/")):
        lic = pkg_go_dev_license_lookup(name)
        cache[name] = lic
        return lic

    # 5. npm fallback
    if name:
        lic = npm_license_lookup(name)
        cache[name] = lic
        return lic

    cache[name] = "UNKNOWN"
    return "UNKNOWN"

# ---------------- Main Enrichment ----------------
def enrich_sbom(input_file):
    with open(input_file, "r") as f:
        sbom = json.load(f)

    components = sbom.get("components", [])
    enriched_data = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_comp = {}
        for comp in components:
            name = comp.get("name", "")
            future_to_comp[executor.submit(resolve_license, name)] = comp

        for future in as_completed(future_to_comp):
            comp = future_to_comp[future]
            name = comp.get("name", "")
            version = comp.get("version", "")
            purl = comp.get("purl", "")

            try:
                enriched_license = future.result()
            except Exception:
                enriched_license = "UNKNOWN"

            # Fallback to PURL
            if enriched_license == "UNKNOWN" and purl:
                purl_name = normalize_from_purl(purl)
                if purl_name:
                    enriched_license = resolve_license(purl_name)

            # Write back to JSON if resolved
            if enriched_license != "UNKNOWN":
                comp["licenses"] = [{"license": {"id": enriched_license}}]

            enriched_data.append([name, version, enriched_license])

    # Save enriched JSON
    with open(OUTPUT_JSON, "w") as jf:
        json.dump(sbom, jf, indent=2)

    # Save CSV
    with open(OUTPUT_CSV, "w", newline="") as cf:
        writer = csv.writer(cf)
        writer.writerow(["Package Name", "Version", "License"])
        writer.writerows(enriched_data)

    # Summary
    total = len(enriched_data)
    unknown_count = sum(1 for row in enriched_data if row[2] == "UNKNOWN")
    proprietary_count = sum(1 for row in enriched_data if row[2] == "Proprietary")
    resolved_count = total - unknown_count

    print(f"Enriched SBOM JSON → {OUTPUT_JSON}")
    print(f"Enriched CSV → {OUTPUT_CSV}")
    print(f"\nSummary: {resolved_count}/{total} resolved, {unknown_count} unknown, {proprietary_count} proprietary")

if __name__ == "__main__":
