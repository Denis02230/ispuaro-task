import argparse, json, requests, time

def is_version_affected(version_end: str, actual_version: str) -> bool:
    try:
        return float(version_end) >= float(actual_version)
    except ValueError:
        return False

def fetch_cves_for_package(pkg_name, pkg_version, max_pages=200, res_per_page=20):
    cves = []
    print(f"# trying to fetch CVEs for {pkg_name} {pkg_version}")

    for page in range(1, max_pages + 1):
        print(f"## looking through page {page}")
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "keywordSearch": pkg_name,
            "resultsPerPage": res_per_page,
            "startIndex": (page - 1) * res_per_page
        }

        resp = requests.get(url, params=params)
        try:
            data = resp.json()
        except:
            print(f"## failed to parse response as json: {resp}")
            exit(1)

        for item in data["vulnerabilities"]:
            try:
                cve_data = item["cve"]
                cve_id = cve_data["id"]
                configs = cve_data["configurations"][0]["nodes"]
            except KeyError: continue

            found_match = False
            for node in configs:
                for cpe in node["cpeMatch"]:
                    if not cpe["vulnerable"]:
                        continue
                    version_end = cpe.get("versionEndIncluding")
                    if version_end:
                        try:
                            if is_version_affected(version_end, pkg_version):
                                cves.append({
                                    "id": cve_id,
                                    "description": cve_data["descriptions"][0]["value"],
                                    "score": cve_data["metrics"]["cvssMetricV2"][0]["cvssData"]["baseScore"],
                                    "severity": cve_data["metrics"]["cvssMetricV2"][0]["baseSeverity"],
                                })
                                found_match = True
                                print(f"## found vulnerability in {pkg_name}, versionEndIncluding was {version_end} >= {pkg_version}")
                                break
                        except KeyError:
                            pass
                if found_match:
                    break

        if cves:
            break

        time.sleep(15)

    if cves:
        print(f"# found {len(cves)} CVEs for {pkg_name} {pkg_version}")
    else:
        print(f"# didn't find CVEs for {pkg_name} {pkg_version} :(")

    return cves

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("no_cve_sbom_path")
    parser.add_argument("full_sbom_path")
    parser.add_argument("--targets", nargs="+", help="List of package:version pairs like glibc:2.40 zlib:1.2.13", required=True)
    args = parser.parse_args()

    no_cve_sbom_path = args.no_cve_sbom_path
    full_sbom_path = args.full_sbom_path
    targets_raw = args.targets

    targets = []
    for pair in targets_raw:
        if ':' not in pair:
            print(f"Invalid target format: {pair}")
            continue
        name, version = pair.split(":", 1)
        targets.append({"name": name, "version": version})

    with open(no_cve_sbom_path) as f:
        sbom = json.load(f)

    sbom.setdefault("components", [])
    sbom.setdefault("vulnerabilities", [])

    for target in targets:
        name = target["name"]
        version = target["version"]
        bom_ref = f"{name}@{version}"

        if bom_ref in [comp["bom-ref"] for comp in sbom["components"]]:
            print(f"# component {bom_ref} already in SBOM, skipping")
            continue

        cves = fetch_cves_for_package(name, version)

        component = {
            "bom-ref": bom_ref,
            "type": "library",
            "name": name,
            "version": version,
        }
        sbom["components"].append(component)

        for cve in cves:
            if cve["id"] in {v["id"] for v in sbom["vulnerabilities"]}:
                print(f"# CVE {cve['id']} already in SBOM, skipping")
                continue
            
            vuln = {
                "id": cve["id"],
                "source": {
                    "name": "NVD",
                },
                "ratings": [{
                    "severity": cve["severity"].lower(),
                    "method": "CVSSv2",
                    "score": cve["score"],
                }],
                "affects": [{
                    "ref": bom_ref,
                }],
                "description": cve["description"],
            }
            sbom["vulnerabilities"].append(vuln)

    tools_to_add = [
        {
            "type": "application",
            "name": "add_vulns.py",
        }
    ]
    for tool in tools_to_add:
        if tool["name"] in [t["name"] for t in sbom["metadata"]["tools"]["components"]]:
            continue
        sbom["metadata"]["tools"]["components"].append(tool)

    with open(full_sbom_path, "w") as f:
        json.dump(sbom, f, indent=2)

    print(f"# SBOM with vulnerabilities saved as {full_sbom_path}")

if __name__ == "__main__":
    main()

