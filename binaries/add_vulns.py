import argparse, json, requests, time

def is_version_affected(version_end: str, glibc_ver: str) -> bool:
    try:
        return float(version_end) >= float(glibc_ver)
    except ValueError:
        return False

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("no_cve_sbom_path")
    parser.add_argument("full_sbom_path")
    args = parser.parse_args()

    no_cve_sbom_path = args.no_cve_sbom_path
    full_sbom_path = args.full_sbom_path

    max_pages = 200
    res_per_page = 20
    cves = []

    glibc_ver = "2.40"
    """
    found by:
    1) `ldd gcc_binaries/binary1` contained `libc.so.6 => /lib64/libc.so.6`
    2) `strings /lib64/libc.so.6 | grep -i "version "` contained `GNU C Library (GNU libc) stable release version 2.40.`
    """

    print(f"# trying to fetch CVEs for glibc {glibc_ver}")
    for page in range(1, max_pages + 1):
        print(f"## looking through page {page}")
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "keywordSearch": "glibc",
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
                            if is_version_affected(version_end, glibc_ver):
                                cves.append({
                                    "id": cve_id,
                                    "description": cve_data["descriptions"][0]["value"],
                                    "score": cve_data["metrics"]["cvssMetricV2"][0]["cvssData"]["baseScore"],
                                    "severity": cve_data["metrics"]["cvssMetricV2"][0]["baseSeverity"],
                                })
                                found_match = True
                                print(f"## found vulnerability, versionEndIncluding was {version_end} >= {glibc_ver}")
                                break
                        except KeyError:
                            pass

                if found_match:
                    break

        if cves:
            break

        time.sleep(15)

    if cves:
        print(f"# found {len(cves)} CVEs for glibc {glibc_ver}")
    else:
        print(f"# didn't find CVEs for glibc {glibc_ver} :(")

    with open(no_cve_sbom_path) as f:
        sbom = json.load(f)

    sbom.setdefault("components", [])
    sbom.setdefault("vulnerabilities", [])

    glibc_comp = {
        "bom-ref": f"glibc@{glibc_ver}",
        "type": "library",
        "name": "glibc",
        "version": glibc_ver,
    }
    sbom["components"].append(glibc_comp)

    for cve in cves:
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
                "ref": f"glibc@{glibc_ver}",
            }],
            "description": cve["description"],
        }
        sbom["vulnerabilities"].append(vuln)

    with open(full_sbom_path, "w") as f:
        json.dump(sbom, f, indent=2)

    print(f"# SBOM with vulnerabilities saved as {full_sbom_path}")

if __name__ == "__main__":
    main()
