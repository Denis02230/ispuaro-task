import argparse, json

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("no_cve_sbom_path")
    parser.add_argument("cve_path")
    parser.add_argument("full_sbom_path")
    args = parser.parse_args()

    no_cve_sbom_path = args.no_cve_sbom_path
    cve_path = args.cve_path
    full_sbom_path = args.full_sbom_path

    with open(no_cve_sbom_path, "r") as f:
        sbom = json.load(f)

    with open(cve_path, "r") as f:
        cves = json.load(f)

    components = sbom["components"]
    temp = []
    for vuln in cves:
        product = vuln["product"]
        version = vuln["version"]
        if not (product in [comp["name"] for comp in components]):
            temp.append(product)
            components.append({
                "bom-ref": f"{product}@{version}",
                "type": "library",
                "name": product,
                "version": version,
            })
    print(f"# added {len(temp)} new components to SBOM")

    sbom["vulnerabilities"] = []
    for vuln in cves:
        bom_ref = None
        for comp in components:
            if comp["name"] == vuln["product"]:
                bom_ref = comp["bom-ref"]
                break
        if not bom_ref:
            continue
        sbom["vulnerabilities"].append({
            "id": vuln["cve_number"],
            "source": {
                "name": vuln["source"],
            },
            "ratings": [{
                "severity": vuln["severity"].lower(),
                "score": float(vuln["score"]),
            }],
            "affects": [{
                "ref": bom_ref,
            }],
        })

    tools_to_add = [
        {
            "type": "application",
            "author": "intel",
            "name": "cve-bin-tool",
            "version": "3.4",
        },
        {
            "type": "application",
            "name": "merge.py",
        }
    ]

    for tool in tools_to_add:
        sbom["metadata"]["tools"]["components"].append(tool)

    with open(full_sbom_path, "w") as f:
        json.dump(sbom, f, indent=2)

    print(f"# added {len(sbom['vulnerabilities'])} vulnerabilities to SBOM and saved it to {full_sbom_path}")

if __name__ == "__main__":
    main()
