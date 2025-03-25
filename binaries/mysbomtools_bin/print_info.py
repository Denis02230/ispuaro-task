import argparse, json
from pathlib import Path

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("sbom_path")
    args = parser.parse_args()
    
    sbom_path = Path(args.sbom_path)
    with open(sbom_path) as f:
        sbom = json.load(f)
    
    components = sbom["components"]
    vulns = sbom["vulnerabilities"]

    print(f"# SBOM summary:")
    print(f"# - components: {len(components)}")
    print(f"# - CVES: {len(vulns)}")

if __name__ == "__main__":
    main()
