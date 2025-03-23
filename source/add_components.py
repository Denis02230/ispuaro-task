import argparse, json, re
from pathlib import Path

def extract_components(root: Path):
    components = []
    for sub in root.iterdir():
        if sub.is_dir() and sub.name.startswith("lib"):
            name = sub.name
            version = None
            print(f"# found component {sub}")

            fpath = sub / "configure.ac"
            if fpath.exists():
                text = fpath.read_text(errors="ignore")
                match = re.search(r'AC_INIT\s*\(\s*\[?[\w\-]+]?\s*,\s*\[?([0-9][^,\]\) ]+)', text)
                if match:
                    version = match.group(1)
                    print(f"# found version {version} in {fpath}")

            if not version: version = "unknown"
            components.append({
                "bom-ref": f"{name}@{version}",
                "type": "library",
                "name": name,
                "version": version,
            })
    
    return components

def main():
    parser = argparse.ArgumentParser(description="Adds missing GCC components to a CycloneDX SBOM file.")
    parser.add_argument("-i", "--input", required=True, help="Path to CycloneDX SBOM file")
    parser.add_argument("-s", "--source", required=True, help="Path to GCC source directory")

    args = parser.parse_args()
    sbom_path = Path(args.input)
    gcc_dir = Path(args.source)

    with open(sbom_path) as f:
        sbom = json.load(f)

    new_components = extract_components(gcc_dir)
    components_to_add = [c for c in new_components if c["name"] not in {c["name"] for c in sbom.get("components", [])}]

    if "components" not in sbom: sbom["components"] = []
    sbom["components"].extend(components_to_add)
    print(f"# added {len(components_to_add)} components")

    with open(sbom_path, "w") as f:
        json.dump(sbom, f, indent=2)

if __name__ == "__main__":
    main()
