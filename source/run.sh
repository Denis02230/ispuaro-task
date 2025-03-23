#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "checking for required files"
REQUIRED_FILES=("gcc.tar.gz" "add_components.py" "merge.py")
for f in $REQUIRED_FILES; do
    if [ ! -f $f ]; then
        echo "required file $f not found in current working directory"
        if [ -f $SCRIPT_DIR/$f ]; then
            echo "however, it exists in $SCRIPT_DIR. you should run the script from there."
        fi
        exit 1
    fi
done

echo "checking for required commands"
REQUIRED_COMMANDS=("syft" "python3" "cve-bin-tool")
for c in $REQUIRED_COMMANDS; do
    if ! command -v $c &> /dev/null; then
        echo "required command $c not found"
        exit 1
    fi
done

echo "extracting gcc"
mkdir -p gcc
tar -xf gcc.tar.gz -C gcc

echo "generating a base SBOM with syft"
syft gcc -o cyclonedx-json > .no_cves-gcc-sbom.cdx.json

echo "running add_components.py to add more components to SBOM"
python3 -m mysbomtools.add_components -i .no_cves-gcc-sbom.cdx.json -s gcc/

echo "generating a vulnerabilities JSON with cve-bin-tool"
cve-bin-tool -f json -o .cves.json gcc

CVEBINTOOL_VERSION=$(cve-bin-tool --version | head -n 1 | awk '{print $1}')
GCC_VERSION=$(gcc --version | head -n 1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)

echo "running merge.py to add vulnerabilities to SBOM"
python3 -m mysbomtools.merge .no_cves-gcc-sbom.cdx.json .cves.json gcc-sbom.cdx.json $CVEBINTOOL_VERSION $GCC_VERSION

echo "cleaning up temporary files"
rm .no_cves-gcc-sbom.cdx.json
rm .cves.json
