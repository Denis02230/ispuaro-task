#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "checking for required files"
REQUIRED_FILES=("gcc_binaries.tar.gz" "add_vulns.py")
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
REQUIRED_COMMANDS=("syft" "python3")
for c in $REQUIRED_COMMANDS; do
    if ! command -v $c &> /dev/null; then
        echo "required command $c not found"
        exit 1
    fi
done

echo "extracting gcc_binaries"
mkdir -p gcc_binaries
tar -xf gcc_binaries.tar.gz -C gcc_binaries

echo "generating a base SBOM with syft"
syft gcc_binaries/ -o cyclonedx-json > .no_cves-gcc-bin-sbom.cdx.json

echo "running add_vulns.py to find and add vulnerabilities to SBOM"
python3 -m mysbomtools_bin.add_vulns .no_cves-gcc-bin-sbom.cdx.json gcc-bin-sbom.cdx.json

echo "cleaning up temporary files"
rm .no_cves-gcc-bin-sbom.cdx.json
