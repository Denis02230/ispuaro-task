mkdir -p gcc
tar -xf gcc.tar.gz -C gcc

syft gcc -o cyclonedx-json > .no_cves-gcc-sbom.cdx.json

python3 add_components.py -i .no_cves-gcc-sbom.cdx.json -s gcc/

cve-bin-tool -f json -o .cves.json gcc

CVEBINTOOL_VERSION=$(cve-bin-tool --version | head -n 1 | awk '{print $1}')
GCC_VERSION=$(gcc --version | head -n 1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)

python3 merge.py .no_cves-gcc-sbom.cdx.json .cves.json gcc-sbom.cdx.json $CVEBINTOOL_VERSION $GCC_VERSION

rm .no_cves-gcc-sbom.cdx.json
rm .cves.json
