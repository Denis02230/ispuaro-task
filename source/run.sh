mkdir -p gcc
tar -xf gcc.tar.gz -C gcc

syft gcc -o cyclonedx-json > .no_cves-gcc-sbom.cdx.json

cve-bin-tool -f json -o .cves.json

python3 merge.py .no_cves-gcc-sbom.cdx.json .cves.json gcc-sbom.cdx.json

rm .no_cves-gcc-sbom.cdx.json
rm .cves.json
