mkdir -p gcc_binaries
tar -xf gcc_binaries.tar.gz -C gcc_binaries

syft gcc_binaries/ -o cyclonedx-json > .no_cves-gcc-bin-sbom.cdx.json

python3 add_vulns.py .no_cves-gcc-bin-sbom.cdx.json gcc-bin-sbom.cdx.json

rm .no_cves-gcc-bin-sbom.cdx.json
