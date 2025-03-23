mkdir -p gcc_binaries
tar -xf gcc_binaries.tar.gz -C gcc_binaries

syft gcc_binaries/ -o cyclonedx-json > .no_cves-gcc-bin-sbom.json

python3 add_vulns.py .no_cves-gcc-bin-sbom.json gcc-bin-sbom.json

rm .no_cves-gcc-bin-sbom.json
