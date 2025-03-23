# ispuaro-task

## Part 1

Everything related to part 1 of the task is in the `source/` folder. All the commands used to generate the final SBOM are compiled into `source/run.sh`.

### How to run

`run.sh` assumes `gcc.tar.gz` exists in `source/`, and assumes you have Python3, Syft and CVE Binary Tool installed. It generates a `gcc-sbom.cdx.json` file in the `source/` directory, which is a SBOM in the CycloneDX file containing information about CVEs.

## Part 2

Everything related to part 2 of the task is in the `binaries/` folder. All the commands used to generate the final SBOM are compiled into `binaries/run.sh`.

### How to run

`run.sh` assumes `gcc_binaries.tar.gz` exists in `binaries/`, and assumes you have Python3 (with `requests` installed) and Syft installed. It generates a `gcc-bin-sbom.cdx.json` file in the `bin/` directory, which is a SBOM in the CycloneDX file containing information about CVEs.
