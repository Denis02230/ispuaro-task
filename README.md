# ispuaro-task

## Part 1

Everything related to part 1 of the task is in the `source/` folder. A file called `run.py` will generate a SBOM from scratch.

### Dependencies

| Tool | Description | How to Install |
|------|-------------|-----------------|
| [Syft](https://github.com/anchore/syft) | SBOM generator from container images and filesystems | `curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \| sh -s -- -b /usr/local/bin` |
| [cve-bin-tool](https://github.com/intel/cve-bin-tool) | Vulnerability scanner for binaries | `pip install cve-bin-tool` |
| [Python 3](https://www.python.org/) | Required for running helper scripts | Already included on most systems |
| GCC | Is being analysed | `gcc.tar.gz` should be in the script directory |


### How to run

`run.py` assumes `gcc.tar.gz` exists in `source/`, and assumes you have Python3, Syft and CVE Binary Tool installed. It generates a `gcc-sbom.cdx.json` file in the `source/` directory, which is a SBOM in the CycloneDX format containing information about CVEs. To run it:
```
cd /path/to/folder
python3 run.py
```

## Part 2

Everything related to part 2 of the task is in the `binaries/` folder. A file called `run.py` will generate a SBOM from scratch.

### Dependencies
| Tool | Description | How to Install |
|------|-------------|-----------------|
| [Syft](https://github.com/anchore/syft) | SBOM generator | `curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \| sh -s -- -b /usr/local/bin` |
| [Python 3](https://www.python.org/) | Required for running scripts | Already included on most systems |
| GCC Binaries | Is being analysed | `gcc_binaries.tar.gz` should be in the script directory |

### How to run

`run.py` assumes `gcc_binaries.tar.gz` exists in `binaries/`, and assumes you have Python3 (with needed packages installed) and Syft installed. It generates a `gcc-bin-sbom.cdx.json` file in the `binaries/` directory, which is a SBOM in the CycloneDX file containing information about CVEs. To run it:
```
cd /path/to/folder
pip install .
python3 run.py
```
