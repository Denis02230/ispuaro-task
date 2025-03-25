import os, subprocess, sys, tarfile, shutil
from pathlib import Path

class Tool:
    def check_installed(self):
        raise NotImplementedError

    def run(self):
        raise NotImplementedError

class Script(Tool):
    def check_installed(self):
        file = self.script_path
        if not Path(file).is_file():
            raise FileNotFoundError(f"required file {file} not found in working directory.")

class Syft(Tool):
    def __init__(self, input_dir, output_file):
        self.input_dir = input_dir
        self.output_file = output_file

    def check_installed(self):
        if not shutil.which("syft"):
            raise RuntimeError("Syft is not installed")

    def run(self):
        print(f"-- running Syft on {self.input_dir}")
        with open(self.output_file, "w") as f:
            subprocess.run(["syft", self.input_dir, "-o", "cyclonedx-json"], stdout=f, check=True)
        print(f"-- Syft output written to {self.output_file}")

class CVEBinTool(Tool):
    def __init__(self, input_dir, output_file):
        self.input_dir = input_dir
        self.output_file = output_file

    def check_installed(self):
        if not shutil.which("cve-bin-tool"):
            raise RuntimeError("cve-bin-tool is not installed")

    def run(self):
        print(f"-- running CVE-Bin-Tool on {self.input_dir}")
        subprocess.run(["cve-bin-tool", "-f", "json", "-o", self.output_file, self.input_dir], check=True)
        print(f"-- CVE-Bin-Tool output written to {self.output_file}")

class AddComponents(Script):
    def __init__(self, input_file, source_dir):
        self.input_file = input_file
        self.source_dir = source_dir
        self.script_path = "mysbomtools/add_components.py"

    def run(self):
        print(f"-- running add_components.py")
        subprocess.run(["python3", "-m", "mysbomtools.add_components", "-i", self.input_file, "-s", self.source_dir], check=True)
        print(f"-- add_components.py added components to {self.input_file}")

class Merge(Script):
    def __init__(self, sbom_input, cve_json, sbom_output, cve_bin_tool_version, gcc_version):
        self.sbom_input = sbom_input
        self.cve_json = cve_json
        self.sbom_output = sbom_output
        self.cve_bin_tool_version = cve_bin_tool_version
        self.gcc_version = gcc_version
        self.script_path = "mysbomtools/merge.py"

    def run(self):
        print(f"-- running merge.py")
        subprocess.run([
            "python3", "-m", "mysbomtools.merge",
            self.sbom_input, self.cve_json, self.sbom_output,
            self.cve_bin_tool_version, self.gcc_version
        ], check=True)
        print(f"-- merge.py output written to {self.sbom_output}")

class PrintInfo(Script):
    def __init__(self, sbom_path):
        self.sbom_path = sbom_path
        self.script_path = "mysbomtools/print_info.py"

    def run(self):
        subprocess.run(["python3", "-m", "mysbomtools.print_info", self.sbom_path], check=True)

def extract_tarball(tar_path, dest_dir):
    print(f"-- extracting {tar_path} into {dest_dir}")
    os.makedirs(dest_dir, exist_ok=True)
    with tarfile.open(tar_path) as tar:
        tar.extractall(dest_dir)
    print(f"-- finished extracting")

def get_versions():
    cve_bin_tool_version = subprocess.check_output(["cve-bin-tool", "--version"]).decode().split()[0]
    gcc_version = subprocess.check_output(["cat", "gcc/gcc/BASE-VER"]).decode().strip()
    gcc_version = next(part for part in gcc_version.split() if part[0].isdigit())
    return cve_bin_tool_version, gcc_version

def main():
    required_files = ["gcc.tar.gz"]
    for f in required_files:
        if not Path(f).is_file():
            raise FileNotFoundError(f"required file {f} not found in working directory.")

    extract_tarball("gcc.tar.gz", "gcc")

    cve_bin_tool_version, gcc_version = get_versions()

    tools = [
        Syft("gcc", ".no_cves-gcc-sbom.cdx.json"),
        AddComponents(".no_cves-gcc-sbom.cdx.json", "gcc/"),
        CVEBinTool("gcc", ".cves.json"),
        Merge(
            ".no_cves-gcc-sbom.cdx.json",
            ".cves.json",
            "gcc-sbom.cdx.json",
            cve_bin_tool_version,
            gcc_version,
        ),
        PrintInfo("gcc-sbom.cdx.json"),
    ]

    for tool in tools: tool.check_installed()

    for tool in tools: tool.run()

    print(f"-- cleaning up temporary files")
    Path(".no_cves-gcc-sbom.cdx.json").unlink(missing_ok=True)
    Path(".cves.json").unlink(missing_ok=True)

    print(f"-- script completed")

if __name__ == "__main__":
    main()
