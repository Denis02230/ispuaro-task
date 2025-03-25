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
        self.check_installed()
        print(f"-- running Syft on {self.input_dir}")
        with open(self.output_file, "w") as f:
            subprocess.run(["syft", self.input_dir, "-o", "cyclonedx-json"], stdout=f, check=True)
        print(f"-- Syft output written to {self.output_file}")

class AddVulns(Script):
    def __init__(self, sbom_input_path, sbom_output_path, targets):
        self.sbom_input_path = sbom_input_path
        self.sbom_output_path = sbom_output_path
        self.targets = targets
        self.script_path = "mysbomtools_bin/add_vulns.py"

    def run(self):
        print(f"-- running add_vulns.py with targets: {self.targets}")
        subprocess.run([
            "python3", "-m", "mysbomtools_bin.add_vulns",
            self.sbom_input_path, self.sbom_output_path,
            "--targets", *self.targets.split()
        ], check=True)

class PrintInfo(Script):
    def __init__(self, sbom_path):
        self.sbom_path = sbom_path
        self.script_path = "mysbomtools_bin/print_info.py"

    def run(self):
        subprocess.run(["python3", "-m", "mysbomtools_bin.print_info", self.sbom_path], check=True)

def extract_tarball(tar_path, dest_dir):
    print(f"-- extracting {tar_path} into {dest_dir}")
    os.makedirs(dest_dir, exist_ok=True)
    with tarfile.open(tar_path) as tar:
        tar.extractall(dest_dir)
    print(f"-- finished extracting")

def find_libs(gcc_binaries_dir):
    print(f"-- running mysbomtools_bin.find_libs on {gcc_binaries_dir}")
    libs = subprocess.check_output(["python3", "-m", "mysbomtools_bin.find_libs", gcc_binaries_dir])
    return libs.decode().strip()

def main():
    required_files = ["gcc_binaries.tar.gz"]
    for f in required_files:
        if not Path(f).is_file():
            raise FileNotFoundError(f"required file {f} not found in working directory.")

    tools = (
        Syft("gcc_binaries", "gcc-bin-sbom.cdx.json"),
        AddVulns("gcc-bin-sbom.cdx.json", "gcc-bin-sbom.cdx.json", find_libs("gcc_binaries")),
        PrintInfo("gcc-bin-sbom.cdx.json"),
    )

    for tool in tools: tool.check_installed()

    extract_tarball("gcc_binaries.tar.gz", "gcc_binaries")

    for tool in tools: tool.run()

    print(f"-- script completed")

if __name__ == "__main__":
    main()
