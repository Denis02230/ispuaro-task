import argparse, subprocess, os, re
from pathlib import Path

PATHS = {
    "libc.so.6": "/lib/x86_64-linux-gnu/libc.so.6",
    "libz.so.1": "/lib/x86_64-linux-gnu/libz.so.1",
    "libgfortran.so.5": "/usr/lib/x86_64-linux-gnu/libgfortran.so.5",
    "libquadmath.so.0": "/usr/lib/x86_64-linux-gnu/libquadmath.so.0",
    "libgcc_s.so.1": "/lib/x86_64-linux-gnu/libgcc_s.so.1",
}

version_patterns = [
    re.compile(r"GNU C Library.*?version (\d+\.\d+)"),
    re.compile(r"(\d+\.\d+\.\d+)"),
]

def get_lib_name(so_name):
    mapping = {
        "libc.so.6": "glibc",
        "libm.so.6": "glibc",
        "libz.so.1": "zlib",
        "ld-linux.so.2": "ld-linux",
        "ld-linux-x86-64.so.2": "ld-linux",
    }
    if not so_name in mapping:
        return so_name
    return mapping[so_name]

def run_cmd(cmd):
    return subprocess.run(cmd, capture_output=True, text=True).stdout

def get_lib_path(lib_name):
    output = run_cmd(["ldconfig", "-p"])
    for line in output.splitlines():
        if lib_name in line:
            match = re.search(r"=>\s+(\S+)", line)
            if not match is None:
                return match.group(1)
    
    return None

def extract_version(path):
    try:
        output = run_cmd(["strings", path])
        for pattern in version_patterns:
            match = pattern.search(output)
            if not match is None:
                return match.group(1)
    except:
        return None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("gcc_binaries_path")
    args = parser.parse_args()

    all_libs = set()
    gcc_bin_dir = Path(args.gcc_binaries_path)

    for binary in gcc_bin_dir.glob("*"):
        try:
            ldd_out = run_cmd(["ldd", str(binary)])
            for line in ldd_out.splitlines():
                match = re.search(r"\s*(\S+\.so\S*)", line)
                if not match is None:
                    all_libs.add(match.group(1))
        except: pass

    results = {}
    for lib in sorted(all_libs):
        path = get_lib_path(lib)
        if not path: continue

        version = extract_version(path)
        if not version: continue

        results[lib] = version
    
    targets = []
    seen = set()

    for so_name, version in results.items():
        name = get_lib_name(os.path.basename(so_name))
        if name not in seen:
            targets.append(f"{name}:{version}")
            seen.add(name)
    
    print(" ".join(targets))

if __name__ == "__main__":
    main()
