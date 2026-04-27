import subprocess
from pathlib import Path
import shutil


# ---------------------------
# Helper
# ---------------------------
def ensure_installed(command_name):
    if shutil.which(command_name) is None:
        raise RuntimeError(f"{command_name} is not installed or not in PATH")


# ---------------------------
# Cppcheck
# ---------------------------
def run_cppcheck(files, output_dir="outputs"):
    ensure_installed("cppcheck")

    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)

    output_file = output_path / "cppcheck_output.xml"

    cmd = ["cppcheck", "--xml", "--enable=all"] + files

    with open(output_file, "w", encoding="utf-8") as f:
        subprocess.run(cmd, stdout=subprocess.PIPE, stderr=f, text=True)

    return str(output_file)


# ---------------------------
# Flawfinder
# ---------------------------
def run_flawfinder(files, output_dir="outputs"):
    ensure_installed("flawfinder")

    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)

    output_file = output_path / "flawfinder_output.txt"

    cmd = ["flawfinder"] + files

    with open(output_file, "w", encoding="utf-8") as f:
        subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, text=True)

    return str(output_file)


# ---------------------------
# GCC Analyzer
# ---------------------------
def run_gcc_analyzer(files, output_dir="outputs"):
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)

    output_file = output_path / "gcc_output.txt"

    all_output = []

    for file in files:
        compiler = "g++" if file.endswith(".cpp") else "gcc"
        ensure_installed(compiler)

        cmd = [compiler, "-fanalyzer", "-c", file]

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        all_output.append(f"\n===== {file} =====\n")
        all_output.append(result.stdout)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("".join(all_output))

    return str(output_file)


# ---------------------------
# Coverity (basic)
# ---------------------------
def run_coverity(files, output_dir="outputs"):
    ensure_installed("cov-build")
    ensure_installed("cov-analyze")
    ensure_installed("cov-format-errors")

    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)

    cov_dir = output_path / "coverity_tmp"
    report_file = output_path / "coverity_output.txt"

    cov_dir.mkdir(exist_ok=True)

    build_cmd = ["cov-build", "--dir", str(cov_dir), "gcc", "-c"] + files
    subprocess.run(build_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    analyze_cmd = ["cov-analyze", "--dir", str(cov_dir)]
    subprocess.run(analyze_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    format_cmd = ["cov-format-errors", "--dir", str(cov_dir)]

    with open(report_file, "w", encoding="utf-8") as f:
        subprocess.run(format_cmd, stdout=f, stderr=subprocess.STDOUT, text=True)

    return str(report_file)


# ---------------------------
# Dispatcher
# ---------------------------
def run_tool(tool, files):
    if tool == "cppcheck":
        return run_cppcheck(files)

    elif tool == "flawfinder":
        return run_flawfinder(files)

    elif tool == "gcc_analyzer":
        return run_gcc_analyzer(files)

    elif tool == "coverity":
        return run_coverity(files)

    else:
        raise ValueError(f"Unsupported tool: {tool}")