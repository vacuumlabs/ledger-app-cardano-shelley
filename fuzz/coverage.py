import os
import platform
import subprocess
from glob import glob


def extract_profiles(corpus_path, cov_executable):
    """ Run corpus through coverage executable.  This function 
    avoids a limitation on filename length on Windows """
    # group by packs of N for faster execution
    # N has to be low enough that Windows does not
    # complain about too long filenames. 512 seems fine.
    file_list = glob(os.path.join(corpus_path, "*"))
    N = 512
    for p in range(0, len(file_list), N):
        subprocess.run([cov_executable, "-close_fd_mask=1", *file_list[p : p + N]])


def merge_profile_data():
    """ Merge profiling data """
    print(
        subprocess.run(
            [
                "llvm-profdata",
                "merge",
                "-sparse",
                "*.profraw",
                "-o",
                "default.profdata",
            ],
            check=True,
        )
    )


def show_summary(cov_executable):
    """ Displays the main report from llvm-cov """
    print(
        subprocess.run(
            ["llvm-cov", "report", "--instr-profile=default.profdata", cov_executable]
        )
    )


def create_report(cov_executable):
    """ Create a report in HTML format into 'coverage/index.html' """
    print(
        subprocess.run(
            [
                "llvm-cov",
                "show",
                cov_executable,
                "--instr-profile=default.profdata",
                "--format=html",
                "-o",
                "./coverage/",
            ]
        )
    )


if __name__ == "__main__":
    from argparse import ArgumentParser

    argp = ArgumentParser()
    argp.add_argument("-path", default="./build/", help="Path to build directory")
    args = argp.parse_args()

    cov = os.path.join(
        args.path, "fuzzer_coverage" + ".exe" * (platform.system() == "Windows")
    )

    if not os.path.exists(cov):
        raise Exception(f"Fuzzer executable ({cov}) cannot be found")

    extract_profiles("./corpus/", cov)
    merge_profile_data()
    show_summary(cov)
    create_report(cov)
