import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
STEPS = [
    "bench_handshake.py",
    "bench_scaling.py",
    "bench_robustness.py",
    "bench_throughput.py",
    "bench_longrun.py",
    "make_tables.py",
    "make_figures.py",
]


def main():
    for s in STEPS:
        print("=" * 62)
        print("running", s)
        print("=" * 62)
        r = subprocess.run([sys.executable, os.path.join(HERE, s)], cwd=HERE)
        if r.returncode != 0:
            sys.exit(r.returncode)
    print("all experiments completed")


if __name__ == "__main__":
    main()
