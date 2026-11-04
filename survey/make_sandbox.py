"""Create survey/sandbox: the files the survey fixtures read.

    python survey/make_sandbox.py

- notes.txt: 2 lines
- big.txt: 20,000 lines ("line number N"), ~350 KB
- sub/: 300 empty files
"""

import os

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sandbox")


def main() -> None:
    os.makedirs(os.path.join(ROOT, "sub"), exist_ok=True)
    with open(os.path.join(ROOT, "notes.txt"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("hello\nworld\n")
    with open(os.path.join(ROOT, "big.txt"), "w", encoding="utf-8", newline="\n") as fh:
        fh.writelines(f"line number {i}\n" for i in range(1, 20001))
    for i in range(1, 301):
        open(os.path.join(ROOT, "sub", f"file_{i}.txt"), "w").close()
    print(f"sandbox ready at {ROOT}")


if __name__ == "__main__":
    main()
