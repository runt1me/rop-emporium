#!/usr/bin/python
import os
import sys
import subprocess
from pathlib import Path
import shutil

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <path_to_binary>")
        sys.exit(1)

    path_to_binary = sys.argv[1]
    dir_of_binary = os.path.dirname(path_to_binary)

    output_file = os.path.join(dir_of_binary, "analysis.txt")

    shell_commands = [
        f'checksec --file={path_to_binary}',
        f'ROPgadget --binary {path_to_binary}',
        f'gdb -q -batch -ex "info functions" {path_to_binary}',
    ]

    print("[*] Running static analysis commands... ")
    with open(output_file, 'w') as outfile:
        for cmd in shell_commands:
            print(cmd)
            outfile.write("="*24+"\n")
            outfile.write(cmd+"\n")
            outfile.write("="*24+"\n")
            outfile.flush()
            subprocess.run(cmd, stdout=outfile, stderr=subprocess.STDOUT, shell=True)
            outfile.flush()

    print(f"[+] Analysis written to: {output_file}")
    print()

    template_files = Path("/root/tools/rop-emporium/template").glob("*")

    print("[*] Template files:")
    for f in template_files:
        shutil.copy2(f, dir_of_binary)
        print(f)

    print(f"[+] Copied template files into {dir_of_binary}")
    print()

if __name__ == "__main__":
    main()
