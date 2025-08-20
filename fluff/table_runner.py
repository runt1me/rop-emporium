import subprocess
from time import sleep

verbose = True
need_bytes = [
    "66", # b'f'
    "6c", # b'l'
    "61", # b'a'
    "67", # b'g'
    "2e", # b'.'
    "74", # b't'
    "78", # b'x'
]

for i in range(512):
    cmd_string = f'python challenge.py {i} | ./fluff32 | hexdump -C | egrep "ile" | egrep -v "Failed" | tee runner_output_all'
    output = subprocess.check_output(cmd_string, shell=True)

    # Went directory from space to newline; probably a null byte produced
    if b'20 0a' in output:
        if verbose:
            print(f"INPUT: {i:02x} OUTPUT: (probably null)")
    else:
        output_byte = str(output).split("20")[1].split("0a")[0].strip()
        if verbose:
            print(f"INPUT: {i:02x} OUTPUT: {output_byte}")

        if output_byte in need_bytes:
            print(f"Found byte: INPUT: {i:02x} OUTPUT: {output_byte} | {chr(int(output_byte, 16))}")
