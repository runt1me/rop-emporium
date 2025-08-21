import subprocess
from time import sleep

verbose = True
need_bytes = [
    "66", # b'f'    b'\x6c\x6c\x6c\x6c'
    "6c", # b'l'    b'\xdd\x06\x00\x00'
    "61", # b'a'    b'\x46\x5d\x00\x00'
    "67", # b'g'    b'\x5a\x4b\x00\x00'
    "2e", # b'.'    b'\xdb\x05\x00\x00'
    "74", # b't'    b'\x01\x7f\x7f\x7f'
    "78", # b'x'    b'\x01\xbd\x01\x01'
    "74"  # b't'    b'\x01\x7f\x7f\x7f'
]

for j in range(4):
    for i in range(256):
        cmd_string = f'python challenge.py {i} {j} | ./fluff32 | hexdump -C | egrep "ile" | egrep -v "Failed" | tee runner_output_all'
        output = subprocess.check_output(cmd_string, shell=True)
    
        # Went directory from space to newline; probably a null byte produced
        if b'20 0a' in output:
            if verbose:
                print(f"INPUT: {i:02x} byte_pos:{j} OUTPUT: (probably null)")
        else:
            output_byte = str(output).split("20")[1].split("0a")[0].strip()
            if verbose:
                print(f"INPUT: {i:02x} byte_pos:{j} OUTPUT: {output_byte}")
    
            if output_byte in need_bytes:
                print(f"Found byte: INPUT: {i:02x} byte_pos:{j} OUTPUT: {output_byte} | {chr(int(output_byte, 16))}")
