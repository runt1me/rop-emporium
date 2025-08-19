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
# Choosing 0x0804a050 as my address; more on that later
payload += write_what_where(b'flag', b'\x50\xa0\x04\x08')

```

To write `flag.txt` into memory, we will need to leverage this primitive at least two times. Once to write the first four bytes (`b'flag'`) and once for the second four (`b'.txt'`). I am in the habit of also calling it a third time, to make sure my string is null-terminated (`b'\x00'`) and then I usually write another 3 bytes just for fun, making my third call something like `b'\x00lol'`. Of note, the third call is probably not necessary in my case, as I chose to write data to the `.bss` segment, where almost the whole region of memory is full of null bytes anyways, but I have the third one in there just to be safe.

## Running into the badchars filtering

