# 00_angr_find
注意angr运行时提示的基址，要与逆向工具的基址设置一致。
![[Pasted image 20210405001152.png]]
## ida修改基址
![[Pasted image 20210405001408.png]]
https://blog.csdn.net/hgy413/article/details/5856827
## Ghidra设置基址
![[Pasted image 20210405001758.png]]
https://bbs.pediy.com/thread-257290.htm
# 05\_angr\_symbolic\_memory
![[Pasted image 20210404224203.png]]

由于我的机器上编译出来的二进制，在访问内存数据的时候通过[EBP+0xabcd]进行访问的，所以在处理state的时候需要给EBP赋值，当ebp被占用时也可能使用其他寄存器
![[Pasted image 20210404224521.png]]

```python
an1 = claripy.BVS("an1",64)  
an2 = claripy.BVS("an2",64)  
an3 = claripy.BVS("an3",64)  
an4 = claripy.BVS("an4",64)  
  
an1_addr = 0x11a54a0 # 0x11a54a0  
an2_addr = 0x11a54a8 # 0x11a54a8  
an3_addr = 0x11a54b0 # 0x11a54b0  
an4_addr = 0x11a54b8 # 0x11a54b8  
# 字符化存储在 对应地址  
init_state.memory.store(an1_addr, an1)  
init_state.memory.store(an2_addr, an2)  
init_state.memory.store(an3_addr, an3)  
init_state.memory.store(an4_addr, an4)  
init_state.regs.ebx = 0x404000  
  
sm = p.factory.simgr(init\_state)
```

# 07\_angr\_symbolic\_file
angr_ctf模版是基于angr6的, angr9没有simsymbolicmemory/
参考https://jasper.la/posts/angr-9-simfile-without-simsymbolicmemory/
符号化文件的blank_state地址是在open文件之前不同于前面的在scanf之后

