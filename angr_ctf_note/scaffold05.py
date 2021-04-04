# -*- encoding: utf-8 -*-
from __future__ import print_function
'''
@文件        :angr_exp.py
@时间        :2020/04/24 10:52:30
@作者        :0xc4m3l
'''
import angr
import sys
import claripy

def main(argv):
    bin_patch = "05_angr_symbolic_memory"
    p = angr.Project(bin_patch)

    start_addr = 0x4012fe
    init_state = p.factory.blank_state(addr = start_addr)
    # 值为 %8s 大小为 64  8个字节  8*8 = 64
    an1 = claripy.BVS("an1",64)
    an2 = claripy.BVS("an2",64)
    an3 = claripy.BVS("an3",64)
    an4 = claripy.BVS("an4",64)

    an1_addr = 0x11a54a0  # 0x11a54a0
    an2_addr = 0x11a54a8  # 0x11a54a8
    an3_addr = 0x11a54b0  # 0x11a54b0
    an4_addr = 0x11a54b8  # 0x11a54b8
    # 字符化存储在 对应地址
    init_state.memory.store(an1_addr, an1)
    init_state.memory.store(an2_addr, an2)
    init_state.memory.store(an3_addr, an3)
    init_state.memory.store(an4_addr, an4)
    init_state.regs.ebx = 0x404000

    sm = p.factory.simgr(init_state)

    def is_good(state):
        return b"Good Job" in state.posix.dumps(1)

    def is_bad(state):
        return b"Try again" in state.posix.dumps(1)

    sm.explore(find=is_good, avoid=is_bad)

    if sm.found:
        found_state = sm.found[0]
        # 得到的结果需要转为 字符 bytes 且进行转码
        password1 = found_state.solver.eval(an1,cast_to=bytes).decode("utf-8")
        password2 = found_state.solver.eval(an2,cast_to=bytes).decode("utf-8")
        password3 = found_state.solver.eval(an3,cast_to=bytes).decode("utf-8")
        password4 = found_state.solver.eval(an4,cast_to=bytes).decode("utf-8")
        print("Solver : {} {} {} {}".format(password1, password2, password3, password4))
    else:
        raise Exception("no found")

if __name__ == "__main__":
    main(sys.argv)
