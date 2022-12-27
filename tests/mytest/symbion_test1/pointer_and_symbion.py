import angr
import claripy
import sys
import pyvex
import archinfo
import unittest
import re
from queue import Queue
import avatar2 as avatar2
from angr_targets import AvatarGDBConcreteTarget
import subprocess
from angr import options

ALLOC_MEMORY = 0xffffc000
symbolic_list = []
symbolic_addr = []
symbolic_value = []
my_symbolic_bit = []
my_symbolic_addr = []
my_symbolic_addr_value = []

# my_target_addr = []
def get_variables(state):
    global symbolic_list, symbolic_addr
    symbolic_list.append(state.inspect.symbolic_expr)
    symbolic_addr.append(str(state.inspect.symbolic_expr))
    print("set new symbolic var ==> " ,state.inspect.symbolic_expr)

def parse_pointer(level_index,pointer_list,next_level_pointer_list):
    global my_symbolic_addr, my_symbolic_addr_value
    index = 0
    while pointer_list:
        delete_index = []
        tmp = pointer_list[0]
        # print("[+] tmp addr ==> {}".format(hex(tmp)))
        # [print(hex(i)) for i in my_symbolic_addr]
        # print("\n")
        # [print(hex(i)) for i in my_symbolic_addr_value]
        for i in range(len(my_symbolic_addr)):
            # print("[+] parse addr => {}".format(hex(my_symbolic_addr[i])))
            if my_symbolic_addr[i] - tmp <= 0x100 and my_symbolic_addr[i] - tmp >= 0: # 设置内存地址偏移小于0x100,根据实际情况可以修改
                if my_symbolic_addr_value[i] & 0x80000000 == 0x80000000:
                    print("level {} node {}, offset {} is pointer".format(level_index-1,index,hex(my_symbolic_addr[i] - tmp)))
                    next_level_pointer_list.append(my_symbolic_addr_value[i])
                    # print("[+]pointer is ==> {}".format(hex(my_symbolic_addr_value[i])))
                else:
                    print("level {} node {}, offset {} is constant, value {}".format(level_index-1,index,hex(my_symbolic_addr[i] - tmp),hex(my_symbolic_addr_value[i])))
                delete_index.append(i)
        del pointer_list[0]
        index += 1
        # print(delete_index)
        for i in range(len(delete_index)):
            delete_index[i] -= i
        for index in delete_index:
            del my_symbolic_addr[index],my_symbolic_addr_value[index]
def recover_struct():
    global my_symbolic_addr, my_symbolic_addr_value
    level1 = [] # 一级指针内存信息
    level2 = []
    level3 = []
    level4 = []
    level5 = [] # 五级指针内存信息
    level6 = []
    level7 = []
    level1.append(ALLOC_MEMORY)
    parse_pointer(1,level1,level2)
    parse_pointer(2,level2,level3)
    parse_pointer(3,level3,level4)
    parse_pointer(4,level4,level5)
    parse_pointer(5,level5,level6)
    parse_pointer(6,level6,level7)


def repair_list(): # 对某个地址信息被分割开的情况进行重组.可优化
    delete_index = []
    global my_symbolic_bit, my_symbolic_addr, my_symbolic_addr_value
    # [print(i) for i in my_symbolic_bit]
    # [print(hex(i)) for i in my_symbolic_addr]
    # [print(hex(i)) for i in my_symbolic_addr_value]
    for i in range(len(my_symbolic_bit)):
        if my_symbolic_addr[i] == 0x7fff0000:
            delete_index.append(i)
        if my_symbolic_addr[i] & 0xf0000000 == 0 and my_symbolic_addr_value == 0 and my_symbolic_bit[i] > 32:
            print(my_symbolic_bit[i])
            delete_index.append(i)
        if my_symbolic_bit[i] < 32 and my_symbolic_addr[i] & 0xf0000000 == 0xf0000000 and my_symbolic_bit[i] + my_symbolic_bit[i+1] == 32: # 符号化范围小于32bit,同时是一个地址,避免某个地址是一个常量且符号花的范围小于32
            tmp = (my_symbolic_addr_value[i+1] << my_symbolic_bit[i]) + my_symbolic_addr_value[i]
            print(hex(my_symbolic_bit[i]))
            print(hex(my_symbolic_addr_value[i+1]))
            if tmp & 0xf0000000 == 0xf0000000: # 保证重组之后的值是一个地址
                my_symbolic_addr_value[i] = tmp
                my_symbolic_bit[i] = 32
                delete_index.append(i+1)
    print(delete_index)
    for i in range(len(delete_index)):
        delete_index[i] = delete_index[i] - i
    for i in delete_index:
        del my_symbolic_addr_value[i], my_symbolic_addr[i], my_symbolic_bit[i]
    [print(i) for i in my_symbolic_bit]
    [print(hex(i)) for i in my_symbolic_addr]
    [print(hex(i)) for i in my_symbolic_addr_value]


def main():
    global my_symbolic_bit, my_symbolic_addr, my_symbolic_addr_value, my_target_addr
    path_to_binary = "./main1"

    print("gdbserver %s:%s %s" % ("127.0.0.1","9588",path_to_binary))
    subprocess.Popen("gdbserver %s:%s %s" % ("127.0.0.1","9588",path_to_binary),
                 stdout=subprocess.PIPE,
                 stderr=subprocess.PIPE,
                 shell=True)
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86,
                                         "127.0.0.1", "9588")
    # Creation of the project with the new attributes 'concrete_target'
    project = angr.Project(path_to_binary,
                           concrete_target=avatar_gdb,
                           # support_selfmodifying_code=True,
                           use_sim_procedures=True,
                           page_size=0x1000)
    # 从entry开始使用具体执行

    entry_state = project.factory.blank_state(
        addr=0x080491B6,
        add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
    )

    # entry_state = project.factory.entry_state()
    # entry_state = project.factory.entry_state()
    # entry_state.options.add(angr.options.SYMBION_SYNC_CLE)
    # entry_state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)
    simgr = project.factory.simgr(entry_state)
    simgr.use_technique(angr.exploration_techniques.Symbion(find=[0x080491CE]))
    exploration = simgr.run()
    new_concrete_state = exploration.stashes['found'][0]

    new_concrete_state.options.update(options.common_options)

    # initial_state.inspect.b('address_concretization', when = angr.BP_AFTER, action=show_constraint_addr)
    # symbolic mother Identification
    bss_addr = 0x0804B2B4
    fake_heap_addr = ALLOC_MEMORY
    new_concrete_state.memory.store(bss_addr,fake_heap_addr,endness=project.arch.memory_endness)
    new_concrete_state.inspect.b('symbolic_variable', when=angr.BP_AFTER, action=get_variables)
    new_concrete_state.project.concrete_target = None
    is_successful = 0x08049281

    simulation = project.factory.simgr(new_concrete_state)


    # simulation.use_technique(angr.exploration_techniques.DFS())
    # while simulation.active:
    #     simulation = simulation.step()
    #     for i in simulation.active:
    #         addr = i.solver.eval(i.regs.eip)
    #         print("[+] eip ==> {}".format(hex(addr)))
    simulation.explore(find=is_successful)
    if simulation.found:
        print("[+] success find target!")
        for i in simulation.found:
            solution_state = i
            for index in range(len(symbolic_list)):
                solution = solution_state.solver.eval(symbolic_list[index])
                int_value = solution_state.solver.eval
                if re.findall(r"mem_(.+?)_",symbolic_addr[index]):
                    print("[+] {0}".format(symbolic_list[index]))
                    print("[+] solve value ==> {0}".format(hex(solution)))
                    print("[+] find addr ==> {0}".format(hex(int(re.findall(r"mem_(.+?)_",symbolic_addr[index])[0],16))))
                    my_symbolic_bit.append(int(re.findall(r"BV(.+?) ",symbolic_addr[index])[0]))
                    my_symbolic_addr.append(int(re.findall(r"mem_(.+?)_",symbolic_addr[index])[0],16))
                    my_symbolic_addr_value.append(solution)

    else:
        raise Exception('Could not find the solution')

    repair_list()
    recover_struct()

if __name__ == '__main__':
    main()

