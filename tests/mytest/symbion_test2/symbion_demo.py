import subprocess
import os
import nose
import avatar2 as avatar2

import angr
import claripy
from angr_targets import AvatarGDBConcreteTarget

BINARY_OEP = 0x4009B2
BINARY_DECISION_ADDRESS = 0x400AF3
DROP_STAGE2_V1 = 0x400B87
DROP_STAGE2_V2 = 0x400BB6
VENV_DETECTED = 0x400BC2
FAKE_CC = 0x400BD6
BINARY_EXECUTION_END = 0x400C03
# First set everything up
binary_x86 = './06_angr_symbolic_dynamic_memory'

# project = angr.Project(binary_x86)#, auto_load_libs=False
# start_address = 0x08048623 #0x80486AF
# initial_state = project.factory.blank_state()
# simulation = project.factory.simgr(initial_state)
# exploration = simulation.explore(find=0x80486AF)
# new_concrete_state = exploration.stashes['found'][0]

# Spawning of the gdbserver analysis environment(这里GDB_SERVER_IP和PORT应该要自己设置)
print("gdbserver %s:%s %s" % ("127.0.0.1","9588",binary_x86))
subprocess.Popen("gdbserver %s:%s %s" % ("127.0.0.1","9588",binary_x86),
                 stdout=subprocess.PIPE,
                 stderr=subprocess.PIPE,
                 shell=True)

# Instantiation of the AvatarGDBConcreteTarget
avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86,
                                     "127.0.0.1", "9588")

# Creation of the project with the new attributes 'concrete_target'
project = angr.Project(binary_x86, concrete_target=avatar_gdb,
                 use_sim_procedures=True)
# 从entry开始使用具体执行
entry_state = project.factory.entry_state()
entry_state.options.add(angr.options.SYMBION_SYNC_CLE)
entry_state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)

simgr = project.factory.simgr(entry_state)

simgr.use_technique(angr.exploration_techniques.Symbion(find=[0x080486b6]))
exploration = simgr.run()
new_concrete_state = exploration.stashes['found'][0]

print(new_concrete_state.regs.pc)
# 符号化需要的内存地址
passwd_size_in_bits = 64
passwd0 = claripy.BVS('passwd0', passwd_size_in_bits)
passwd1 = claripy.BVS('passwd1', passwd_size_in_bits)

fake_heap_address0 = 0xffffc93c
pointer_to_malloc_memory_address0 = 0x0A2DEF74
fake_heap_address1 = 0xffffc94c
pointer_to_malloc_memory_address1 = 0xA2DEF7C
new_concrete_state.memory.store(pointer_to_malloc_memory_address0, fake_heap_address0, endness=project.arch.memory_endness)
new_concrete_state.memory.store(pointer_to_malloc_memory_address1, fake_heap_address1, endness=project.arch.memory_endness)

new_concrete_state.memory.store(fake_heap_address0, passwd0)
new_concrete_state.memory.store(fake_heap_address1, passwd1)


simgr = project.factory.simgr(new_concrete_state)
find_addr = [0x8048772,0x8048775,0x804877a,0x804877f]
# exploration.explore(find=0x8048775, avoid=0x08048760)

flag = 1
input()
while simgr.active and flag == 1:
    simgr = simgr.step()
    for state in simgr.active:
        address = state.solver.eval(state.regs.eip)
        # var1 = state.solver.eval(state.regs.esp)
        solution0 = state.solver.eval(passwd0, cast_to=bytes)
        # info = state.memory.load(pointer_to_malloc_memory_address0,8)
        print("eip ==> {}, var1 ==> {}".format(hex(address),solution0))
        if address == 0x8048772:
            end_state = state
            flag = 0
            break
    print("\n")
solution0 = end_state.solver.eval(passwd0, cast_to=bytes)
solution1 = end_state.solver.eval(passwd1, cast_to=bytes)
print("[+] Success! Solution is: {0} {1}".format(solution0.decode('utf-8'), solution1.decode('utf-8')))

