import os,pickle,ctypes,json
from ..util import my_debug_log
def read_from_shm_json(config,c_lib,vtor):
    '''
    used to read data from shared memory
    '''
    emulation_handler_serialized_data = None
    
        # read from shared memory file
        # os.walk get include shared_memory.txt
    shm_file = None
    for root, dirs, files in os.walk(os.path.dirname(config["binary_file"])):
        for file in files:
            if file.endswith(".json"):
                shm_file = os.path.join(root, file)
                break
    emulation_handler_serialized_data = json.load(open(shm_file, "r"))
    irq_dt_set = emulation_handler_serialized_data["irq_dt_set"]
    main_dt_set = emulation_handler_serialized_data["main_dt_set"]
    fill_global_datatracker_array(c_lib,main_dt_set,irq_dt_set,vtor)
    # call c function to save irq_dt_set and main_dt_set
    my_debug_log("Shared memory is read")
    my_debug_log("Recover dt hooks complete")

def convert_to_ctypes(dt_object):
    from .data_tracker import StructDataTracker
    dt = StructDataTracker()
    dt.dr=0 if dt_object['dr'] is None else dt_object['dr']
    dt.callread_pc=0 if dt_object['callread_pc'] is None else dt_object['callread_pc']
    dt.read_pc=0 if dt_object['read_pc'] is None else dt_object['read_pc']
    dt.buffer_addr=0 if dt_object['buffer_addr']  is None else dt_object['buffer_addr']
    dt.irq_pc=0 if dt_object['irq_pc'] is None else dt_object['irq_pc']
    dt.avail_pc=0 if dt_object['avail_pc'] is None else dt_object['avail_pc']
    dt.rx_head=0 if dt_object['rx_head'] is None else dt_object['rx_head']
    dt.rx_tail=0 if dt_object['rx_tail'] is None else dt_object['rx_tail']
    dt.buffer_len=0 if dt_object['buffer_len'] is None else dt_object['buffer_len']
    dt.buffer_min_len=0 if dt_object['buffer_min_len'] is None else dt_object['buffer_min_len']
    dt.consume_count=0 if dt_object['consume_count'] is None else dt_object['consume_count']
    return dt

def fill_global_datatracker_array(c_lib,main_dt_set,irq_dt_set,vtor):
    for i, get_dt in enumerate(main_dt_set):
    # Assuming convert_to_ctypes returns a properly populated StructDataTracker instance
        dt = convert_to_ctypes(get_dt)
        res = c_lib.fill_data_tracker_main_dt_array(dt.dr,dt.callread_pc,dt.read_pc,dt.buffer_addr,dt.irq_pc,dt.avail_pc,dt.rx_head,dt.rx_tail,dt.buffer_len,dt.buffer_min_len,dt.consume_count)
        if res != 0:
            my_debug_log("fill_data_tracker_array error")
            return
        else:
            my_debug_log("fill_data_tracker_array success")
    for i, get_dt in enumerate(irq_dt_set):
        
        dt = convert_to_ctypes(get_dt)
        res = c_lib.fill_data_tracker_irq_dt_array(dt.dr,dt.callread_pc,dt.read_pc,dt.buffer_addr,dt.irq_pc,dt.avail_pc,dt.rx_head,dt.rx_tail,dt.buffer_len,dt.buffer_min_len,dt.consume_count,vtor)
        if res != 0:
            my_debug_log("fill_data_tracker_array error")
            return
        else:
            my_debug_log("fill_data_tracker_array success")
            
from capstone import Cs, CS_ARCH_ARM, CS_MODE_MCLASS, CS_MODE_THUMB
cs = Cs(CS_ARCH_ARM, CS_MODE_MCLASS|CS_MODE_THUMB)
from unicorn.arm_const import UC_ARM_REG_PC
def _hook_instruction(uc, address, size, user_data):
    '''
    dump instruction disassembly and log. 
    Used if globs.debug_level > 2.
    '''
    curpc = uc.reg_read(UC_ARM_REG_PC)
    mem = uc.mem_read(address, size)
    for (cs_address, cs_size, cs_mnemonic, cs_opstr) in cs.disasm_lite(bytes(mem), size):
        my_debug_log
        ("    Instr: {:#016x}:\t{}\t{}".format(address, cs_mnemonic, cs_opstr))
        my_debug_log(f"    PC: {curpc:#016x}")
        # head_offset = uc.mem_read(536872044,2)
        # head_offset = int.from_bytes(head_offset,byteorder='little')
        # my_debug_log(f"head_offset: {head_offset:#x}")
        # tail_offset = uc.mem_read(536872046,2)
        # tail_offset = int.from_bytes(tail_offset,byteorder='little')
        # my_debug_log(f"tail_offset: {tail_offset:#x}")
    # if address == 0x80042ba:
    #     from unicorn.arm_const import UC_ARM_REG_R0
    #     r1 = uc.reg_read(UC_ARM_REG_R0+1)
    #     r2 = uc.reg_read(UC_ARM_REG_R0+2)
    #     charc = uc.mem_read(r1+r2,4)
    #     my_debug_log(f"r1: {r1:#x}")
    #     my_debug_log(f"r2: {r2:#x}")
    #     my_debug_log(f"charc: {charc}")
    #     dr = 0x4000

def _hook_irq_function(uc, address, size, user_data):
    '''
    hook irq function. 
    '''
    my_debug_log(f"irq function: {address:#x}")
    my_debug_log(f"irq function: {size:#x}")
    my_debug_log