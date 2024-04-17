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
from unicorn.arm_const import UC_ARM_REG_PC,UC_ARM_REG_IPSR
def _hook_instruction(uc, address, size, user_data):
    '''
    dump instruction disassembly and log. 
    Used if globs.debug_level > 2.
    '''
    curpc = uc.reg_read(UC_ARM_REG_PC)
    mem = uc.mem_read(address, size)
    ipsr = uc.reg_read(UC_ARM_REG_IPSR)
    # 执行代码块
    # 执行代码
    for (cs_address, cs_size, cs_mnemonic, cs_opstr) in cs.disasm_lite(bytes(mem), size):
        my_debug_log
        ("    Instr: {:#016x}:\t{}\t{}".format(address, cs_mnemonic, cs_opstr))
    my_debug_log(f"function:{user_data} PC: {curpc:#016x} IPSR: {ipsr:#x}")


def my_add_hooks(uc):
    '''
    Add hooks to the emulator.
    '''
    from unicorn import UC_HOOK_CODE
    uc.hook_add(UC_HOOK_CODE, _hook_instruction, "spi_stm32_isr",0x800a85c,0x800a87e)
    # uc.hook_add(UC_HOOK_CODE, _hook_instruction, "uart_stm32_isr",0x800ab40,0x800ab48)



def _hook_irq_function(uc, address, size, user_data):
    '''
    hook irq function. 
    '''
    my_debug_log(f"irq function: {address:#x}")
    my_debug_log(f"irq function: {size:#x}")
    
def hook_fuzzware_bugs(uc, address, size, user_data):
    from .fuzzware_hook_folder import cve3319,cve3320,cve3321,cve3322,cve3323,cve3329,cve3330,cve10064,cve10065,cve10066
    cve3319.on_CVE_2021_3319(uc)
    
