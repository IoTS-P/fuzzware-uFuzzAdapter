# usage: the main function that handles the emulation

from unicorn import (
    UC_HOOK_CODE,
    UC_HOOK_MEM_READ,
    UC_HOOK_MEM_READ_AFTER,
    UC_HOOK_MEM_WRITE,
    UC_HOOK_BLOCK,
)
from unicorn.arm_const import (
    UC_ARM_REG_LR,
    UC_ARM_REG_IPSR,
    UC_ARM_REG_PC,
    UC_ARM_REG_R0,
)

from ..exit import do_exit
from ..util import (
    my_debug_log,
    uc_mem_read_offset_four_byte,
    uc_mem_read_offset_one_byte,
)
from .. import globs
from .data_tracker import DataTracker
from .global_var import GlobalVar,find_longest_continuous_segment
from .headless_ghidra import run_ghidra_script
import os, pickle, math ,random, copy
from multiprocessing import shared_memory


class EmulationHandler:
    def __init__(self, uc,ghidra_config, data_regs_list):
        # 配置项
        self.uc = uc
        self.shm_name = ""
        self.ghidra_config = ghidra_config
        self.binary_file = ghidra_config['binary_file']
        self.avail_start_point = None # Save the avail pc which is read firstly by DR
        self.get_data_from_shared_memory = True # 通过返回值确定是否从共享内存中读取数据
        self.port = ghidra_config['port']
        self.begitpoint_hook_handler = None
        self.debug = False
        
        # 寄存器信息
        self.data_regs = data_regs_list
        self.dr_remove_count = 0
        
        # dt相关变量 
        self.avail_read_consume_dt = None # 用于传承avail中的dt到read,consume等函数中
        self.consume_dt_dict = {} # consume-dt
        self.avail_dt_dict = {} # avail-dt
        self.irq_dt_set = set() # irq中的所有dt
        self.main_dt_set = set() # 主程序读的所有dt
        self.tmp_dt = DataTracker()#一个独立的dt对象，用来暂存中断读情况时的数据状态
        self.dt_created_dr = set() #保存所有已经创建过dt类型的dr
        
        #静态脚本相关变量
        self.dynamic_hook_indirect_path = None
        self.global_vars = []
        self.invalid_callreadpc = set()
        
        # 间接调用相关变量
        self.indirectaddr_jumpaddr_map = {}
        self.indirect_remove_count = 0 #检测每轮间接调用的移除数，当某轮少于1时，则移除所有间接调用hook
        self.indirect_src_addrs = [] # 保存所有间接调用的地址
        
        # 头尾指针相关变量
        self.headtail_count = 0
        self.before_tail_val = 0
        self.threshold = 0
        self.changed_vars = []
        self.tmp_list_include_head_tail = []
        self.head_offset_set = set()
        
        # 数据输入相关变量
        self.partion = 0
        self.read_flag = 0 # 使数据放置3轮后再退出
        self.supple_input = 0
        self.escape_flag = False
        self.escape_funcs = []  #用于学习所有越过数据清除点间的所有函数的地址
        self.random_split = {}  #根据buffer大小随机分配每次数据输入长度,以不同的通道划分
        self.last_read_times = 0  

        # Hook相关变量   
        self.buffer_hook = None
        self.head_tail_bufferlen_hook = None
        # self.basicblock_hook = self.uc.hook_add(UC_HOOK_BLOCK, self.hook_func_basicblock)
        self.mem_second_write_hook = None
        self.input_hook = None
        self.buffer_min_len_input = None
        
        # Hook相关字典
        self.avail_pc_hook = {}
        self.mem_global_hook = {}
        self.consume_pc_hook = {}
        self.read_pc_hook = {}
        self.interrupt_dr_hook_dict = {}
        self.indirect_call_hook_map = {}
        self.justify_dr_hook_dict = {}
        
        #计算buffer_len相关变量
        self.round = 0    # 用于估算buffer退出时机的参数
        self.prev_len = 0 # list中最长的元素长度
        self.prev_list_length = 0 # list上一次的长度
        self.addr_list = [] # list
        self.taintdata = None # 用于确定全局变量时的追踪数据
    
        #SR 相关变量
        self.sr_pc_dict = {} #每个SR所对应的PC
        self.sr_dr_route = [] # 保存SR到DR的路径PC
        

        
        # if is debug, then read from shared memory file, so don't need to create shared memory
        if not self.debug:
            from uuid import uuid1
            shm_name = str(uuid1())
            shm = shared_memory.SharedMemory(shm_name,create=True, size=65536)
            globs.shm_name = shm_name
            self.shm_name = shm_name
    
    def recover_shm_and_add_dr_hook(self):
        print("recover_shm_and_add_dr_hook")
        from ..native import get_fuzz
        globs.user_input = get_fuzz(self.uc._uch,64)  # 保存用户输入的数据
        # recover the shared memory
        self.read_from_shared_memory()
        self.get_callind_addr()
        self.hook_all_data_regs()
        
        # 初始化的时候就hook所有的data_regs
        
        
        self.hook_all_indirect_call()
        
        #只用于第一轮，减少开销
        
        if not self.get_data_from_shared_memory:
            self.write_byte_to_data_reg(self.data_regs,[0xBB]*4)
        

    def read_from_shared_memory(self):
        '''
        used to read data from shared memory
        '''
        emulation_handler_serialized_data = None
        
        if self.debug:
            # read from shared memory file
            home_path = os.path.expanduser('~')
            shm_file = os.path.join(home_path, f"ghidra_project/{self.port}_shared_memory.txt")
            if os.path.exists(shm_file):
                with open(shm_file, "rb") as f:
                    emulation_handler_serialized_data = f.read()
            else:
                my_debug_log("Shared memory file is not exist.")
                self.get_data_from_shared_memory = False
                return
        else:
            # read from shared memory
            emulation_handler_existing_shm = shared_memory.SharedMemory(
                name=self.shm_name
            )
            emulation_handler_serialized_data = bytes(emulation_handler_existing_shm.buf[:])
        
        # check if the shared memory is empty
        if emulation_handler_serialized_data == b"\x00" * len(
            emulation_handler_serialized_data
        ):
            my_debug_log("Shared memory is empty or uninitialized.")
            self.get_data_from_shared_memory = False
            return
        
        # recover the data from shared memory
        data_tracker_dict = pickle.loads(emulation_handler_serialized_data)
        self.consume_dt_dict = data_tracker_dict[
            "consume_dt_dict"
        ]
        # recover the variables
        self.indirect_src_addrs = data_tracker_dict["indirect_src_addrs"]
        self.avail_dt_dict = data_tracker_dict["avail_dt_dict"]
        self.data_regs = data_tracker_dict["data_regs"]
        self.irq_dt_set = data_tracker_dict["irq_dt_set"]
        self.main_dt_set = data_tracker_dict["main_dt_set"]
        my_debug_log("Shared memory is read")
        
        # recover the hooks of each dt object
        self._add_all_dt_hooks(self.irq_dt_set)
        self._add_all_dt_hooks(self.main_dt_set)
        self._print_dt()
        self._print_hook_count()
        my_debug_log("Recover dt hooks complete")


    def hook_all_data_regs(self):
        #the self.data_regs may from last round of data
        for dr in self.data_regs:
            # 保留这个dict以防之后使用
            my_debug_log("dr is {}".format(hex(dr)))
            self.justify_dr_hook_dict[dr] = self.uc.hook_add(
                UC_HOOK_MEM_READ_AFTER,
                self.hook_func_data_regs_check,
                begin=dr,
                end=dr,
            )
        
    

    def hook_func_data_regs_check(self, uc, access, address, size, value, user_data):
        my_debug_log(">>> %x dr is read" % address)  # dr被读取
        my_debug_log(">>>  the pc is %x" % uc.reg_read(UC_ARM_REG_PC))  
        
        # 放入一个数据
        self.write_byte_to_data_reg([address],[0xBB])
        
        # 初始化dr
        # self.tmp_dt = DataTracker()
        
        ipsr = uc.reg_read(UC_ARM_REG_IPSR)
        
        #DR在中断里被读
        if ipsr != 0:
            self.tmp_dt.dr = address
            self.tmp_dt.callread_pc = uc.reg_read(UC_ARM_REG_LR)
            #修正由LR带来的偏移
            self.tmp_dt.callread_pc = run_ghidra_script(self.port, ["correct_lr"], [self.tmp_dt.callread_pc])
            my_debug_log("DR in interrupt, the callread_pc is {}".format(hex(self.tmp_dt.callread_pc)))
            
            #删除此处的DR hook
            if self.justify_dr_hook_dict.get(address,None):
                uc.hook_del(self.justify_dr_hook_dict[address])
            if address in self.data_regs:
                self.data_regs.remove(address)
                self.dr_remove_count +=1 
            
            #进入中断处理函数
            self.dr_interrupt_hook_func()
        
        #DR在主程序中被读 
        else:
            my_debug_log("主程序读取的dr")
            pc = uc.reg_read(UC_ARM_REG_PC)
            #这里处理第一次遇到dr read时的情况
            if self.avail_start_point == None:
                self.sr_dr_route.append(pc)
                self.avail_start_point = self.sr_dr_route[0]
            
            #清空dt
            self.tmp_dt = DataTracker()
            
            #对于固件读的情况，callread_pc的初始值先赋予read_pc的值，然后运行脚本
            self.tmp_dt.read_pc = pc
            self.tmp_dt.callread_pc = pc
            self.tmp_dt.dr = address
            
            #运行静态脚本并获得dt实例
            self.get_static_data(uc,self.main_dt_set)
            
            # 现在由静态脚本得到的avail_pc并没有越过SR检查，但是由静态脚本获得了唯一的avail_pc
            # 所以可以通过hook avail点来分别获得SR路径
            # 先清空之前的所有SR路径
            self.sr_dr_route.clear()
            
            #对main_dt中的所有dt加上avail_hook
            for cur_dt in self.main_dt_set:
                if cur_dt.avail_pc == None or self.avail_pc_hook.get(cur_dt.avail_pc,None):
                    continue 
                my_debug_log("avail_pc = :%s,add the sr_avail hook for it" % cur_dt.avail_pc)
                self.avail_pc_hook[cur_dt.avail_pc] = self.uc.hook_add(
                    UC_HOOK_CODE,
                    self.hook_func_sr_add_avail,
                    begin=cur_dt.avail_pc,
                    end=cur_dt.avail_pc,
                )                    
                # #放入数据
                # self.write_byte_to_data_reg([cur_dt.dr],[0xBB])
            
            #当所有的avail_pc都更新后，删除该DR_hook
            uc.hook_del(self.justify_dr_hook_dict[address])
            if self.data_regs and address in self.data_regs:
                self.data_regs.remove(address)
                self.dr_remove_count +=1 


    def hook_func_sr_add_avail(self,uc,address,size,user_data):
        my_debug_log(">>> hook_func_SR_add_avail")
        #放入数据
        dt = self.avail_dt_dict.get(address, None)
        if dt == None:
            my_debug_log("error,the SR_add_avail_hook dt is None")
            do_exit(-1)
            
        self.write_byte_to_data_reg([dt.dr],[0xBB])
        
        self.sr_dr_route.append(dt.avail_pc)
        #如果前面有SR,则将最前面的SR作为avail_pc,否则仍将保留原avail_pc
        tmp_avail_pc = dt.avail_pc
        dt.avail_pc = self.sr_dr_route[0]   
        my_debug_log("--the avail_pc is {}".format(hex(dt.avail_pc)))
        
        #清除最近的SR_HOOK
        if len(self.sr_dr_route) > 1:
            my_debug_log("--the avail_pc is become the sr read pc, which is {}".format(hex(dt.avail_pc)))
            my_debug_log("delete the sr successful, now the justify_sr_hook_dict is {}".format(self.justify_sr_hook_dict))
            uc.hook_del(self.justify_sr_hook_dict[self.sr_pc_dict[self.sr_dr_route[-2]]])      

        #如果avail_pc发生了改变,则更新avail_dt_dict，否则不更新
        if tmp_avail_pc != dt.avail_pc:
            #更新avail-dt dict
            del self.avail_dt_dict[tmp_avail_pc]
            
            #假如新的avail_pc已存在对应的值，将地址往前偏移2个单位(为确保avail_pc的唯一性，但方案有待测试)
            while self.avail_dt_dict.get(dt.avail_pc):
                my_debug_log("*****************Warning:the avail key {} is conflict, try to minus the address".format(hex(dt.avail_pc)))
                dt.avail_pc -= 2    

            #更新avail-dt字典
            self.avail_dt_dict[dt.avail_pc] = dt
                            
            #如果更新后的avail_pc没有对应的hook,则删除原来的avail_hook，并添加新的
            if not self.avail_pc_hook.get(dt.avail_pc,None):        
                uc.hook_del(self.avail_pc_hook[tmp_avail_pc])
                self.add_avail_hook(dt)
                
        #否则需要将hook重定向到hook_func_avail_pc函数  
        else:        
            uc.hook_del(self.avail_pc_hook[dt.avail_pc])
            self.avail_pc_hook.pop(dt.avail_pc)
            self.add_avail_hook(dt)
                                
        #清空sr_route
        self.sr_dr_route.clear()
    
    
    #用于处理中断函数的程序
    def dr_interrupt_hook_func(self):
        from ..nvic import out_vtor

        my_debug_log(">>> hook_dr_interrupt")
        ipsr_val = self.uc.reg_read(UC_ARM_REG_IPSR)
        my_debug_log("ipsr_val:%s" % (hex(ipsr_val)))
        nvic_base_addr = out_vtor(0)
        PTR_SIZE = 4
        # 计算中断向量表中的地址
        handler_addr = nvic_base_addr + (ipsr_val * PTR_SIZE)
        
        self.tmp_dt.irq_pc = uc_mem_read_offset_four_byte(self.uc, handler_addr) - 1
        my_debug_log(">>>dr_interrupt_hook: irq_pc:{}".format(hex(self.tmp_dt.irq_pc)))
        # 得到irq_pc后，去获取间接调用信息，删除hook，并添加hook获取readpc和callreadpc

        # 设置read和write的hook获得readpc和bufferaddr
        self.read_hook = self.uc.hook_add(
            UC_HOOK_MEM_READ_AFTER, self.hook_func_all_memread, begin=0, end=0xFFFFFFFF
        )
        self.write_hook = self.uc.hook_add(
            UC_HOOK_MEM_WRITE, self.hook_func_all_memwrite, begin=0, end=0xFFFFFFFF
        )
        self.write_byte_to_data_reg([self.tmp_dt.dr],[0xBB] * 10)

    def get_callind_addr(self):
        result = run_ghidra_script(
            self.port, ["callind_collect"]
        )
        for indir_addr in result:
            self.indirect_src_addrs.append(int(indir_addr, 16))
    
    def hook_all_indirect_call(self):
        my_debug_log("the indirect count = {}".format(len(self.indirect_src_addrs)))
        for indir_addr in self.indirect_src_addrs:
            self.indirect_call_hook_map[indir_addr] = self.uc.hook_add(
                UC_HOOK_CODE,
                self.hook_func_indirect_addr_call,
                begin=indir_addr,
                end=indir_addr,
            )
        
    def hook_func_indirect_addr_call(self, uc, address, size, user_data):
        my_debug_log(
            ">>> enter the indirect hook, the src address is {}".format(hex(address))
        )
        home_path = os.path.expanduser("~")
        # 打印r0-r1
        self.dynamic_hook_indirect_path = os.path.join(
            home_path, f"ghidra_project/{self.port}_dynamic_hook_indirect_addr.txt"
        )
        # 调用capstone框架反汇编当前指令，并提取寄存器。并使用memread读取寄存器的值
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_MCLASS, CS_MODE_THUMB

        cs = Cs(CS_ARCH_ARM, CS_MODE_MCLASS | CS_MODE_THUMB)
        pc = uc.reg_read(UC_ARM_REG_PC)
        mem = uc.mem_read(pc, size)
        try:
            for cs_address, cs_size, cs_mnemonic, cs_opstr in cs.disasm_lite(bytes(mem), size):
                my_debug_log(
                    ">>> Indirect Call: addr= 0x%x, size=0x%x, data=0x%x, pc=0x%x, %s %s"
                    % (
                        address,
                        size,
                        uc_mem_read_offset_four_byte(uc, address),
                        pc,
                        cs_mnemonic,
                        cs_opstr,
                    )
                )
                
                if cs_mnemonic == "blx" or cs_mnemonic == "bx":
                    my_debug_log(">>> indirect cs_mnemonic: %s" % cs_mnemonic)
                    # 打印出来是r0-r15，则需要匹配unicorn中的常量并memread它，比如cs_opstr是r0-r1，则需要memread(UC_ARM_REG_R0)和memread(UC_ARM_REG_R1)
                    register = cs_opstr
                    register_num = int(register[1:])
                    register_value = uc.reg_read(UC_ARM_REG_R0 + register_num)
                    my_debug_log("Register %s: %s" % (register_num, hex(register_value)))
                    # 从字符串中提取寄存器
                    if hex(register_value).startswith("0xffff"):
                        my_debug_log("not effective address!")
                        continue
                    self.indirectaddr_jumpaddr_map[address] = register_value
                    with open(self.dynamic_hook_indirect_path, "w") as f:
                        my_debug_log(" %s: %s will be written" % (address, hex(register_value)))
                        f.write(str(self.indirectaddr_jumpaddr_map))

                    # 移除间接调用hook和map中的值
                    uc.hook_del(self.indirect_call_hook_map[address])
                    self.indirect_call_hook_map.pop(address)
                    
                    #indirect 移除数 + 1
                    self.indirect_remove_count += 1
                    my_debug_log("the indirect_remove_count = {}".format(self.indirect_remove_count))

                elif cs_mnemonic == "tbb" or cs_mnemonic == "tbh":
                        my_debug_log(">>> indirect cs_mnemonic: %s" % cs_mnemonic)
                        import re
                        #   tbb        [pc,r3] 处理这样的指令，提取出r3，再获得它的值
                        register = re.search(r'r(\d+)',cs_opstr).group()
                        my_debug_log("register:{}".format(register))
                        register_num = int(register[1:])
                        register_value = uc.reg_read(UC_ARM_REG_R0 + register_num)
                        register_value = register_value + pc
                        self.indirectaddr_jumpaddr_map[address] = register_value
                        with open(self.dynamic_hook_indirect_path, "w") as f:
                            my_debug_log(" %s: %s will be written" % (address, hex(register_value)))
                            f.write(str(self.indirectaddr_jumpaddr_map))

                        # 移除间接调用hook和map中的值
                        uc.hook_del(self.indirect_call_hook_map[address])
                        self.indirect_call_hook_map.pop(address)
                        
                        #indirect 移除数 + 1
                        self.indirect_remove_count += 1
                        my_debug_log("the indirect_remove_count = {}".format(self.indirect_remove_count))
                        
                else:
                    my_debug_log("Indirect match failed ,return")   
                    return
                    
        except Exception as e:
            my_debug_log(">>> exception: %s" % e)


    #该函数的主要作用是最终结算buffer长度
    def compute_bufferlen(self,uc):
        if self.tmp_dt == None:
            my_debug_log(">>>hook_func_all_memread: dt not in datatracker_dict")
            do_exit(-1)
            
        #取出暂存队列中的最长的，即为buffer长度
        if not self.tmp_dt.buffer_len:
            cur_max_len = len(max(self.addr_list, key=lambda x: len(x)))
            self.tmp_dt.buffer_len = cur_max_len
            my_debug_log("the buffer_len = {}".format(self.tmp_dt.buffer_len))
            
        #取出暂存队列中的最长的首地址，即为buffer首地址    
        if not self.tmp_dt.buffer_addr:
            longest_seq = max(self.addr_list, key=lambda x: len(x))
            self.tmp_dt.buffer_addr = longest_seq[0]
            my_debug_log("the buffer_addr = {}".format(hex(self.tmp_dt.buffer_addr)))
            
        if not self.buffer_hook:    
            self.buffer_hook = uc.hook_add(
                UC_HOOK_MEM_READ,
                self.hook_func_bufferaddr_get_readpc,
                begin=self.tmp_dt.buffer_addr,
                end=self.tmp_dt.buffer_addr,
            )    
        
        #清空参数
        self.round = 0
        self.prev_list_length
        self.prev_len = 0 
        self.addr_list.clear()
        
        # 删除hook
        if self.write_hook:
            uc.hook_del(self.write_hook)
        if self.read_hook:
            uc.hook_del(self.read_hook)
        
        
    # 该函数的主要作用即是获取buffer地址和buffer长度
    def hook_func_all_memwrite(self, uc, access, address, size, value, user_data):
        if value == self.taintdata:
            
            pc = uc.reg_read(UC_ARM_REG_PC)
            my_debug_log(">>> Write: addr= %x  data=%x (pc %x)" % (address, value, pc))
            ipsr = uc.reg_read(UC_ARM_REG_IPSR)
            my_debug_log("current addr_list = {}".format(self.addr_list))
            if ipsr != 0:
                if len(self.addr_list):
                    #满足连续的情况
                    cur_max_len = len(max(self.addr_list, key=lambda x: len(x)))
                    condition1 = cur_max_len == self.prev_len
                    condition2 = len(self.addr_list) * 2 < self.round
                    # condition = condition1 and condition2
                    
                    if condition1 and cur_max_len >= 4:
                        #若列表中的元素在最长元素长度大于4的时候仍在上涨，并且最长元素此时已不再增长时，则考虑是否已经到达buffer上限
                        if self.prev_list_length < len(self.addr_list):
                            my_debug_log("the list is still increasing,over")
                            self.compute_bufferlen(uc)
                        else:
                            self.round += 2
                    
                    if condition2:
                        self.compute_bufferlen(uc)
                        return
                    
                    self.prev_list_length = len(self.addr_list)
                    my_debug_log("round = {}".format(self.round))
                    
                    for index in range(len(self.addr_list)):
                        #跳过所有已经存在且重复的
                        if len(self.addr_list[index]) == 1 and self.addr_list[index][0] == address:
                            my_debug_log("skip repeat element = {}".format(address))
                            return
                        
                        #满足address等于尾+1的连续情况
                        elif self.addr_list[index][-1] + 1 == address:
                            # if len(self.addr_list[index]) == cur_max_len:
                            my_debug_log("add new contiounus element = {}".format(address))
                            self.write_byte_to_data_reg([self.tmp_dt.dr],[0xBB])
                            self.addr_list[index].append(address)
                            self.prev_len = len(max(self.addr_list, key=lambda x: len(x)))
                            self.round = 0
                            
                            if self.prev_len >= 4 and self.buffer_hook == None:
                                buffer_head_addr = self.addr_list[index][0]
                                my_debug_log("the buffer_head_addr is got by longest judge = {}".format(hex(buffer_head_addr)))
                                self.tmp_dt.buffer_addr = buffer_head_addr
                                self.buffer_hook = uc.hook_add(
                                    UC_HOOK_MEM_READ,
                                    self.hook_func_bufferaddr_get_readpc,
                                    begin=buffer_head_addr,
                                    end=buffer_head_addr,
                                )                                
                            break
                        
                        #满足address等于头的情况
                        elif self.addr_list[index][0] == address and len(self.addr_list[index]) > 1:
                            my_debug_log("the element come back to head= {}".format(address))
                            self.compute_bufferlen(uc)
                            return

                        #都不满足，则作为新情况，建立新的list重新计算
                        elif index == len(self.addr_list) - 1:
                            my_debug_log("add new list {}".format(address))
                            self.write_byte_to_data_reg([self.tmp_dt.dr],[0xBB])
                            sub_l = [address]
                            self.addr_list.append(sub_l)
                            self.round += 1 / len(self.addr_list)
                            my_debug_log("self.round = {}".format(self.round))
                            break
                        
                #若为第一次，则直接加入队列
                else:
                    sub_l = [address]
                    self.addr_list.append(sub_l)
                    self.round += 1 / len(self.addr_list)
                    my_debug_log("self.addr_list = {}".format(self.addr_list))        
                
            else:
                # 位于主函数后，移除write hook
                my_debug_log("主函数中写入数据")
                uc.hook_del(self.write_hook)
    
    def hook_func_all_memread(self, uc, access, address, size, value, user_data):
        if address == self.tmp_dt.dr:
            self.taintdata = value
            if self.read_hook:
                uc.hook_del(self.read_hook)

    # 该函数的主要作用是获取buffer的头尾指针
    def hook_func_bufferaddr_get_readpc(self, uc, access, address, size, value, user_data):
        if self.prev_len!= 0 and self.tmp_dt.buffer_len == 0:
            #prev_len存在并且prev_len +1属于2的n次方，且此时并未获得buffer_len,则认为buffer_len = prev_len + 1
            test_len = self.prev_len + 1
            condition = test_len > 0 and (test_len & (test_len - 1)) == 0
            if self.tmp_dt.buffer_len == 0 and condition:
                my_debug_log(">>>buffer_len may not be computed before,but it is probably = {}".format(test_len))
                self.tmp_dt.buffer_len = test_len
                self.compute_bufferlen(uc)
        
        my_debug_log(">>>hook_func_bufferaddr_get_readpc: buffer_addr {} is read".format(hex(address)))
        
        self.tmp_dt.callread_pc = uc.reg_read(UC_ARM_REG_LR)
        self.tmp_dt.callread_pc = run_ghidra_script(self.port, ["correct_lr"], [self.tmp_dt.callread_pc])
        
        if self.tmp_dt.callread_pc in self.invalid_callreadpc:
            return
        
        self.tmp_dt.read_pc = uc.reg_read(UC_ARM_REG_PC)
        my_debug_log("now the readpc and callreadpc = {},{}".format(hex(self.tmp_dt.read_pc),hex(self.tmp_dt.callread_pc)))

        #运行静态脚本      
        self.get_static_data(uc,self.irq_dt_set)

        avail_pc = None
        
        
        #如果是中断读的情况，则需要添加consume_hook以求buffer下限
        
        for cur_dt in self.irq_dt_set:
            avail_pc = cur_dt.avail_pc
            self.buffer_min_len_input = uc.hook_add(
                UC_HOOK_CODE,
                self.hook_func_got_buffer_min_len,
                begin = avail_pc,
                end = avail_pc,
            )
                
        #添加avail点hook作为试探buffer下限的放数据起点
        if len(self.irq_dt_set):
            if avail_pc == None:
                avail_pc = self.tmp_dt.callread_pc
                self.buffer_min_len_input = uc.hook_add(
                    UC_HOOK_CODE,
                    self.hook_func_got_buffer_min_len,
                    begin = avail_pc,
                    end = avail_pc,
                )
        else:
            self.invalid_callreadpc.add(self.tmp_dt.callread_pc)
            return                
        
        # 如果已经拿到dt，再添加获取头尾指针和buffer长度hook
        if not self.head_tail_bufferlen_hook:
            self.head_tail_bufferlen_hook = uc.hook_add(
                UC_HOOK_CODE,
                self.hook_func_get_head_tail_bufferlen,
                begin = self.tmp_dt.read_pc,
                end = self.tmp_dt.read_pc,
            )                    
    
            

                
    def hook_func_get_head_tail_bufferlen(self, uc, address, size, user_data):
        my_debug_log(">>>> get headtail")
        def change_vars(self):
            self.changed_vars = [
                var for var in self.changed_vars if var.value_changed(uc)
            ]
            for var in self.changed_vars:
                my_debug_log(
                    "var.address: %s,var.value:%d" % (hex(var.address), var.value)
                )

        # 读取head和tail的时候，记录head和tail的值

        my_debug_log("pid:%d" % os.getpid())
        
        change_vars(self)
        get_head_tail_flag = False
        
        if len(self.changed_vars) == 0:
            my_debug_log("0 variables changed")
            global_vars = self.read_global_vars_file(uc)
            self.changed_vars = global_vars
            # 通过全局变量的数量/4得到判断阈值
            self.threshold = len(global_vars) // 4
            self.write_byte_to_data_reg([self.tmp_dt.dr],[0xBB])
            
        elif len(self.changed_vars) == 1:
            my_debug_log("only 1 variables changed")
            if self.tmp_dt.rx_head == None:
                my_debug_log("rx_head == None only 1 global variable")
                my_debug_log("failed to get head and tail pointer,come to the end")
                get_head_tail_flag = True
                
                
            # 只有read的情况下tail会变化
            if self.tmp_dt.rx_tail != self.changed_vars[0].address:
                self.tmp_dt.rx_head,self.tmp_dt.rx_tail = self.tmp_dt.rx_tail,self.tmp_dt.rx_head
                # my_debug_log("rx_head: %s,rx_tail:%s" % (hex(self.tmp_dt.rx_head), hex(self.tmp_dt.rx_tail)))
                get_head_tail_flag = True
            
        elif len(self.changed_vars) == 2:
            my_debug_log("only 2 variables changed")
            addr1 = self.changed_vars[0].address
            addr2 = self.changed_vars[1].address
            if addr1 > addr2:
                self.tmp_dt.rx_tail = addr1
                self.tmp_dt.rx_head = addr2
            else:
                self.tmp_dt.rx_tail = addr2
                self.tmp_dt.rx_head = addr1
            get_head_tail_flag = True
                
            #将头尾指针的结果写入irq的所有dt中 (或者等最后退出前的写入)
            # for cur_dt in self.irq_dt_set:
            #     if cur_dt.rx_head == None:
            #         cur_dt.rx_head = self.tmp_dt.rx_head
            #     if cur_dt.rx_tail == None:
            #         cur_dt.rx_tail = self.tmp_dt.rx_tail
        
        else:
            my_debug_log("more than 2 variables changed")
            if self.headtail_count < self.threshold:
                self.write_byte_to_data_reg([self.tmp_dt.dr],[0xBB])
            else:
                addresses = []
                for var in self.changed_vars:
                    addresses.append(var.address)
                close_addresses = []
                for i in range(len(addresses)):
                    for j in range(i+1, len(addresses)):
                        addr1 = addresses[i]
                        addr2 = addresses[j]
                        if abs(addr1 - addr2) <= 16:
                            if addresses[i] not in close_addresses:
                                close_addresses.append(addresses[i])
                            if addresses[j] not in close_addresses:
                                close_addresses.append(addresses[j])
                sub_address = set(addresses)-set(close_addresses)
                for var in self.changed_vars:
                    if var.address in sub_address:
                        self.changed_vars.remove(var)
                self.write_byte_to_data_reg([self.tmp_dt.dr],[0xBB])


        # 读取第一个字节数据到dr中
        if get_head_tail_flag and self.tmp_dt.buffer_len == None:
            head_offset = uc_mem_read_offset_one_byte(uc, self.tmp_dt.rx_head)
            before_len = len(self.head_offset_set)
            self.head_offset_set.add(head_offset)
            after_len = len(self.head_offset_set)
            my_debug_log(
                "before_len:%d,after_len:%d,head_offset:%d"
                % (before_len, after_len, head_offset)
            )

            if before_len == after_len:
                sorted_head_offset_set = sorted(self.head_offset_set)
                # my_debug_log("sorted_head_offset_set:%s" % sorted_head_offset_set)
                self.tmp_dt.buffer_len = sorted_head_offset_set[-1] + 1
                
                #添加和删除一些与buffer相关的hook,如果是第一轮则在此退出
                self.add_and_delete_hook_before_exit(uc)
 
                
            else:
                #该hook只有当buffer首地址重新为0时才会触发，即buffer被填满后，buffer首地址重新为0
                if self.mem_second_write_hook == None and self.tmp_dt.buffer_len == 0:
                    self.mem_second_write_hook = uc.hook_add(
                        UC_HOOK_MEM_WRITE,
                        self.hook_func_mem_second_write,
                        begin=self.tmp_dt.buffer_addr,
                        end=self.tmp_dt.buffer_addr,
                    )
                    
        elif get_head_tail_flag and self.tmp_dt.buffer_len != None:
            #添加和删除一些与buffer相关的hook,如果是第一轮则在此退出
            self.add_and_delete_hook_before_exit(uc)

    
        # 塞入相同的数据为了把recv全局变量剔除
        self.headtail_count += 1


    #用于buffer结算阶段，用于删除一些已完毕的hook，以及完成在第一轮写入共享内存前的添加hook操作
    def add_and_delete_hook_before_exit(self,uc):
        my_debug_log(">>> add and delete hook before exit")
        #得到数据后，删除此时的hook
        if self.head_tail_bufferlen_hook != None:
            uc.hook_del(self.head_tail_bufferlen_hook)
        
        # 添加hook增加input_offset
        # uc.hook_add(
        #     UC_HOOK_CODE,
        #     self.hook_func_increase_offset_read,
        #     begin=self.tmp_dt.read_pc,
        #     end=self.tmp_dt.read_pc,
        # )
        
        # 如果这种方案拿到了数据，就删除另一种方案的hook
        if self.mem_second_write_hook != None:
            uc.hook_del(self.mem_second_write_hook)

        # 在间接调用补充的情况下，再运行一次静态脚本更新dt数据
        self.get_static_data(uc,self.irq_dt_set)

        # 如果目前是第一轮，则写完后退出。因为第二轮是在avail_hook的位置结束，所以这里只需要处理第一轮的情况
        if self.get_data_from_shared_memory == False:
            my_debug_log("avail_start_poiont = {}".format(self.avail_start_point))
            self._print_dt()
            
            if self.tmp_dt.buffer_min_len != None:
                self.write_to_shared_memory()
                my_debug_log("write to shared memory")
                do_exit(0)
            else:
                #计算buffer下限后再退出
                self.write_byte_to_data_reg([self.tmp_dt.dr],[0xBB])
                #添加上read hook，以防止无法经过avail的情况
                
                self.add_read_hook(self.tmp_dt)
            
    # 用于恢复和更新avail和consume，对象是全体dt
    def _add_all_dt_hooks(self,dt_set):
        my_debug_log(">>> add all dt avail and consume hook")
        
        for cur_dt in dt_set:
            cur_dt.input_offset = cur_dt.consume_count = cur_dt.read_times = 0  #这条仅在恢复共享内存的时候初始化
            # self.add_consume_hook(cur_dt)
            self.add_avail_hook(cur_dt)
            self.add_read_hook(cur_dt)

        my_debug_log("finish recover hook")

    #添加consume hook
    def add_consume_hook(self,cur_dt):
        if cur_dt.consume_pc_set == None:
            return
        for consume_addr in cur_dt.consume_pc_set:
            if self.consume_pc_hook.get(int(consume_addr, 16)):
                continue
            my_debug_log("current consume_addr:%s,add the hook for it" % consume_addr)
            
            consume_addr = int(consume_addr, 16)
            
            #添加consume和dt的映射(映射不一定唯一，但暂用)
            if self.consume_dt_dict.get(consume_addr, None) == None:
                self.consume_dt_dict[consume_addr] = cur_dt
            
            self.consume_pc_hook[consume_addr] = self.uc.hook_add(
                UC_HOOK_CODE,
                self.hook_func_get_consume_count,
                begin=consume_addr,
                end=consume_addr,
            )
    
    def add_avail_hook(self, cur_dt):
        #添加avail hook
        if cur_dt.avail_pc == None or self.avail_pc_hook.get(cur_dt.avail_pc, None):
            my_debug_log("avail_pc == None or the same avail hook is exist!")
            return 
        my_debug_log("avail_pc = :%s,add the hook for it" % cur_dt.avail_pc)
        self.avail_pc_hook[cur_dt.avail_pc] = self.uc.hook_add(
            UC_HOOK_CODE,
            self.hook_func_avail_pc,
            begin=cur_dt.avail_pc,
            end=cur_dt.avail_pc,
        )
    
    #添加read hook
    def add_read_hook(self,cur_dt):
        if cur_dt.read_pc == None or self.read_pc_hook.get(cur_dt.read_pc,None):
            return
        
        self.read_pc_hook[cur_dt.read_pc] = self.uc.hook_add(
            UC_HOOK_CODE,
            self.hook_func_increase_offset_read,
            begin=cur_dt.read_pc,
            end=cur_dt.read_pc,
        )
    
    
    #在此处放入1个数据,用于测试buffer下限
    def hook_func_got_buffer_min_len(self,uc,address,size,user_data):

        my_debug_log(">>> reach the buffer_min_len data point,put 1 data")

        if self.supple_input == 0:
            #清除当前寄存器队列中的缓存数据，以便后续求下限
            from .rule import call_hardware_clear_r_fifo
            call_hardware_clear_r_fifo([self.tmp_dt.dr])
            for cur_dt in self.irq_dt_set:
                self.add_consume_hook(cur_dt)

        self.write_byte_to_data_reg([self.tmp_dt.dr],[0xBB])

        self.supple_input += 1
    
    
    def hook_func_get_consume_count(self, uc, address, size, user_data):
        # 这里既是获取buffer_min_len的hook，也是consume点的pc的hook
        # 现在该函数仅用于获得buffer_min_len
        my_debug_log(">>> hook_func_get_consume_count")
        #删除所有consume_hook,并删除buffer_min_input_avail_hook
        for key in self.consume_pc_hook.keys():
            uc.hook_del(self.consume_pc_hook[key])
    
        uc.hook_del(self.buffer_min_len_input)
        
        my_debug_log("buffer_min_len = {}".format(self.supple_input))
        
        #结算当前的self.tmp_dt.bufffer_min_len
        for cur_dt in self.irq_dt_set:
            cur_dt.buffer_min_len = self.supple_input
            self.tmp_dt.buffer_min_len = self.supple_input
        
        if self.get_data_from_shared_memory == False:
            my_debug_log("avail_start_poiont = {}".format(self.avail_start_point))
            self._print_dt()
            
            if self.tmp_dt.buffer_min_len != None:
                self.write_to_shared_memory()
                my_debug_log("write to shared memory")
                do_exit(0)


    def hook_func_mem_second_write(self, uc, access, address, size, value, user_data):
        my_debug_log("---------------hook_func_mem_second_write-----------------")
        my_debug_log("len(self.head_offset_set):%d" % len(self.head_offset_set))
        
        offset = uc_mem_read_offset_one_byte(uc, self.tmp_dt.rx_head)
        if offset == 0:
            my_debug_log("offset == 0")
            if self.mem_second_write_hook != None:
                uc.hook_del(self.mem_second_write_hook)
            return
        
        #获取到buffer长度
        self.tmp_dt.buffer_len = offset - 1
        my_debug_log("Mem second self.bufferlen:%d" % self.tmp_dt.buffer_len)

        #检查并删除两个头尾指针相关的hook
        if self.head_tail_bufferlen_hook != None:
            uc.hook_del(self.head_tail_bufferlen_hook)
        if self.mem_second_write_hook != None:
            uc.hook_del(self.mem_second_write_hook)

        #进行更新和清理hook的操作
        self.add_and_delete_hook_before_exit(uc)
    
        #如果是第一轮，在此写入共享内存数据并退出
        if self.get_data_from_shared_memory == False:
            
            my_debug_log("avail_start_poiont = {}".format(self.avail_start_point))
            self._print_dt()
            if self.tmp_dt.buffer_min_len != None:
                my_debug_log("write to shared memory")
                self.write_to_shared_memory()
                do_exit(0,9)
            else:
                self.write_byte_to_data_reg([self.tmp_dt.dr],[0xBB])
                self.add_read_hook(self.tmp_dt)
    
    def read_global_vars_file(self, uc):
        global_vars = []
        # 读取全局变量文件，记录所有全局变量地址对应的内存值
        for address in self.global_vars:
            global_vars.append(GlobalVar(uc, address))

        return global_vars

    def hook_func_avail_pc(self, uc, address, size, user_data):
        my_debug_log(">>>> avail_pc_input_point")
    
        dt = self.avail_dt_dict.get(address, None)
        
        if dt == None:
            print(hex(address))
            self._print_dt()
            my_debug_log(">>>hook_func_avail_pc: dt not in datatracker_dict")
            do_exit(-1)

        self.avail_read_consume_dt = dt

        if dt.buffer_addr == None:
            #进入数据输入阶段
            my_debug_log(">>>> now the input_offset is {}".format(dt.input_offset))
            if self.partion >= len(globs.user_input) - 1:
                #假如读次数已满，或所有dt的读次数均为0，或超过3次读取计数后，则退出
                if dt.read_times >= len(globs.user_input)-1 or self.read_flag >= 2 or sum([x.read_times for x in self.main_dt_set]) == 0:
                    my_debug_log("---------------avail_pc_input_point_exit-------------")
                    pid = os.getpid()
                    my_debug_log("pid: %d" % pid)
                    # my_debug_log("Final consume_count: %d" % dt.consume_count)
                    
                    #第一轮退出前,或间接调用有更新时，更新dt
                    if self.get_data_from_shared_memory == False or self.indirect_remove_count > 0:
                        self.tmp_dt.callread_pc = dt.callread_pc 
                        self.tmp_dt.read_pc = dt.read_pc
                        
                        self.get_static_data(uc,self.main_dt_set)
                        my_debug_log("avail_start_poiont = {}".format(self.avail_start_point))
                        self._print_dt()
                    
                    #写入共享内存
                    self.write_to_shared_memory()
                    do_exit(0)
                else:
                    my_debug_log("read_flag = %d" % self.read_flag)
                    self.read_flag += 1 
            
            #如果是第一轮,或该dt已放入数据且已被读过，或所有dt的读次数均为0，则再对其放数据，否则略过
            if self.get_data_from_shared_memory == False or (dt.read_times != 0 and dt.input_offset != 0) or sum([x.read_times for x in self.main_dt_set]) or (dt.read_times == 0 and self.partion == 0): 
                my_debug_log("main dr_read")
                
                partion = self.get_current_partion(dt)
                self.partion += partion
                # need_input = min(len(globs.user_input) - dt.input_offset , partion)
                self.write_byte_to_data_reg(
                    [dt.dr],
                    globs.user_input[dt.input_offset:dt.input_offset + partion]
                )
                dt.input_offset += partion
                my_debug_log("write to data reg,now the input_offset = {}".format(dt.input_offset))
        else:
            #如果不存在消耗点，则该点可能不是有效的数据读入点，删除此处hook
            if dt.consume_pc_set == []:
                my_debug_log( ">>>hook_func_avail_pc: consume_pc_set is empty,this avail point may not effective")
                uc.hook_del(self.avail_pc_hook[address])

            #在遇到buffer_avail_pc,即对应结算中断DR的SR的情况,清理掉离Avail_pc最近的SR
            if len(self.sr_dr_route) > 1:
                my_debug_log("delete the IRQ sr successful, now the justify_sr_hook_dict is {}".format(self.justify_sr_hook_dict))
                uc.hook_del(self.justify_sr_hook_dict[self.sr_pc_dict[self.sr_dr_route[-2]]])
                self.sr_dr_route.clear()
                
            #如果种子长度除以buffer上限小于数据输入点的数量，则也采用均分方式放数据
            # if dt.rx_head == None or dt.rx_tail == None or (math.ceil(len(globs.user_input) / dt.buffer_len) > len(self.irq_dt_set) + len(self.main_dt_set)):
            
            my_debug_log("read times = %d" % dt.read_times)
            
            #第一次放数据，或本次loop放入的数据都消耗完毕后，或发现本次未进行读操作时，或存在头尾指针且相等时，再放下一次数据
            if (dt.read_times == 0 and self.partion == 0) or (dt.read_times != 0 and dt.read_times % self.partion == 0) or (self.last_read_times == dt.read_times) or (dt.rx_head != None and dt.rx_tail != None and dt.rx_head == dt.rx_tail):
            
                if dt.input_offset < len(globs.user_input):
                    partion = self.get_current_partion(dt)
                    self.partion += partion            
                    dt.input_offset += self.fill_data(dt,partion)
            
            self.last_read_times = dt.read_times
            
            if self.partion >= len(globs.user_input) - 1:
                #假如读次数已满，或所有dt的读次数均为0，或超过3次读取计数后，则退出
                if dt.read_times >= len(globs.user_input)-1 or self.read_flag >= 3 or sum([x.read_times for x in self.irq_dt_set]) == 0:
                    my_debug_log("---------------offset_is_finished_exit-------------")
                    pid = os.getpid()
                    my_debug_log("pid: %d" % pid)
                    if self.indirect_remove_count > 0:
                        self.tmp_dt.callread_pc = dt.callread_pc
                        self.tmp_dt.read_pc = dt.read_pc
                        if dt.buffer_addr:
                            self.tmp_dt.buffer_addr = dt.buffer_addr
                        if dt.irq_pc:
                            self.tmp_dt.irq_pc = dt.irq_pc
    
                        self.get_static_data(uc,self.irq_dt_set)
                    
                    self.write_to_shared_memory()
                    my_debug_log("Final consume_count: %d" % dt.consume_count)
                    do_exit(0)                        
                else:
                    my_debug_log("read_flag = %d" % self.read_flag)
                    self.read_flag += 1   
                        
            #否则按照buffer长度放数据
            # else:
            #     head_offset = uc_mem_read_offset_one_byte(uc, dt.rx_head) % dt.buffer_len
            #     tail_offset = uc_mem_read_offset_one_byte(uc, dt.rx_tail) % dt.buffer_len
            #     my_debug_log("head_offset: %d, tail_offset: %d" % (head_offset, tail_offset))
            #     my_debug_log("input offset = %d" % dt.input_offset)
            #     self.before_tail_val = tail_offset
            #     if head_offset == tail_offset:
            #         if dt.read_times >= len(globs.user_input)-1:
            #             #如果消耗点大于输入点，则认为数据已经输入完毕。否则再等一轮，无论是否大于都退出
            #             if dt.consume_count >= len(globs.user_input) or self.read_flag == True:
            #                 my_debug_log("---------------offset_is_finished_exit-------------")
            #                 pid = os.getpid()
            #                 my_debug_log("pid: %d" % pid)
                            
            #                 #若间接调用有被使用，则更新dt
            #                 if self.indirect_remove_count > 0:
            #                     self.tmp_dt.callread_pc = dt.callread_pc
            #                     self.tmp_dt.read_pc = dt.read_pc
            #                     self.tmp_dt.buffer_addr = dt.buffer_addr
            #                     self.tmp_dt.irq_pc = dt.irq_pc
                            
            #                     self.get_static_data(uc,self.irq_dt_set)

            #                 self.write_to_shared_memory()
            #                 my_debug_log("Final consume_count: %d" % dt.consume_count)
            #                 my_debug_log("fork_point_times: %d" % globs.config.fork_point_times)
                            
            #                 do_exit(0)
            #             else:
            #                 self.read_flag = True
                
            #         elif (head_offset + 1) % dt.buffer_len != tail_offset:
            #             dt.input_offset += self.fill_data(dt,dt.buffer_len)

    def fill_data(self,dt,container_len):
        remain_data_len = len(globs.user_input) - dt.input_offset
        if remain_data_len <= 0 or container_len <= 0:
            return 0
        random_input = []
        
        my_debug_log("---------------fill_data-------------")
        my_debug_log("remain_data_len: %d" % remain_data_len)

        need_input_len = min(remain_data_len,container_len)
        padding_len = 0
        if dt.buffer_min_len != None:  
            if need_input_len < dt.buffer_min_len:
            # TODO: 这里需要处理如果数据不足的情况(padding)
                my_debug_log("need_input_len < self.buffer_min_len")
                padding_len = dt.buffer_min_len - need_input_len

        my_debug_log("要塞入的数据长度need_input_len: %d" % need_input_len)
        
        if padding_len > 0:
            #填充随机值到padding中
            for i in range(padding_len):
                random_input.append(random.randint(0, 0xff))
            my_debug_log("add the padding data = {} to the input".format(random_input))
            self.write_byte_to_data_reg([dt.dr],random_input)   
        
        self.write_byte_to_data_reg([dt.dr],
                globs.user_input[dt.input_offset : dt.input_offset + need_input_len] + random_input)
        
        return need_input_len

    def hook_func_increase_offset_read(self, uc, address, size, user_data):
        my_debug_log(">>> start increase_offset_read_hook")
        
        #假如第一轮找buffer下限时,没有经过avail点就到了read点,则直接退出
        if self.get_data_from_shared_memory == False:
            if self.supple_input == 0 and self.escape_flag == False:
                my_debug_log(">>> it may not have lower limit,exit")
                for cur_dt in self.irq_dt_set:
                    cur_dt.buffer_min_len = 1
                
                self._print_dt()
                self.write_to_shared_memory()
                do_exit(0)
    
        else:
            #将avail_hook处的dt用于此处
            cur_dt = self.avail_read_consume_dt 
            cur_dt.read_times += 1
            my_debug_log(">>> Current read_times = %d" % cur_dt.read_times)


    def get_static_data(self,uc,dt_set):
        # dyanmic_hook_indirect_addr.txt是hook获取到的地址
        my_debug_log("get_static_data here")
        
        #获得dt实例的数据列表，以及全局变量集合
        dt_dict_list, self.global_vars  = run_ghidra_script(
            self.port, ["global_static_data"],[
            self.tmp_dt.callread_pc,
            self.tmp_dt.read_pc,
            self.ghidra_config["entry_point"],
            self.tmp_dt.irq_pc,
            self.tmp_dt.buffer_addr,
            self.dynamic_hook_indirect_path]
        )
        
        my_debug_log("the dt list = {}".format(dt_dict_list)) 
        
        
        #假如返回的数据不是dt实例，则可能是由于数据太少卡在了某个下限的位置，需要打开放入点放入数据
        if len(dt_dict_list) == 0:
            if dt_set == self.irq_dt_set:
                my_debug_log("tmp recover the dr")
                
                #先恢复该DRhook
                self.justify_dr_hook_dict[self.tmp_dt.dr] = self.uc.hook_add(
                    UC_HOOK_MEM_READ_AFTER,
                    self.hook_func_data_regs_check,
                    begin=self.tmp_dt.dr,
                    end=self.tmp_dt.dr,
                )
                
                if self.input_hook == None:
                    # 添加一个基本块Hook
                    self.input_hook = self.uc.hook_add(
                        UC_HOOK_BLOCK,
                        self.hook_func_escape_data_input,
                    )
            
            
        #如果返回了新的dt,则创建新的dt实例，将静态脚本获得的数据添加进去
        elif len(dt_dict_list):
            
            self.update_dt_set(dt_dict_list,dt_set)
        
            #中断读的情况中,如果这次静态脚本执行获得了dt实例，则可以删除buffer的read hook
            #否则可能是因为遇到了无效的读行为，导致无消耗点输出，则需要继续挂着buffer的read hook等待下一个读buffer的行为发生
            if self.buffer_hook:
                uc.hook_del(self.buffer_hook)
                
            if self.input_hook:
                uc.hook_del(self.input_hook)
                
        #处理第一次进入DR read的情况
        if self.avail_start_point == None and len(dt_dict_list):
            #如果能找到,则直接赋予,否则将tmp_dt.callread_pc作为avail_start_point
            for dt in dt_set:
                if dt.callread_pc == self.tmp_dt.callread_pc:
                    self.avail_start_point = dt.avail_pc
                    break
            if self.avail_start_point == None:
                self.avail_start_point = self.tmp_dt.callread_pc


    #根据静态脚本返回的实例数，创建等量的dt并赋值
    def update_dt_set(self,dt_dict_list,dt_set):
        my_debug_log(">>> update_dt_set")
        
        #如果本轮dr在此前已经出现过，则进行更新操作(删除原有的相同dr的实例)
        cur_dr = self.tmp_dt.dr 
        if cur_dr in self.dt_created_dr:
            dt_need_to_remove = {dt for dt in dt_set if dt.dr == cur_dr}
            #如果已存在的符合条件的dt数量少于待更新的dt数量，则更新。否则不更新
            if len(dt_need_to_remove) <= len(dt_dict_list):         
                dt_set -= dt_need_to_remove
                my_debug_log(">>> clear old dt")
        
        my_debug_log(">>> add new dt_set")
        for dt_dict in dt_dict_list:
            
            my_debug_log(">>> start created new dt")
            cur_dt = DataTracker()
            
            #将静态脚本中获得的值赋予每个dt
            cur_dt.callread_pc = int(dt_dict["callread_pc"], 16)
            cur_dt.avail_pc = int(dt_dict["avail_pc"], 16)
            cur_dt.consume_pc_set = dt_dict["consume_pc_set"]
            
            #如果发现avail_pc与之前的冲突，则替换之前的dt
            
            for tmp_dt in dt_set:
                if cur_dt.avail_pc == tmp_dt.avail_pc:
                    tmp = {tmp_dt}
                    dt_set -= tmp
                    my_debug_log("the avail_pc {} is conflict with the previous one, replace it".format(hex(cur_dt.avail_pc)))
                    break
            
            #将之前tmp_dt中获得的公用值赋予dt
            cur_dt.buffer_addr = self.tmp_dt.buffer_addr
            cur_dt.irq_pc = self.tmp_dt.irq_pc
            cur_dt.buffer_len = self.tmp_dt.buffer_len
            cur_dt.read_pc = self.tmp_dt.read_pc
            cur_dt.dr = self.tmp_dt.dr
            cur_dt.rx_head = self.tmp_dt.rx_head
            cur_dt.rx_tail = self.tmp_dt.rx_tail
            
            
            #将avail_pc与dt实例对应,方便以后使用
            self.avail_dt_dict[cur_dt.avail_pc] = cur_dt
            
            my_debug_log(">>> the current produce dt is:{}".format(cur_dt))
            
            #将创建好的dt放入dt集合中
            dt_set.add(cur_dt)
        
        self.dt_created_dr.add(cur_dr)

    def _print_dt(self):
        my_debug_log("----irq_dt:\n")
        for irq_dt in self.irq_dt_set:
            my_debug_log(irq_dt)
            
        my_debug_log("----main_dt:\n")    
        for main_dt in self.main_dt_set:
            my_debug_log(main_dt)    

    def write_byte_to_data_reg(self, valid_dr,get_input):
        # from .rule import hardware_write_to_receive_buffer_list
        # hardware_write_to_receive_buffer_list(valid_dr, get_input, 4)
        print("write_byte_to_data_reg")
    
    def write_to_shared_memory(self):
        my_debug_log(">>> write_to_shared_memory")
    
        # save the data to the dict
        attrs = ["consume_dt_dict", "avail_dt_dict", "irq_dt_set", "main_dt_set"]
        
        dumps_data_dict= {}
        
        for attr in attrs:
            v = getattr(self, attr)
            pickle.dumps(v)
            dumps_data_dict[attr] = v
        
        # (TODO: remove) if the dr hook is not triggered, then the dr hook will not be written to the shared memory
        if self.dr_remove_count >= 1:
            dumps_data_dict["data_regs"] = self.data_regs
        else:
            dumps_data_dict["data_regs"] = []
        
        # (TODO: remove) if the indirect call hook is not triggered, then the indirect call hook will not be written to the shared memory
        if self.indirect_remove_count >= 1:
            my_debug_log("the final indirect_remove_count = {}".format(self.indirect_remove_count))
            dumps_data_dict["indirect_src_addrs"] = list(self.indirect_call_hook_map.keys())
        else:
            dumps_data_dict["indirect_src_addrs"] = []
        
        # serialize the data
        serialized_data = pickle.dumps(dumps_data_dict)
        
        # if not debug mode, write the serialized data to the shared memory
        if not self.debug:
            # Create a shared memory block
            shm = shared_memory.SharedMemory(name=self.shm_name)
            shm.buf[: len(serialized_data)] = serialized_data
        # write the serialized data to the file, no matter debug mode or not
        home_path = os.path.expanduser('~')
        shm_file = os.path.join(home_path, f"ghidra_project/{self.port}_shared_memory.txt")
        with open(shm_file, "wb") as f:
            my_debug_log("shm_file:{}".format(shm_file))
            f.write(serialized_data)
        my_debug_log("Serialized data is written to shared memory")
    
    def _print_hook_count(self):
        my_debug_log("the avail hook count = {}".format(len(self.avail_pc_hook.keys())))
        my_debug_log("the consume hook count = {}".format(len(self.consume_pc_hook.keys())))
        my_debug_log("the read hook count = {}".format(len(self.read_pc_hook.keys())))
        my_debug_log("the indirect hook count = {}".format(len(self.indirect_call_hook_map.keys())))
        my_debug_log("the dr hook count = {}".format(len(self.justify_dr_hook_dict.keys())))
        
    # 仅调试的时候使用
    def hook_func_basicblock(self,uc, address, size, user_data):
        # self.basicblock_list.append((address,size))
        dt = self.avail_read_consume_dt
        if dt != None and dt.rx_head != None and dt.rx_tail != None:
            
            head_offset = uc_mem_read_offset_one_byte(uc, dt.rx_head)
            tail_offset = uc_mem_read_offset_one_byte(uc, dt.rx_tail)
            my_debug_log("head_offset: %d, tail_offset: %d" % (head_offset, tail_offset))
            my_debug_log("input offset = %d" % dt.input_offset)

        my_debug_log("basicblock address:%s,size:%s" % (hex(address),hex(size)))
        # tmp_rx_head = 0x2000046c
        # tmp_rx_tail = 0x2000046e
        tmp_rx_head = 0x20070c88
        tmp_rx_tail = 0x20070c8c        
        head_offset = uc_mem_read_offset_one_byte(uc, tmp_rx_head)
        tail_offset = uc_mem_read_offset_one_byte(uc, tmp_rx_tail)
        my_debug_log("head_offset: %d, tail_offset: %d" % (head_offset, tail_offset))
    
    #获得每一次的随机分段
    def get_current_partion(self,dt):
        
        #生成最新的随机分段
        self.random_split_data_input(dt)
        
        #若有信息，则每次取出第一个分段作为当前分段
        if len(self.random_split[dt.dr]) == 1:
            partion = self.random_split[dt.dr][0]
            my_debug_log("current partion = {}".format(partion))
        elif len(self.random_split[dt.dr]) > 1:
            partion = self.random_split[dt.dr][-1] - self.random_split[dt.dr][-2]
            my_debug_log("current partion = {}".format(partion))
        
        my_debug_log("current random_split = {}".format(self.random_split))
        return partion
    
    # 根据输入数据长度和buffer长度关系，切分成随机长度的数据段
    def random_split_data_input(self,dt):
        #如果第一次开始计算，则初始化。否则从最新的偏移处开始切分
        if dt.dr not in self.random_split.keys():
            self.random_split[dt.dr] = []
            index = 0
        else:
            index = self.random_split[dt.dr][-1] 
        
        if index >= len(globs.user_input):
            self.random_split[dt.dr].append(index)
            return
        
        #固件读和中断读采用不同的分段方式
        if dt.buffer_len:
            # channels = len(self.irq_dt_set)
            threshold = 1
            if dt.buffer_min_len > 0:
                threshold = dt.buffer_min_len
            self.random_split[dt.dr].append(self.random_split_algothrim(index,dt.buffer_len,threshold))
    
        #如果是固件读的情况，根据通道数确定每段的上限
        else:
            split_count = self.statistic_channels(dt)
            if split_count > 3:
                partion = len(globs.user_input) // (split_count - 1)
            else:
                partion = len(globs.user_input) // 2
            self.random_split[dt.dr].append(self.random_split_algothrim(index,partion))
            
    #随机切分算法
    def random_split_algothrim(self,index,ceil,threshold = 1):
        # 随机数替换为fuzz输入
        # 每轮以模糊测试第i个字节为随机种子        
        remaining_sum = len(globs.user_input) - index
        seed = globs.user_input[index]
        start = threshold
        end = min(remaining_sum, ceil)
        if start == end:
            return remaining_sum + index
        random_value = start + int(seed) % (end - start)
        # #假如剩余数据只剩下上限的一半，则直接全部获取
        # if remaining_sum < ceil // 2:
        #     random_value = remaining_sum
        return random_value + index


    #用于统计同一Buffer或dr的通道数
    def statistic_channels(self,dt):
        count = 0
        if dt.buffer_addr != None:
            for cur_dt in self.irq_dt_set:
                if cur_dt.buffer_addr == dt.buffer_addr:
                    count += 1
        else:
            for cur_dt in self.main_dt_set:
                if cur_dt.dr == dt.dr:
                    count += 1
        return count        
    

    #用于在遇到一个新的函数时就放入数据，以跳出清空buffer的循环
    def hook_func_escape_data_input(self,uc, address, size, user_data):
        
        my_debug_log("hook_func_escape_data_input")
        if self.escape_flag == False:
            self.escape_flag = True
        #到达一个新函数,就放4个数据试探
        if address in globs.config.symbols and address not in self.escape_funcs:
            #放入4个数据
            self.escape_funcs.append(address)
            my_debug_log("put 4 data!")
            self.write_byte_to_data_reg([self.tmp_dt.dr],[0xBB]*4)
            my_debug_log("%s %s\n"%(hex(address), globs.config.symbols[address]))
            
        
