#include <iostream>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <unicorn/unicorn.h>
#include "DataTracker.h"

// Assuming my_debug_log is a function you have defined elsewhere
void my_debug_log(const std::string &message);

class EmulationHandler
{
private:
    uc_engine *uc;
    std::string emulation_handler_shared_memory_name;
    std::string binary_file;
    uint64_t avail_start_point;
    bool get_data_from_shared_memory;
    int port;
    bool debug;

    std::vector<uint64_t> data_regs;
    std::vector<uint64_t> status_regs;
    int dr_remove_count;

    DataTracker *avail_read_consume_dt;
    std::map<uint64_t, DataTracker> consume_dt_dict;
    std::map<uint64_t, DataTracker> avail_dt_dict;
    std::set<uint64_t> irq_dt_set;
    std::set<uint64_t> main_dt_set;
    DataTracker tmp_dt;
    std::set<uint64_t> dt_created_dr;

    std::string dynamic_hook_indirect_path;
    std::vector<std::string> global_vars;

    std::map<uint64_t, uint64_t> indirectaddr_jumpaddr_map;
    int indirect_remove_count;

    int headtail_count;
    uint64_t before_tail_val;
    int threshold;
    std::vector<std::string> changed_vars;
    std::vector<std::string> tmp_list_include_head_tail;
    std::set<uint64_t> head_offset_set;

    int partion;
    bool consume_flag;
    int supple_input;
    std::vector<std::string> escape_funcs;
    std::map<int, int> random_split;
    int last_read_times;

    uc_hook buffer_hook;
    uc_hook head_tail_bufferlen_hook;
    uc_hook mem_second_write_hook;
    uc_hook input_hook;
    uc_hook buffer_min_len_input;

    std::map<uint64_t, uc_hook> avail_pc_hook;
    std::map<uint64_t, uc_hook> mem_global_hook;
    std::map<uint64_t, uc_hook> consume_pc_hook;
    std::map<uint64_t, uc_hook> read_pc_hook;
    std::map<uint64_t, uc_hook> interrupt_dr_hook_dict;
    std::map<uint64_t, uc_hook> indirect_call_hook_map;
    std::map<uint64_t, uc_hook> justify_dr_hook_dict;
    std::map<uint64_t, uc_hook> justify_sr_hook_dict;

    int round;
    int prev_len;
    int prev_list_length;
    std::vector<uint64_t> addr_list;
    void *taintdata;

    std::map<uint64_t, uint64_t> sr_pc_dict;
    std::vector<uint64_t> sr_dr_route;

public:
    EmulationHandler()
    {
        // Initialize your variables here
        // For example:
        uc = nullptr;     // You would actually initialize this with uc_open() or similar
        binary_file = ""; // Set this to the actual binary file path
        // ... and so on for the other variables
    }

    // void hook_all_data_regs()
    // {
    //     for (auto dr : data_regs)
    //     {
    //         my_debug_log("dr is " + std::to_string(dr));
    //         // You need to replace the following with the actual hooking code
    //         // For example:
    //         // uc_hook_add(uc, &buffer_hook, UC_HOOK_MEM_READ_AFTER, hook_func_data_regs_check, this, dr, dr);
    //         // justify_dr_hook_dict[dr] = buffer_hook;
    //     }
    // }

    // void hook_all_status_regs()
    // {
    //     for (auto sr : status_regs)
    //     {
    //         my_debug_log("sr is " + std::to_string(sr));
    //         // You need to replace the following with the actual hooking code
    //         // For example:
    //         // uc_hook_add(uc, &buffer_hook, UC_HOOK_MEM_READ_AFTER, hook_func_status_regs_check, this, sr, sr);
    //         // justify_sr_hook_dict[sr] = buffer_hook;
    //     }
    // }

    // static void hook_func_status_regs_check(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
    // {
    //     EmulationHandler *handler = reinterpret_cast<EmulationHandler *>(user_data);
    //     uint32_t pc = uc_reg_read(uc, UC_ARM_REG_PC);
    //     uint32_t ipsr = uc_reg_read(uc, UC_ARM_REG_IPSR);
    //     if (ipsr == 0)
    //     {
    //         handler->sr_pc_dict[pc] = address;
    //         handler->sr_dr_route.push_back(pc);
    //     }
    //     // my_debug_log("--------------met a sr pc at " + std::to_string(pc) + "----------------");
    // }

    // static void hook_func_data_regs_check(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
    // {
    //     EmulationHandler *handler = reinterpret_cast<EmulationHandler *>(user_data);
    //     my_debug_log(">>> " + std::to_string(address) + " dr is read");
    //     my_debug_log(">>> the pc is " + std::to_string(uc_reg_read(uc, UC_ARM_REG_PC)));

    //     // ... (rest of the method implementation)

    //     // Note: You will need to implement the rest of the method logic here, including the calls to
    //     // write_byte_to_data_reg, uc_hook_del, and any other logic that is specific to your application.
    // }

    // static void hook_func_sr_add_avail(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
    // {
    //     EmulationHandler *handler = reinterpret_cast<EmulationHandler *>(user_data);
    //     auto it = handler->avail_dt_dict.find(address);
    //     if (it == handler->avail_dt_dict.end())
    //     {
    //         std::cerr << "error, the SR_add_avail_hook dt is None" << std::endl;
    //         std::exit(-1);
    //     }

    //     DataTracker &dt = it->second;
    //     handler->write_byte_to_data_reg(dt.dr, 0xBB);

    //     handler->sr_dr_route.push_back(dt.avail_pc);

    //     uint64_t tmp_avail_pc = dt.avail_pc;
    //     if (!handler->sr_dr_route.empty())
    //     {
    //         dt.avail_pc = handler->sr_dr_route.front();
    //     }

    //     std::cout << "--the new avail_pc is " << std::hex << dt.avail_pc << std::endl;

    //     if (handler->sr_dr_route.size() > 1)
    //     {
    //         uint64_t sr_to_remove = handler->sr_dr_route[handler->sr_dr_route.size() - 2];
    //         uc_hook_del(uc, handler->justify_sr_hook_dict[sr_to_remove]);
    //         handler->justify_sr_hook_dict.erase(sr_to_remove);
    //     }

    //     if (tmp_avail_pc != dt.avail_pc)
    //     {
    //         handler->avail_dt_dict.erase(tmp_avail_pc);

    //         while (handler->avail_dt_dict.find(dt.avail_pc) != handler->avail_dt_dict.end())
    //         {
    //             std::cout << "*****************Warning: the avail key " << std::hex << dt.avail_pc << " is conflict, try to minus the address" << std::endl;
    //             dt.avail_pc -= 2;
    //         }

    //         handler->avail_dt_dict[dt.avail_pc] = dt;

    //         if (handler->avail_pc_hook.find(dt.avail_pc) == handler->avail_pc_hook.end())
    //         {
    //             uc_hook_del(uc, handler->avail_pc_hook[tmp_avail_pc]);
    //             handler->avail_pc_hook.erase(tmp_avail_pc);
    //             // Add the new hook here using uc_hook_add
    //             // handler->add_avail_hook(dt);
    //         }
    //     }

    //     handler->sr_dr_route.clear();
    // }

    // void dr_interrupt_hook_func(uc_engine *uc)
    // {
    //     try
    //     {
    //         my_debug_log(">>> hook_dr_interrupt");
    //         uint32_t ipsr_val = uc_reg_read(uc, UC_ARM_REG_IPSR);
    //         my_debug_log("ipsr_val:" + std::to_string(ipsr_val));
    //         uint64_t nvic_base_addr = out_vtor(0);
    //         const uint32_t PTR_SIZE = 4;
    //         uint64_t handler_addr = nvic_base_addr + (ipsr_val * PTR_SIZE);

    //         tmp_dt.irq_pc = uc_mem_read_offset_four_byte(uc, handler_addr) - 1;
    //         my_debug_log(">>>dr_interrupt_hook: irq_pc:" + std::to_string(tmp_dt.irq_pc));
    //         write_byte_to_data_reg(uc, tmp_dt.dr, 0xBB);
    //     }
    //     catch (const std::exception &e)
    //     {
    //         my_debug_log(">>> exception: " + std::string(e.what()));
    //     }
    // }

    // void hook_func_indirect_addr_call(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
    // {
    //     my_debug_log(">>> enter the indirect hook, the src address is " + std::to_string(address));

    //     // Assuming CsDisassembler is a class that wraps Capstone disassembly functionalities
    //     CsDisassembler disassembler(CS_ARCH_ARM, CS_MODE_MCLASS | CS_MODE_THUMB);
    //     uint32_t pc = uc_reg_read(uc, UC_ARM_REG_PC);
    //     std::vector<uint8_t> mem = uc_mem_read(uc, pc, size);

    //     try
    //     {
    //         auto instructions = disassembler.disassemble(mem, pc, size);
    //         for (const auto &insn : instructions)
    //         {
    //             my_debug_log(">>> Indirect Call: addr= " + std::to_string(insn.address) +
    //                          ", size=" + std::to_string(insn.size) +
    //                          ", mnemonic=" + insn.mnemonic +
    //                          ", op_str=" + insn.op_str);

    //             if (insn.mnemonic == "blx" || insn.mnemonic == "bx")
    //             {
    //                 // Extract register number from the operand string using regular expressions
    //                 std::regex reg_expr("r(\\d+)");
    //                 std::smatch match;
    //                 if (std::regex_search(insn.op_str, match, reg_expr))
    //                 {
    //                     int register_num = std::stoi(match[1]);
    //                     uint32_t register_value = uc_reg_read(uc, UC_ARM_REG_R0 + register_num);
    //                     my_debug_log("Register " + std::to_string(register_num) + ": " + std::to_string(register_value));

    //                     if (register_value & 0xFFFF0000)
    //                     { // Check if the address is not effective
    //                         my_debug_log("not effective address!");
    //                         continue;
    //                     }

    //                     indirectaddr_jumpaddr_map[address] = register_value;
    //                     std::ofstream file(get_dynamic_hook_indirect_path(), std::ios::out);
    //                     if (file.is_open())
    //                     {
    //                         my_debug_log(" " + std::to_string(address) + ": " + std::to_string(register_value) + " will be written");
    //                         file << indirectaddr_jumpaddr_map;
    //                     }

    //                     // Remove the indirect call hook and value from the map
    //                     uc_hook_del(uc, indirect_call_hook_map[address]);
    //                     indirect_call_hook_map.erase(address);

    //                     // Increment the count of removed indirect hooks
    //                     indirect_remove_count++;
    //                     my_debug_log("the indirect_remove_count = " + std::to_string(indirect_remove_count));
    //                 }
    //             }
    //             else if (insn.mnemonic == "tbb" || insn.mnemonic == "tbh")
    //             {
    //                 // Handle table branch instructions
    //                 // ... (similar logic as above)
    //             }
    //             else
    //             {
    //                 my_debug_log("Indirect match failed, return");
    //                 return;
    //             }
    //         }
    //     }
    //     catch (const std::exception &e)
    //     {
    //         my_debug_log(">>> exception: " + std::string(e.what()));
    //     }
    // }

    // static void hook_func_all_memwrite(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
    // {
    //     EmulationHandler *handler = reinterpret_cast<EmulationHandler *>(user_data);
    //     if (value == handler->taintdata)
    //     {
    //         uint32_t pc = uc_reg_read(uc, UC_ARM_REG_PC);
    //         my_debug_log(">>> Write: addr= " + std::to_string(address) + " data=" + std::to_string(value) + " (pc " + std::to_string(pc) + ")");
    //         uint32_t ipsr = uc_reg_read(uc, UC_ARM_REG_IPSR);
    //         my_debug_log("current addr_list = " + std::to_string(handler->addr_list.size()));
    //         if (ipsr != 0)
    //         {
    //             // ... rest of the implementation ...
    //         }
    //         else
    //         {
    //             // In the main function, remove the write hook
    //             my_debug_log("Writing data in the main function");
    //             uc_hook_del(uc, handler->write_hook);
    //         }
    //     }
    // }

    // void hook_func_all_memread(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
    // {
    //     auto handler = static_cast<EmulationHandler *>(user_data);
    //     if (address == handler->tmp_dt.dr)
    //     {
    //         handler->taintdata = value;
    //         if (handler->read_hook)
    //         {
    //             uc_hook_del(uc, handler->read_hook);
    //             handler->read_hook = 0;
    //         }
    //     }
    // }

    // void hook_func_bufferaddr_get_readpc(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
    // {
    //     auto handler = static_cast<EmulationHandler *>(user_data);
    //     if (handler->prev_len != 0 && handler->tmp_dt.buffer_len == 0)
    //     {
    //         uint32_t test_len = handler->prev_len + 1;
    //         bool condition = test_len > 0 && (test_len & (test_len - 1)) == 0;
    //         if (condition)
    //         {
    //             my_debug_log(">>>buffer_len may not be computed before,but it is probably = " + std::to_string(test_len));
    //             handler->tmp_dt.buffer_len = test_len;
    //             handler->compute_bufferlen(uc);
    //         }
    //     }

    //     my_debug_log(">>>hook_func_bufferaddr_get_readpc: buffer_addr " + to_hex_string(address) + " is read");
    //     uint32_t lr;
    //     uc_reg_read(uc, UC_ARM_REG_LR, &lr);
    //     handler->tmp_dt.callread_pc = lr;

    //     uint32_t pc;
    //     uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    //     handler->tmp_dt.read_pc = pc;
    //     my_debug_log("now the readpc and callreadpc = " + to_hex_string(handler->tmp_dt.read_pc) + "," + to_hex_string(handler->tmp_dt.callread_pc));

    //     // Run static script
    //     handler->get_static_data(uc, handler->irq_dt_set);

    //     uint64_t avail_pc = 0;
    //     // If it's an interrupt read, add consume_hook to get the lower limit of the buffer
    //     for (const auto &cur_dt : handler->irq_dt_set)
    //     {
    //         if (std::abs(static_cast<int>(handler->tmp_dt.callread_pc) - static_cast<int>(cur_dt.callread_pc)) <= 5)
    //         {
    //             avail_pc = cur_dt.avail_pc;
    //         }
    //     }

    //     // Add avail point hook as a probe for the lower limit of the buffer
    //     if (avail_pc == 0)
    //     {
    //         avail_pc = handler->tmp_dt.callread_pc;
    //     }

    //     if (!handler->irq_dt_set.empty())
    //     {
    //         handler->buffer_min_len_input = uc_hook_add(
    //             uc, UC_HOOK_CODE, hook_func_got_buffer_min_len, handler, avail_pc, avail_pc, nullptr);
    //     }

    //     // If dt is already obtained, add hooks to get head, tail pointers, and buffer length
    //     if (!handler->head_tail_bufferlen_hook)
    //     {
    //         handler->head_tail_bufferlen_hook = uc_hook_add(
    //             uc, UC_HOOK_CODE, hook_func_get_head_tail_bufferlen, handler, handler->tmp_dt.read_pc, handler->tmp_dt.read_pc, nullptr);
    //     }
    // }

    // void processInterruptFunction(uc_engine* uc) {
    //     if (tmp_dt.buffer_len == 0) {
    //         // If prev_len exists and prev_len + 1 is a power of 2, and buffer_len is not yet obtained,
    //         // then assume buffer_len = prev_len + 1
    //         uint32_t test_len = tmp_dt.prev_len + 1;
    //         if ((test_len & (test_len - 1)) == 0) { // Check if test_len is a power of 2
    //             my_debug_log(">>> buffer_len may not be computed before, but it is probably = " + std::to_string(test_len));
    //             tmp_dt.buffer_len = test_len;
    //             // compute_bufferlen(uc); // You need to implement this function
    //         }
    //     }

    //     // ... (rest of the logic for handling different lengths of changed_vars)

    //     // Read the first byte of data into dr
    //     if (get_head_tail_flag && tmp_dt.buffer_len == 0) {
    //         uint8_t head_offset = uc_mem_read_offset_one_byte(uc, tmp_dt.rx_head);
    //         size_t before_len = head_offset_set.size();
    //         head_offset_set.insert(head_offset);
    //         size_t after_len = head_offset_set.size();
    //         my_debug_log("before_len: " + std::to_string(before_len) + ", after_len: " + std::to_string(after_len) + ", head_offset: " + std::to_string(head_offset));

    //         if (before_len == after_len) {
    //             // If the set size hasn't changed, it means the offset is a repeat and we've found the buffer length
    //             auto sorted_head_offset_set = std::vector<uint8_t>(head_offset_set.begin(), head_offset_set.end());
    //             std::sort(sorted_head_offset_set.begin(), sorted_head_offset_set.end());
    //             tmp_dt.buffer_len = sorted_head_offset_set.back() + 1;
    //             // add_and_delete_hook_before_exit(uc); // You need to implement this function
    //         } else {
    //             // mem_second_write_hook logic goes here
    //         }
    //     } else if (get_head_tail_flag && tmp_dt.buffer_len != 0) {
    //         // add_and_delete_hook_before_exit(uc); // You need to implement this function
    //     }

    //     // Increment the headtail_count
    //     headtail_count++;
    // }

    // void add_and_delete_hook_before_exit(uc_engine* uc) {
    //     my_debug_log(">>> add and delete hook before exit");
    //     // After getting the data, delete the current hook
    //     if (head_tail_bufferlen_hook != 0) {
    //         uc_hook_del(uc, head_tail_bufferlen_hook);
    //         head_tail_bufferlen_hook = 0;
    //     }

    //     // If this approach got the data, delete the hook from the other approach
    //     if (mem_second_write_hook != 0) {
    //         uc_hook_del(uc, mem_second_write_hook);
    //         mem_second_write_hook = 0;
    //     }

    //     // Update and add consume_hook and avail_hook before buffer settlement
    //     // add_all_dt_avail_and_consume_hook(dt_set);

    //     // Run the static script again in case of indirect call supplement to update dt data
    //     get_static_data(uc, dt_set);

    //     // If it's the first round, exit after writing. The second round ends at the avail_hook position, so only the first round needs to be handled here
    //     if (!get_data_from_shared_memory) {
    //         my_debug_log("avail_start_point = " + std::to_string(avail_start_point));
    //         print_dt();

    //         if (tmp_dt.buffer_min_len != 0) {
    //             write_to_shared_memory();
    //             my_debug_log("write to shared memory");
    //             exit(0); // Assuming do_exit is replaced with exit
    //         }
    //     }
    // }

    // // ... other methods ...

    // // Add consume hook
    // void add_consume_hook(DataTracker& cur_dt) {
    //     if (cur_dt.consume_pc_set.empty()) {
    //         return;
    //     }

    //     for (auto consume_addr : cur_dt.consume_pc_set) {
    //         if (consume_pc_hook.find(consume_addr) != consume_pc_hook.end()) {
    //             continue;
    //         }

    //         my_debug_log("current consume_addr: " + std::to_string(consume_addr) + ", add the hook for it");

    //         // Add consume and dt mapping (mapping is not necessarily unique, but use it for now)
    //         if (consume_dt_dict.find(consume_addr) == consume_dt_dict.end()) {
    //             consume_dt_dict[consume_addr] = &cur_dt;
    //         }

    //         uc_hook tmp_hook;
    //         uc_hook_add(uc, &tmp_hook, UC_HOOK_CODE, hook_func_get_consume_count, &cur_dt, consume_addr, consume_addr);
    //         consume_pc_hook[consume_addr] = tmp_hook;
    //     }
    // }

    // void add_avail_hook(DataTracker& cur_dt) {
    //     if (cur_dt.avail_pc == 0 || avail_pc_hook.find(cur_dt.avail_pc) != avail_pc_hook.end()) {
    //         return;
    //     }
    //     my_debug_log("avail_pc = :" + std::to_string(cur_dt.avail_pc) + ", add the hook for it");
    //     uc_hook tmp_hook;
    //     uc_hook_add(uc, &tmp_hook, UC_HOOK_CODE, hook_func_avail_pc, &cur_dt, cur_dt.avail_pc, cur_dt.avail_pc);
    //     avail_pc_hook[cur_dt.avail_pc] = tmp_hook;
    // }

    // void add_read_hook(DataTracker& cur_dt) {
    //     if (cur_dt.read_pc == 0 || read_pc_hook.find(cur_dt.read_pc) != read_pc_hook.end()) {
    //         return;
    //     }
    //     uc_hook tmp_hook;
    //     uc_hook_add(uc, &tmp_hook, UC_HOOK_CODE, hook_func_increase_offset_read, &cur_dt, cur_dt.read_pc, cur_dt.read_pc);
    //     read_pc_hook[cur_dt.read_pc] = tmp_hook;
    // }

    // static void hook_func_got_buffer_min_len(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    //     EmulationHandler* handler = reinterpret_cast<EmulationHandler*>(user_data);
    //     my_debug_log(">>> reach the buffer_min_len data point, put 1 data");

    //     if (handler->supple_input == 0) {
    //         call_hardware_clear_r_fifo({handler->tmp_dt.dr});
    //         for (DataTracker* cur_dt : handler->irq_dt_set) {
    //             handler->add_consume_hook(*cur_dt);
    //         }
    //         write_byte_to_data_reg(uc, handler->tmp_dt.dr, 0xBB);
    //         handler->supple_input += 1;
    //     }
    // }

    // static void hook_func_get_consume_count(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    //     EmulationHandler* handler = reinterpret_cast<EmulationHandler*>(user_data);
    //     my_debug_log(">>> hook_func_get_consume_count");

    //     for (auto& kv : handler->consume_pc_hook) {
    //         uc_hook_del(uc, kv.second);
    //     }

    //     uc_hook_del(uc, handler->buffer_min_len_input);

    //     my_debug_log("buffer_min_len = " + std::to_string(handler->supple_input));

    //     for (DataTracker* cur_dt : handler->irq_dt_set) {
    //         cur_dt->buffer_min_len = handler->supple_input;
    //     }
    //     handler->tmp_dt.buffer_min_len = handler->supple_input;

    //     if (!handler->get_data_from_shared_memory) {
    //         my_debug_log("avail_start_point = " + std::to_string(handler->avail_start_point));
    //         handler->print_dt();

    //         if (handler->tmp_dt.buffer_min_len != 0) {
    //             handler->write_to_shared_memory();
    //             my_debug_log("write to shared memory");
    //             exit(0);
    //         }
    //     }
    // }

    // void hook_func_mem_second_write(Unicorn* uc, int access, int address, int size, int value) {
    //     DebugLog::log("---------------hook_func_mem_second_write-----------------");
    //     DebugLog::log("len(self.head_offset_set):" + std::to_string(head_offset_set.size()));

    //     int offset = uc_mem_read_offset_one_byte(uc, tmp_dt.rx_head);
    //     if (offset == 0) {
    //         DebugLog::log("offset == 0");
    //         if (mem_second_write_hook) {
    //             uc->hook_del(mem_second_write_hook);
    //         }
    //         return;
    //     }

    //     tmp_dt.buffer_len = offset - 1;
    //     DebugLog::log("Mem second self.bufferlen:" + std::to_string(tmp_dt.buffer_len));

    //     if (head_tail_bufferlen_hook) {
    //         uc->hook_del(head_tail_bufferlen_hook);
    //     }
    //     if (mem_second_write_hook) {
    //         uc->hook_del(mem_second_write_hook);
    //     }

    //     add_and_delete_hook_before_exit(uc);

    //     if (!get_data_from_shared_memory) {
    //         DebugLog::log("avail_start_poiont = " + std::to_string(avail_start_point));
    //         print_dt();
    //         if (tmp_dt.buffer_min_len) {
    //             DebugLog::log("write to shared memory");
    //             write_to_shared_memory();
    //             do_exit(0, 9);
    //         }
    //     }
    // }

    // std::vector<GlobalVar> read_global_vars_file(Unicorn* uc) {
    //     std::vector<GlobalVar> global_vars_vector;
    //     for (int address : global_vars) {
    //         global_vars_vector.push_back(GlobalVar(uc, address));
    //     }
    //     return global_vars_vector;
    // }

    // void hook_func_avail_pc(Unicorn* uc, int address, int size) {
    //     DebugLog::log(">>>> avail_pc_input_point");

    //     auto it = avail_dt_dict.find(address);
    //     if (it == avail_dt_dict.end()) {
    //         std::cout << std::hex << address << std::endl;
    //         print_dt();
    //         DebugLog::log(">>>hook_func_avail_pc: dt not in datatracker_dict");
    //         do_exit(-1);
    //     }

    //     DataTracker& dt = it->second;
    //     avail_read_consume_dt = dt;

    //     if (dt.buffer_addr == 0) {
    //         // Data input phase
    //         DebugLog::log(">>>> now the input_offset is " + std::to_string(dt.input_offset));
    //         // ... Rest of the code handling the data input phase ...
    //     } else {
    //         // ... Rest of the code handling the buffer address present case ...
    //     }

    //     // Other logic as needed
    // }
    
    // int fill_data(DataTracker& dt, int container_len) {
    //     int remain_data_len = GlobalVars::user_input.size() - dt.input_offset;
    //     if (remain_data_len <= 0 || container_len <= 0) {
    //         return 0;
    //     }
    //     std::vector<char> random_input;

    //     DebugLog::log("---------------fill_data-------------");
    //     DebugLog::log("remain_data_len: " + std::to_string(remain_data_len));

    //     int need_input_len = std::min(remain_data_len, container_len);
    //     int padding_len = 0;
    //     if (dt.buffer_min_len != -1) { // Assuming -1 represents None
    //         if (need_input_len < dt.buffer_min_len) {
    //             DebugLog::log("need_input_len < self.buffer_min_len");
    //             padding_len = dt.buffer_min_len - need_input_len;
    //         }
    //     }

    //     DebugLog::log("要塞入的数据长度need_input_len: " + std::to_string(need_input_len));

    //     if (padding_len > 0) {
    //         std::default_random_engine generator;
    //         std::uniform_int_distribution<int> distribution(0, 0xff);
    //         for (int i = 0; i < padding_len; ++i) {
    //             random_input.push_back(static_cast<char>(distribution(generator)));
    //         }
    //         DebugLog::log("add the padding data to the input");
    //         write_byte_to_data_reg(dt.dr, random_input);
    //     }

    //     std::vector<char> data_to_write(GlobalVars::user_input.begin() + dt.input_offset,
    //                                     GlobalVars::user_input.begin() + dt.input_offset + need_input_len);
    //     data_to_write.insert(data_to_write.end(), random_input.begin(), random_input.end());
    //     write_byte_to_data_reg(dt.dr, data_to_write);

    //     return need_input_len;
    // }

    // void hook_func_increase_offset_read() {
    //     DebugLog::log(">>> start increase_offset_read_hook");

    //     avail_read_consume_dt.read_times += 1;
    //     DebugLog::log(">>> Current read_times = " + std::to_string(avail_read_consume_dt.read_times));
    // }

    // void get_static_data() {
    //     DebugLog::log("get_static_data here");
    //     auto [dt_dict_list, global_vars] = Ghidra::run_ghidra_get_static_data(
    //         // Assuming these are the correct parameters
    //         // self.port, self.tmp_dt.callread_pc, self.tmp_dt.read_pc, GlobalVars::entry_point, self.tmp_dt.irq_pc, self.tmp_dt.buffer_addr, self.dynamic_hook_indirect_path
    //     );

    //     DebugLog::log("the dt list = " + std::to_string(dt_dict_list.size()));

    //     if (dt_dict_list.empty()) {
    //         // Handle the case where no data trackers are returned
    //     } else {
    //         // Handle the case where new data trackers are returned
    //     }

    //     // Other logic as needed
    // }

    // void update_dt_set(const std::vector<DataTracker>& dt_dict_list, std::unordered_set<DataTracker>& dt_set) {
    //     DebugLog::log(">>> update_dt_set");

    //     int cur_dr = tmp_dt.dr[0]; // Assuming dr is a vector and we're interested in the first element
    //     if (dt_created_dr.find(cur_dr) != dt_created_dr.end()) {
    //         // If the current dr is already created, update the dt_set
    //     }

    //     DebugLog::log(">>> add new dt_set");
    //     for (const auto& dt_dict : dt_dict_list) {
    //         // Create new DataTracker instances and add them to dt_set
    //     }

    //     dt_created_dr.insert(cur_dr);
    // }

    // void serialize_data() {
    //     std::unordered_map<std::string, std::any> dumps_data_dict;
    //     dumps_data_dict["consume_dt_dict"] = consume_dt_dict;
    //     dumps_data_dict["avail_dt_dict"] = avail_dt_dict;

    //     if (dr_remove_count >= 1) {
    //         dumps_data_dict["data_regs"] = data_regs;
    //     } else {
    //         dumps_data_dict["data_regs"] = std::vector<int>();
    //     }

    //     DebugLog::log("the final indirect_remove_count = " + std::to_string(indirect_remove_count));
    //     if (indirect_remove_count >= 1) {
    //         for (auto& entry : indirect_call_hook_map) {
    //             entry.second = nullptr; // Assuming nullptr represents removal
    //         }
    //     } else {
    //         indirect_call_hook_map.clear();
    //     }

    //     // Deduplicate sets
    //     std::unordered_set<DataTracker> new_irq_set;
    //     std::unordered_set<DataTracker> new_main_set;
    //     std::unordered_set<size_t> existing_hashes;

    //     // Deduplicate irq_dt_set
    //     for (const auto& item : irq_dt_set) {
    //         auto item_hash = std::hash<DataTracker>{}(item);
    //         if (existing_hashes.find(item_hash) == existing_hashes.end()) {
    //             new_irq_set.insert(item);
    //             existing_hashes.insert(item_hash);
    //         }
    //     }

    //     // Deduplicate main_dt_set
    //     existing_hashes.clear();
    //     for (const auto& item : main_dt_set) {
    //         auto item_hash = std::hash<DataTracker>{}(item);
    //         if (existing_hashes.find(item_hash) == existing_hashes.end()) {
    //             new_main_set.insert(item);
    //             existing_hashes.insert(item_hash);
    //         }
    //     }

    //     irq_dt_set = std::move(new_irq_set);
    //     main_dt_set = std::move(new_main_set);
    //     dumps_data_dict["irq_dt_set"] = irq_dt_set;
    //     dumps_data_dict["main_dt_set"] = main_dt_set;

    //     // Serialize data
    //     std::stringstream ss;
    //     {
    //         cereal::BinaryOutputArchive oarchive(ss);
    //         oarchive(dumps_data_dict);
    //     }
    //     std::string serialized_data = ss.str();

    //     std::string shm_file = "shared_memory.bin";
    //     std::ofstream f(shm_file, std::ios::binary);
    //     DebugLog::log("shm_file:" + shm_file);
    //     f.write(serialized_data.data(), serialized_data.size());
    //     f.close();
    //     DebugLog::log("Serialized data is written to shared memory");
    //     std::cout << "Serialized data is written to shared memory" << std::endl;
    //     // Assuming shared memory operations are handled elsewhere
    // }

    // bool read_from_shared_memory() {
    //     // Assuming shared memory operations are handled elsewhere
    //     std::string shm_file = "shared_memory.bin";
    //     std::ifstream f(shm_file, std::ios::binary);
    //     if (!f.is_open()) {
    //         DebugLog::log("Shared memory file could not be opened.");
    //         return false;
    //     }
    //     std::stringstream ss;
    //     ss << f.rdbuf();
    //     f.close();

    //     std::unordered_map<std::string, std::any> data_tracker_dict;
    //     {
    //         cereal::BinaryInputArchive iarchive(ss);
    //         iarchive(data_tracker_dict);
    //     }

    //     // Deserialize data
    //     consume_dt_dict = std::any_cast<std::unordered_map<int, DataTracker>>(data_tracker_dict["consume_dt_dict"]);
    //     indirect_call_hook_map = std::any_cast<std::unordered_map<int, std::function<void()>>>(data_tracker_dict["indirect_call_hook_map"]);
    //     avail_dt_dict = std::any_cast<std::unordered_map<int, DataTracker>>(data_tracker_dict["avail_dt_dict"]);
    //     data_regs = std::any_cast<std::vector<int>>(data_tracker_dict["data_regs"]);
    //     irq_dt_set = std::any_cast<std::unordered_set<DataTracker>>(data_tracker_dict["irq_dt_set"]);
    //     main_dt_set = std::any_cast<std::unordered_set<DataTracker>>(data_tracker_dict["main_dt_set"]);
    //     DebugLog::log("Shared memory is read");

    //     // Restore hooks and other operations as needed

    //     DebugLog::log("recover read_hook complete");

    //     return true;
    // }

    // void print_hook_count() {
    //     DebugLog::log("the avail hook count = " + std::to_string(avail_dt_dict.size()));
    //     DebugLog::log("the consume hook count = " + std::to_string(consume_dt_dict.size()));
    //     DebugLog::log("the read hook count = " + std::to_string(data_regs.size()));
    //     DebugLog::log("the indirect hook count = " + std::to_string(indirect_call_hook_map.size()));
    //     DebugLog::log("the dr hook count = " + std::to_string(justify_dr_hook_dict.size()));
    // }

    
    // void print_dt() {
    //     DebugLog::log("----irq_dt:\n");
    //     for (const auto& irq_dt : irq_dt_set) {
    //         DebugLog::log(std::to_string(irq_dt));
    //     }
        
    //     DebugLog::log("----main_dt:\n");
    //     for (const auto& main_dt : main_dt_set) {
    //         DebugLog::log(std::to_string(main_dt));
    //     }
    // }

    // void write_byte_to_data_reg(const std::vector<int>& valid_dr, const std::vector<char>& get_input) {
    //     // Assuming call_hardware_write_to_descriptor_valid_dr is a function that writes to the hardware
    //     call_hardware_write_to_descriptor_valid_dr(valid_dr, get_input);
    // }

    // void write_to_shared_memory() {
    //     DebugLog::log(">>> write_to_shared_memory");
    //     // Assuming SharedMemory is a class that handles shared memory operations
    //     SharedMemory shm(self.emulation_handler_shared_memory_name);
    //     std::unordered_map<std::string, std::vector<char>> dumps_data_dict;

    //     // Logic to populate dumps_data_dict with necessary data

    //     // Write to shared memory
    //     shm.write(dumps_data_dict);
    // }

    // int get_current_partion(const DataTracker& dt) {
    //     // Generate the latest random partition
    //     random_split_data_input(dt);

    //     int partition = 0;
    //     if (random_split[dt.dr].size() == 1) {
    //         partition = random_split[dt.dr][0];
    //         DebugLog::log("current partition = " + std::to_string(partition));
    //     } else if (random_split[dt.dr].size() > 1) {
    //         partition = random_split[dt.dr].back() - random_split[dt.dr][random_split[dt.dr].size() - 2];
    //         DebugLog::log("current partition = " + std::to_string(partition));
    //     }

    //     DebugLog::log("current random_split = " + std::to_string(random_split[dt.dr].back()));
    //     return partition;
    // }

    // void random_split_data_input(const DataTracker& dt) {
    //     // Logic to initialize or continue from the latest offset
    //     // ...

    //     // Logic to split the input data into random lengths
    //     // ...
    // }

    // void hook_func_escape_data_input(Unicorn& uc, int address, int size, void* user_data) {
    //     DebugLog::log("hook_func_escape_data_input");

    //     // Logic to handle new function and put data
    //     // ...

    //     if (globs.config.symbols.find(address) != globs.config.symbols.end() && escape_funcs.find(address) == escape_funcs.end()) {
    //         escape_funcs.insert(address);
    //         DebugLog::log("put 4 data!");
    //         write_byte_to_data_reg({tmp_dt.dr}, {0xBB, 0xBB, 0xBB, 0xBB});
    //         DebugLog::log(hex(address) + " " + globs.config.symbols[address] + "\n");
    //     }
    // }

    // // Helper function to convert address to hex string
    // std::string to_hex_string(uint64_t value)
    // {
    //     std::stringstream stream;
    //     stream << "0x" << std::hex << value;
    //     return stream.str();
    }



    // You would need to define hook_func_got_buffer_min_len and hook_func_get_head_tail_bufferlen elsewhere in your code.

    // You will need to define the hook functions like hook_func_data_regs_check and hook_func_status_regs_check
    // and any other methods that are used in the Python class
};

// Implement the hook functions and any other helper functions here

int main()
{
    EmulationHandler handler;
    // Set up your emulation environment and start the emulation
    return 0;
}
