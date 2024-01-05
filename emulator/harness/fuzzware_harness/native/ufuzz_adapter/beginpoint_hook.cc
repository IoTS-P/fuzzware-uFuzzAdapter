#include <cstdio>
#include<unicorn/unicorn.h>

void beginpointHook(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    // try to set fork_point_times related to user_input in the future
    printf("beginpointHook");

    // fuzzware_init()

    // EmulationHandler e;
    // e.emulation_handler_shared_memory_name = globs.shared_memory_name;
    // my_debug_log("emulation_handler_shared_memory_name: %s", e.emulation_handler_shared_memory_name);
    // // 获得1个共享内存的名称后，去判断是否存在数据，如果存在则恢复
    // // 共享内存恢复
    // if (e.read_from_shared_memory()) {
    //     e.get_data_from_shared_memory = true;
    // }
    // // 初始化的时候就hook所有的data_regs
    // e.get_callind_addr();
    // e.hook_all_data_regs();

    // // 只用于第一轮，减少开销
    // if (!e.get_data_from_shared_memory) {
    //     e.hook_all_status_regs();
    // }
    // // 一定不能删除，放入一个字节的输入，不然过不去任何判断，！！！！！！！！！！！
    // if (!e.get_data_from_shared_memory) {
    //     // 放入一个数据
    //     e.write_byte_to_data_reg(e.data_regs, {0xBB, 0xBB, 0xBB, 0xBB});
    // }
    // uc_hook_del(RULE.beginpointHook_handler);
}
