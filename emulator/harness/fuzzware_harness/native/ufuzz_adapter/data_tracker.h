
#include <stdint.h>
#ifndef DATA_TRACKER_H
#define DATA_TRACKER_H
// 定义DataTracker结构体
typedef struct DataTracker {
    uint32_t dr; // 数据寄存器的地址
    uint32_t callread_pc; // 调用read函数的pc
    uint32_t read_pc; // 在read函数中调用dr的pc
    uint32_t buffer_addr; // 由dr反映的地址
    // void *consume_pc_set; // 消费dr数据的pc集合
    uint32_t irq_pc; // irq处理程序的pc
    uint32_t avail_pc; // 检查rx缓冲区可用性的pc（由irq处理程序或read_pc计算）
    uint32_t rx_head; // 指向rx缓冲区的头部指针
    uint32_t rx_tail; // 指向rx缓冲区的尾部指针
    short buffer_len; // 缓冲区长度
    short buffer_min_len; // 缓冲区最小长度
    short consume_count; // 消费计数
} DataTracker;

#endif