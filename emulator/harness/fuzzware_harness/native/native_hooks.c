/* Low level unicorn hooks for fuzzing */

/* Porting Considerations
- Memory handlers currently assume shared endianness between host and emulated
target (uc_mem_write)
- ARM thumb instruction set
- System peripherals written for Cortex-M3
*/

#include "native_hooks.h"
#include "core_peripherals/cortexm_nvic.h"
#include "interrupt_triggers.h"
#include "khash.h"
#include "state_snapshotting.h"
#include "timer.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include "uc_snapshot.h"
#include "ufuzz_adapter/data_tracker.h"
#include "util.h"
#include <stdbool.h>
#include <sys/types.h>
#include <unicorn/unicorn.h>

#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/shm.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <stdarg.h>

// 0. Constants
// ~10 MB of preallocated fuzzing buffer size
#define PREALLOCED_FUZZ_BUF_SIZE 10000000
#define MMIO_HOOK_PC_ALL_ACCESS_SITES (0xffffffffuL)
#define DEFAULT_MAX_EXIT_HOOKS 32
#define MMIO_START_UNINIT (0xffffffffffffffffLL)
#define MAX_MMIO_CALLBACKS 4096
#define MAX_IGNORED_ADDRESSES 4096
#define FREAD_NMAX_CHUNKS 5
#define DT_LEARNING_LOG_PATH "/tmp/dt_learning.log"

// AFL-related constants
// 65k bitmap size
#define MAP_SIZE_POW2 16
#define MAP_SIZE (1 << MAP_SIZE_POW2)
#define FORKSRV_FD 198
#define SHM_ENV_VAR "__AFL_SHM_ID"
// AFL++ compatibility constants
#define SHM_FUZZ_ENV_VAR "__AFL_SHM_FUZZ_ID"
#define FS_OPT_SHDMEM_FUZZ 0x01000000
#define FS_OPT_ENABLED 0x80000001

#define CPUID_ADDR 0xE000ED00
const int CPUID_CORTEX_M4 = 0x410fc240;
const int CPUID_CORTEX_M3 = 0x410fc230;

// static int irq_cnt = 1001;
// static int cnt_group_store = 1001;
// int flag = 0;
// int read_count = 0;
// int avali_count = 0;
// int write_count = 0;
// int tk_interrupt = 0;
// static bool exit_code = false;

uc_err mem_errors[] = {
    UC_ERR_READ_UNMAPPED,  UC_ERR_READ_PROT,  UC_ERR_READ_UNALIGNED,
    UC_ERR_WRITE_UNMAPPED, UC_ERR_WRITE_PROT, UC_ERR_WRITE_UNALIGNED,
    UC_ERR_FETCH_UNMAPPED, UC_ERR_FETCH_PROT, UC_ERR_FETCH_UNALIGNED,
};

// 1. Static (after initialization) configs
int do_print_exit_info = 0;

uc_hook invalid_mem_hook_handle = 0;
uc_hook hook_block_cond_py_handlers_handle;
uc_cb_hookcode_t py_hle_handler_hook = (uc_cb_hookcode_t)0;
int num_handlers = 0;
uint64_t *bb_handler_locs = 0;
uint32_t fuzz_consumption_timer_id;
uint64_t fuzz_consumption_timeout;
uint32_t instr_limit_timer_id;
void *py_default_mmio_user_data = NULL;
uint32_t num_mmio_regions = 0;
uint64_t *mmio_region_starts = 0;
uint64_t *mmio_region_ends = 0;
int num_mmio_callbacks = 0;
struct mmio_callback *mmio_callbacks[MAX_MMIO_CALLBACKS];
char *input_path = NULL;
uint32_t num_ignored_addresses = 0;
uint64_t ignored_addresses[MAX_IGNORED_ADDRESSES];
uint32_t ignored_address_pcs[MAX_IGNORED_ADDRESSES];
uint32_t exit_at_hit_limit = 1;

uint32_t do_fuzz = 0;

uint64_t instr_limit = 0;

// 2. Transient variables (not required to be included in state restore)
// Housekeeping information for tracing MMIO accesses
unsigned long latest_mmio_fuzz_access_index = 0;
unsigned long latest_mmio_fuzz_access_size = 0;
uint32_t num_exit_hooks = 0;
exit_hook_t exit_hooks[DEFAULT_MAX_EXIT_HOOKS] = {NULL};

uint32_t is_discovery_child = 0;
static int pipe_to_parent[2] = {-1};

uint8_t *fuzz = NULL;
bool input_mode_SHM = false;
long fuzz_size = 0;
long fuzz_cursor = 0;

// 3. Dynamic State (required for state restore)
uint32_t input_already_given = 0;
int duplicate_exit = false;
uc_err custom_exit_reason = UC_ERR_OK;

// Fuzzer coverage bitmap
uint8_t coverage_bitmap[MAP_SIZE];

// 4. DataTracker declarations
#define DATATRACKER_SIZE 100
extern DataTracker *main_dt_array;
extern DataTracker *irq_dt_array;
extern short main_dt_array_index;
extern short irq_dt_array_index;
DataTracker *main_dt_array = NULL;
DataTracker *irq_dt_array = NULL;

short main_dt_array_index = 0;
short irq_dt_array_index = 0;
uint32_t delivery_X = 0;       // X = 全局最小交付块大小
uint32_t delivery_N = 0;       // N = 估算的交付点数量
uint32_t delivery_LenR = 0;    // LenR = 剩余需求预算
int32_t delivery_LenFI = 0;     // LenFI = 剩余额外预算（可为负）
static bool g_delivery_budget_closed = false;
uint32_t read_times = 0;
uint32_t vtor_num = 0;
uint32_t stop_count = 1;

bool adapter_can_exit = false;
// 定义哈希表的数据类型
KHASH_MAP_INIT_INT(dr_dt, DataTracker *)
khash_t(dr_dt) *hash_table = NULL;

// Channel discovery globals
DataTracker *pending_dt_array = NULL;
short pending_dt_array_index = 0;

uint32_t g_all_dr_addrs[MAX_DR_ADDRS] = {0};
int g_num_dr_addrs = 0;
uint32_t g_all_sr_addrs[MAX_SR_ADDRS] = {0};
int g_num_sr_addrs = 0;

bool g_in_discovery_mode = false;
uint32_t g_discovery_dr = 0;
uint32_t g_discovery_taint = 0;
uint32_t g_discovery_irq_pc = 0;
uint32_t g_discovery_addr_list[MAX_DISCOVERY_ADDRS] = {0};
int g_discovery_addr_count = 0;
uint32_t g_discovery_buffer_addr = 0;
uc_hook g_discovery_mem_write_hook = 0;
bool g_discovery_occurred = false;
char g_json_file_path[512] = {0};

// Phase 0: buffer-addr discovery (taint tracking, no refill)
// After buffer_addr is found, capture read_pc/callread_pc in the main loop.
uint32_t g_discovery_read_pc = 0;
uint32_t g_discovery_callread_pc = 0;
uc_hook g_discovery_buffer_read_hook = 0;
bool g_read_pc_done = false;

// Post-static-analysis bound learning state:
// after Ghidra fills avail_pc/consume_pc_set, learn buffer_min_len and
// buffer_len from avail_pc-triggered IRQ writes into the discovered buffer.
#define BOUNDS_FIFO_SIZE 4096
#define BOUNDS_MAX_SCAN 4096
#define BOUNDS_MISS_LIMIT 5
#define BOUNDS_MAX_IRQ_PENDS BOUNDS_FIFO_SIZE
#define BOUNDS_CONSUMER_LOG_LIMIT 256
#define BOUNDS_DIAG_HOOK_MAX 8
#ifndef DT_DIAG_HOOK_ENABLE
#define DT_DIAG_HOOK_ENABLE 0
#endif
#ifndef BOUNDS_PC_TRACE_ENABLE
#define BOUNDS_PC_TRACE_ENABLE 0
#endif
#define BOUNDS_PC_TRACE_LIMIT 200000
static int g_bounds_state = 0;       // 0=IDLE, 1=INFERRING
static int g_bounds_dt_idx = -1;
static uint32_t g_bounds_dt_dr = 0;
static int g_bounds_irq = 0;
static bool g_bounds_avail_hit = false;
static bool g_bounds_avail_pass_next = false;
static bool g_bounds_fifo_seeded = false;
static bool g_bounds_chain_started = false;
static uint32_t g_bounds_chain_min = 0;
static uint32_t g_bounds_chain_max = 0;
static int g_bounds_miss_count = 0;
static int g_bounds_irq_pend_count = 0;
static int g_bounds_dr_read_log_count = 0;
static int g_bounds_taint_write_log_count = 0;
static bool g_bounds_need_upper = false;
static bool g_bounds_need_min = false;
static bool g_bounds_upper_done = false;
static short g_bounds_upper_len = 0;
static bool g_bounds_min_done = false;
static short g_bounds_min_len = 0;
static bool g_bounds_preparing_exit = false;
static int g_bounds_consumer_log_count = 0;
static uint32_t g_bounds_read_entry_guess_pc = 0;
static uc_hook g_bounds_dispatch_hook = 0;
static uint64_t g_code_hook_begin = 1;
static uint64_t g_code_hook_end = 0;
static uc_hook g_bounds_write_hook = 0;
static uint32_t g_bounds_consume_pcs[16] = {0};
static int g_bounds_num_consume_pcs = 0;
typedef struct {
  uint32_t pc;
  uc_cb_hookcode_t cb;
  const char *name;
} BoundsDiagDispatchEntry;
static BoundsDiagDispatchEntry g_bounds_diag_entries[BOUNDS_DIAG_HOOK_MAX] = {0};
static int g_bounds_num_diag_hooks = 0;
#if BOUNDS_PC_TRACE_ENABLE
static FILE *g_bounds_pc_trace_fp = NULL;
static uint32_t g_bounds_pc_trace_round = 0;
static uint32_t g_bounds_pc_trace_count = 0;
#endif

static void hook_bounds_avail(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_bounds_buffer_write(uc_engine *uc, uc_mem_type type,
    uint64_t address, int size, int64_t value, void *user_data);
static void hook_bounds_consume(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
#if BOUNDS_PC_TRACE_ENABLE
static void hook_bounds_pc_trace(uc_engine *uc, uint64_t address,
    uint32_t size, void *user_data);
#endif
#if DT_DIAG_HOOK_ENABLE
static void hook_bounds_avail_return(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_bounds_process_call(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_bounds_callread_before(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_bounds_callread_return(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_bounds_read_entry_guess(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_bounds_read_pc_diag(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
#endif
static void hook_bounds_dispatch(uc_engine *uc, uint64_t address,
    uint32_t size, void *user_data);
static bool dispatch_complete_dt_avail_hook(uc_engine *uc, uint32_t pc,
    uint64_t address, uint32_t size);
static void bounds_prepare_retry_on_exit(uc_engine *uc, const char *reason);
static void bounds_finish_round(uc_engine *uc, const char *reason);
static DataTracker *bounds_find_dt(void);
static bool start_bounds_learning_if_needed(uc_engine *uc);
uc_err main_proc_avail_hook_handler(uc_engine *uc, uint64_t pc, uint32_t size,
                                    void *user_data);
uc_err irq_avail_hook_handler(uc_engine *uc, uint64_t pc, uint32_t size,
                              void *user_data);

static void dt_learning_log(const char *fmt, ...) {
  FILE *fp = fopen(DT_LEARNING_LOG_PATH, "a");
  if (!fp) return;

  va_list args;
  va_start(args, fmt);
  vfprintf(fp, fmt, args);
  va_end(args);
  fputc('\n', fp);
  fclose(fp);
}

#ifndef DT_DELIVERY_LOG_ENABLE
#define DT_DELIVERY_LOG_ENABLE 1
#endif

static void delivery_log(const char *fmt, ...) {
#if DT_DELIVERY_LOG_ENABLE
  FILE *fp = fopen(DT_LEARNING_LOG_PATH, "a");
  if (!fp) return;

  fputs("[DELIVERY] ", fp);
  va_list args;
  va_start(args, fmt);
  vfprintf(fp, fmt, args);
  va_end(args);
  fputc('\n', fp);
  fclose(fp);
#else
  (void)fmt;
#endif
}

#if BOUNDS_PC_TRACE_ENABLE
static void hook_bounds_pc_trace(uc_engine *uc, uint64_t address,
    uint32_t size, void *user_data) {
  (void)user_data;
  if (g_bounds_state != 1 || !g_bounds_pc_trace_fp) return;
  if (g_bounds_pc_trace_count >= BOUNDS_PC_TRACE_LIMIT) return;

  uint32_t pc = (uint32_t)address & ~1u;

  uint32_t ipsr = 0;
  uc_reg_read(uc, UC_ARM_REG_IPSR, &ipsr);

  fprintf(g_bounds_pc_trace_fp,
          "round=%u idx=%u pc=0x%x size=0x%x ipsr=0x%x avail_hit=%d pends=%d cursor=%ld/%ld\n",
          g_bounds_pc_trace_round,
          g_bounds_pc_trace_count,
          pc,
          size,
          ipsr,
          g_bounds_avail_hit ? 1 : 0,
          g_bounds_irq_pend_count,
          fuzz_cursor,
          fuzz_size);
  g_bounds_pc_trace_count++;
}
#endif

static void hook_bounds_dispatch(uc_engine *uc, uint64_t address,
    uint32_t size, void *user_data) {
  uint32_t pc = (uint32_t)address & ~1u;

#if BOUNDS_PC_TRACE_ENABLE
  if (g_bounds_state == 1) {
    hook_bounds_pc_trace(uc, address, size, user_data);
  }
#endif

  if (g_bounds_state == 1) {
    DataTracker *dt = bounds_find_dt();
    if (dt) {
      if (pc == dt->avail_pc) {
        hook_bounds_avail(uc, address, size, user_data);
        dispatch_complete_dt_avail_hook(uc, pc, address, size);
        return;
      }

      for (int i = 0; i < g_bounds_num_consume_pcs; i++) {
        if (pc == g_bounds_consume_pcs[i]) {
          hook_bounds_consume(uc, address, size, user_data);
          return;
        }
      }
    }
  }

#if DT_DIAG_HOOK_ENABLE
  if (g_bounds_state == 1) {
    for (int i = 0; i < g_bounds_num_diag_hooks; i++) {
      BoundsDiagDispatchEntry *entry = &g_bounds_diag_entries[i];
      if (entry->pc == pc && entry->cb) {
        entry->cb(uc, address, size, user_data);
      }
    }
  }
#endif

  dispatch_complete_dt_avail_hook(uc, pc, address, size);
}

static bool bounds_should_log_dr_fifo(uint64_t addr) {
  return g_bounds_state == 1 &&
         (uint32_t)addr == g_bounds_dt_dr &&
         g_bounds_dr_read_log_count < 64;
}

static void bounds_log_dr_fifo_read(uc_engine *uc, const char *source,
    uint64_t addr, int size, uint64_t raw_val, uint64_t result_val,
    DataTracker *dt) {
  if (!bounds_should_log_dr_fifo(addr)) return;

  uint32_t pc = 0;
  uint32_t ipsr = 0;
  uc_reg_read(uc, UC_ARM_REG_PC, &pc);
  uc_reg_read(uc, UC_ARM_REG_IPSR, &ipsr);
  dt_learning_log("[BOUNDS] DR_READ_FIFO source=%s pc=0x%x ipsr=0x%x "
                  "dr=0x%lx size=%d raw=0x%llx result=0x%llx "
                  "fifo_tail=%d fifo_head=%d",
                  source, pc, ipsr, addr, size,
                  (unsigned long long)raw_val,
                  (unsigned long long)result_val,
                  dt->fifo_tail, dt->fifo_head);
  g_bounds_dr_read_log_count++;
}

static void bounds_log_dr_fifo_empty(uc_engine *uc, const char *source,
    uint64_t addr, int size, DataTracker *dt) {
  if (!bounds_should_log_dr_fifo(addr)) return;

  uint32_t pc = 0;
  uint32_t ipsr = 0;
  uc_reg_read(uc, UC_ARM_REG_PC, &pc);
  uc_reg_read(uc, UC_ARM_REG_IPSR, &ipsr);
  dt_learning_log("[BOUNDS] DR_READ_FIFO_EMPTY source=%s pc=0x%x ipsr=0x%x "
                  "dr=0x%lx size=%d fifo_tail=%d fifo_head=%d",
                  source, pc, ipsr, addr, size,
                  dt->fifo_tail, dt->fifo_head);
  g_bounds_dr_read_log_count++;
}

// Ghidra static analysis callback
static void *g_ghidra_callback = NULL;
typedef struct {
  uint32_t pc;
  DataTracker *dt;
  bool is_main;
} AvailDispatchEntry;
static AvailDispatchEntry g_avail_dispatch_entries[MAX_AVAIL_HOOKS] = {0};
int g_num_avail_hooks = 0;
uc_hook g_pending_hook_handles[MAX_PENDING_HOOKS] = {0};
int g_num_pending_hooks = 0;

// 前向声明
void init_delivery_budget(void);
int compute_delivery_size(DataTracker *dt);
bool is_irq_managed_by_dt(int irq_num);
static void finalize_discovery(uc_engine *uc);
static void try_finalize(uc_engine *uc);
void hook_discovery_mem_write(uc_engine *uc, uc_mem_type type,
    uint64_t address, int size, int64_t value, void *user_data);
void hook_phase1_buffer_read(uc_engine *uc, uc_mem_type type,
    uint64_t address, int size, int64_t value, void *user_data);

static void determine_input_mode() {
  char *id_str;
  int shm_id;
  int tmp;

  id_str = getenv(SHM_FUZZ_ENV_VAR);
  if (id_str) {
    shm_id = atoi(id_str);
    fuzz = shmat(shm_id, NULL, 0);
    if (!fuzz || fuzz == (void *)-1) {
      perror("[!] could not access fuzzing shared memory");
      exit(1);
    }

    // AFL++ detected. Read its status value
    if (read(FORKSRV_FD, &tmp, 4) != 4) {
      perror("[!] did not receive AFL++ status value");
      exit(1);
    }

    input_mode_SHM = true;
  }
}

void do_exit(uc_engine *uc, uc_err err) {
  if (g_bounds_state == 1 && !g_bounds_preparing_exit) {
    bounds_prepare_retry_on_exit(uc, "do_exit");
  }

  printf("[EXIT] cursor=%ld/%ld fuzz_size=%ld read_times=%d\n",
         fuzz_cursor, fuzz_size, fuzz_size, read_times);

  // Clean up discovery hooks if still active
  if (g_in_discovery_mode) {
    if (g_discovery_mem_write_hook) {
      uc_hook_del(uc, g_discovery_mem_write_hook);
      g_discovery_mem_write_hook = 0;
    }
    if (g_discovery_buffer_read_hook) {
      uc_hook_del(uc, g_discovery_buffer_read_hook);
      g_discovery_buffer_read_hook = 0;
    }
    g_in_discovery_mode = false;
  }

  reset_datatrcker_and_global_vars();
  if (do_print_exit_info) {
    fflush(stdout);
  }
  if (!duplicate_exit) {
    custom_exit_reason = err;
    duplicate_exit = true;
    uc_emu_stop(uc);
  }
}

void hook_block_debug(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    uint32_t lr;
    uint32_t r0;
    // static int cnt_store = 101;
    uc_reg_read(uc, UC_ARM_REG_LR, &lr);
    uc_reg_read(uc, UC_ARM_REG_R0, &r0);

    printf("Basic Block: addr= 0x%016lx (lr=0x%x)\n", address, lr);
    printf("$$$r0: (R0=0x%x)\n",r0);

    // if (address == 525764)do_exit(uc, UC_ERR_OK);

    // if (address== 529382){
    //     cnt_group_store--;
    //     // printf("***cnt_store: %d\n",irq_cnt);
    //     printf("***cnt_group_store: %d\n",cnt_group_store);
    //     if (cnt_group_store == 0){
    //       // exit_code = true;
    //       printf("ready to exit\n");
    //       do_exit(uc, UC_ERR_OK);
    //     }
    // }

    // if (address == 529400) {
    //   flag = 1;
    // }

    // if (address == 529462) {
    //   read_count++;
    // }

    // if (address == 529416) {
    //   avali_count++;
    // }

    // if (address == 529528) {
    //   write_count++;
    // }
    // if (address== 528){
    //   do_exit(uc, UC_ERR_OK);
    // }
    fflush(stdout);
}

void hook_debug_mem_access(uc_engine *uc, uc_mem_type type, uint64_t address,
                           int size, int64_t value, void *user_data) {
  uint32_t pc, sp;
  uc_reg_read(uc, UC_ARM_REG_SP, &sp);
  uc_reg_read(uc, UC_ARM_REG_PC, &pc);

  int64_t sp_offset = sp - address;
  if (sp_offset > -0x1000 && sp_offset < 0x2000) {
    if (type == UC_MEM_WRITE) {
      printf("        >>> Write: addr= 0x%08lx[SP:%c%04lx] size=%d "
             "data=0x%08lx (pc 0x%08x)\n",
             address, sp_offset >= 0 ? '+' : '-',
             sp_offset >= 0 ? sp_offset : -sp_offset, size, value, pc);
    } else {
      uint32_t read_value = 0;
      uc_mem_read(uc, address, &read_value, size);
      printf("        >>> Read: addr= 0x%08lx[SP:%c%04lx] size=%d data=0x%08x "
             "(pc 0x%08x)\n",
             address, sp_offset >= 0 ? '+' : '-',
             sp_offset >= 0 ? sp_offset : -sp_offset, size, read_value, pc);
    }
  } else {
    if (type == UC_MEM_WRITE) {
      printf("        >>> Write: addr= 0x%016lx size=%d data=0x%08lx (pc "
             "0x%08x)\n",
             address, size, value, pc);
    } else {
      uint32_t read_value = 0;
      uc_mem_read(uc, address, &read_value, size);
      printf(
          "        >>> Read: addr= 0x%016lx size=%d data=0x%08x (pc 0x%08x)\n",
          address, size, read_value, pc);
    }
  }
  fflush(stdout);
}

uc_err add_debug_hooks(uc_engine *uc) {
  uc_hook tmp;
  uc_err res = UC_ERR_OK;
  // Register unconditional hook for checking for handler presence
  res |= uc_hook_add(uc, &tmp, UC_HOOK_BLOCK_UNCONDITIONAL, hook_block_debug,
                     NULL, 1, 0);
  res |= uc_hook_add(uc, &tmp, UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ,
                     hook_debug_mem_access, 0, 1, 0);
  return res;
}

bool hook_debug_mem_invalid_access(uc_engine *uc, uc_mem_type type,
                                   uint64_t address, int size, int64_t value,
                                   void *user_data) {
  uint64_t pc = 0;
  uc_reg_read(uc, UC_ARM_REG_PC, &pc);
  if (type == UC_MEM_WRITE_UNMAPPED || type == UC_MEM_WRITE_PROT) {
    printf("        >>> [ 0x%08lx ] INVALID Write: addr= 0x%016lx size=%d "
           "data=0x%016lx\n",
           pc, address, size, value);
  } else if (type == UC_MEM_READ_UNMAPPED || type == UC_MEM_READ_PROT) {
    printf("        >>> [ 0x%08lx ] INVALID READ: addr= 0x%016lx size=%d "
           "data=0x%016lx\n",
           pc, address, size, value);
  } else if (type == UC_MEM_FETCH_UNMAPPED || type == UC_MEM_FETCH_PROT) {
    printf("        >>> [ 0x%08lx ] INVALID FETCH: addr= 0x%016lx\n", pc,
           address);
  }
  fflush(stdout);
  return false;
}

int uc_err_to_sig(uc_err error) {
  for (uint32_t i = 0; i < sizeof(mem_errors) / sizeof(*mem_errors); ++i) {
    if (error == mem_errors[i]) {
      return SIGSEGV;
    }
  }
  if (error == UC_ERR_INSN_INVALID) {
    return SIGILL;
  } else {
    return SIGABRT;
  }
}

void force_crash(uc_engine *uc, uc_err error) { printf("there is force crash.\n");do_exit(uc, error); }

void hook_block_exit_at(uc_engine *uc, uint64_t address, uint32_t size,
                        void *user_data) {
  if (++native_hooks_state.curr_exit_at_hit_num == exit_at_hit_limit) {
    if (do_print_exit_info) {
      printf("Hit exit basic block address: %08lx, times: %d\n", address,
             native_hooks_state.curr_exit_at_hit_num);
      fflush(stdout);
    }
    printf("hook_block_exit_at called\n");
    do_exit(uc, UC_ERR_OK);
  }
}

void load_delayed_input(uc_engine *uc) {
  // Having spun up the fork server, we can now load the input file
  if (load_fuzz(input_path) != 0) {
    _exit(-1);
  }

  input_already_given = 1;
}

bool get_fuzz(uc_engine *uc, uint8_t *buf, uint32_t size) {
/*
 * Consuming input is more complex here than one might expect.
 * The reason for this is that we support a prefix input as well
 * as detecting the number of basic blocks that we can execute
 * before consuming fuzzing input.
 *
 * a) The ordinary case is having input, consuming it, and progressing
 * the cursor as one would expect.
 * b) The second case makes the discovery child report the number of
 * translation blocks to run as part of the execution prefix as soon
 * as new fuzzing input would have to be consumed.
 * c) Once after a snapshot, we want to load the fuzzing input. We
 * do this in a delayed manner to support pre-loaded prefix inputs
 * (which are consumed as part of the execution prefix).
 * d) In case we have already loaded the dynamic input once, we
 * finally ran out of input to provide and conclude the run.
 */
#ifdef DEBUG
  printf("[NATIVE FUZZ] Requiring %d fuzz bytes\n", size);
  fflush(stdout);
#endif
// #ifdef MYDEBUG
// char mybuf[100];
// uint32_t myipsr = 0;
// uc_reg_read(uc, UC_ARM_REG_IPSR, &myipsr);
// sprintf(mybuf, "myipsr = %x\n", myipsr);
// my_debug_log(mybuf);
// #endif

  // Deal with copying over the (remaining) fuzzing bytes
  if (size && fuzz_cursor + size <= fuzz_size) {
#ifdef DEBUG
    printf("[NATIVE FUZZ] Returning %d fuzz bytes\n", size);
    fflush(stdout);
#endif
    memcpy(buf, &fuzz[fuzz_cursor], size);
    fuzz_cursor += size;

    // We are consuming fuzzing input, reset watchdog
    reload_timer(fuzz_consumption_timer_id);

    return 0;
  } else if (unlikely(is_discovery_child)) {
    // We are the discovery child, report the current tick count
    uint64_t ticks_so_far = get_global_ticker();
    if (write(pipe_to_parent[1], &ticks_so_far, sizeof(ticks_so_far)) !=
        sizeof(ticks_so_far)) {
      puts(
          "[Discovery Child] Error: could not write number of ticks to parent");
      fflush(stdout);
    }
    _exit(0);
  } else if (!input_already_given) {
    // Load file-based input now
    load_delayed_input(uc);

    return get_fuzz(uc, buf, size);
  } else {
    // 部分耗尽：还有剩余数据但不够请求大小，返回可用的
    if (size && fuzz_cursor < fuzz_size) {
      uint32_t remaining = fuzz_size - fuzz_cursor;
      memcpy(buf, &fuzz[fuzz_cursor], remaining);
      fuzz_cursor += remaining;
      reload_timer(fuzz_consumption_timer_id);
      return 0;
    }
    // 真正耗尽
    if (do_print_exit_info) {
      puts("\n>>> Ran out of fuzz\n");
      do_exit(uc, UC_ERR_OK);
    }
    // printf("get_fuzz called do_exit\n");
    // do_exit(uc, UC_ERR_OK);
    return 1;
  }
}

uint32_t fuzz_consumed() { return fuzz_cursor; }

uint8_t *get_fuzz_ptr(uc_engine *uc, uint32_t size) {
#ifdef DEBUG
  printf("[NATIVE FUZZ] Requiring %d fuzz bytes\n", size);
  fflush(stdout);
#endif

  // Deal with handing out pointer to fuzzing bytes
  if (size && fuzz_cursor + size <= fuzz_size) {
#ifdef DEBUG
    printf("[NATIVE FUZZ] Returning %d fuzz bytes\n", size);
    fflush(stdout);
#endif
    uint8_t *res = &fuzz[fuzz_cursor];
    fuzz_cursor += size;

    // We are consuming fuzzing input, reset watchdog
    reload_timer(fuzz_consumption_timer_id);

    return res;
  } else if (unlikely(is_discovery_child)) {
    // We are the discovery child, report the current tick count
    uint64_t ticks_so_far = get_global_ticker();
    if (write(pipe_to_parent[1], &ticks_so_far, sizeof(ticks_so_far)) !=
        sizeof(ticks_so_far)) {
      puts(
          "[Discovery Child] Error: could not write number of ticks to parent");
      fflush(stdout);
    }
    _exit(0);
  } else if (!input_already_given) {
    // Load file-based input now
    load_delayed_input(uc);

    return get_fuzz_ptr(uc, size);
  } else {
    if (do_print_exit_info) {
      puts("\n>>> Ran out of fuzz\n");
      fflush(stdout);
    }
    my_debug_log("do_exit:ran out of fuzz\n");
    fuzz_cursor = 0;
    if (size && fuzz_cursor + size <= fuzz_size) {
      uint8_t *res = &fuzz[fuzz_cursor];
      fuzz_cursor += size;

      // We are consuming fuzzing input, reset watchdog
      reload_timer(fuzz_consumption_timer_id);

      return res;
    }
    printf("get_fuzz_ptr called do_exit\n");
    do_exit(uc, UC_ERR_OK);
    return NULL;
  }
}

uint32_t get_latest_mmio_fuzz_access_index() {
  return latest_mmio_fuzz_access_index;
}

uint32_t get_latest_mmio_fuzz_access_size() {
  return latest_mmio_fuzz_access_size;
}

uint32_t fuzz_remaining() { return fuzz_size - fuzz_cursor; }

void hook_mmio_access(uc_engine *uc, uc_mem_type type, uint64_t addr, int size,
                      int64_t value, void *user_data) {
  uint32_t pc = 0;
  latest_mmio_fuzz_access_index = fuzz_cursor;

  uc_reg_read(uc, UC_ARM_REG_PC, &pc);

  // TODO: optimize this lookup
  for (int i = 0; i < num_ignored_addresses; ++i) {
    if (addr == ignored_addresses[i] &&
        (ignored_address_pcs[i] == MMIO_HOOK_PC_ALL_ACCESS_SITES ||
         ignored_address_pcs[i] == pc)) {
#ifdef DEBUG
      printf("Hit passthrough address 0x%08lx - pc: 0x%08x - returning\n", addr,
             pc);
      fflush(stdout);
#endif
      goto out;
    }
  }

  for (int i = 0; i < num_mmio_callbacks; ++i) {
    if (addr >= mmio_callbacks[i]->start && addr <= mmio_callbacks[i]->end &&
        (mmio_callbacks[i]->pc == MMIO_HOOK_PC_ALL_ACCESS_SITES ||
         mmio_callbacks[i]->pc == pc)) {
      if (mmio_callbacks[i]->user_data != NULL) {
        user_data = mmio_callbacks[i]->user_data;
      }

      mmio_callbacks[i]->callback(uc, type, addr, size, value, user_data);
      goto out;
    }
  }

#ifdef DEBUG
  printf("Serving %d byte(s) fuzz for mmio access to 0x%08lx, pc: 0x%08x, rem "
         "bytes: %ld\n",
         size, addr, pc, fuzz_size - fuzz_cursor);
  fflush(stdout);
#endif

  uint64_t val = 0;

  // 兜底：DT FIFO 优先，get_fuzz 后备
  if (hash_table != NULL) {
    khint_t k = kh_get(dr_dt, hash_table, addr);
    if (k != kh_end(hash_table)) {
      DataTracker *dt = kh_value(hash_table, k);
      if (!fifo_get_fuzz(uc, dt, (uint8_t *)&val, size)) {
        bounds_log_dr_fifo_read(uc, "default", addr, size, val, val, dt);
        goto write_val;
      }
      bounds_log_dr_fifo_empty(uc, "default", addr, size, dt);
    }
  }
  if (get_fuzz(uc, (uint8_t *)&val, size)) {
    return;
  }
write_val:
  uc_mem_write(uc, addr, (uint8_t *)&val, size);

out:

  latest_mmio_fuzz_access_size = fuzz_cursor - latest_mmio_fuzz_access_index;
  return;
}

void add_exit_hook(exit_hook_t hook) {
  if (num_exit_hooks == DEFAULT_MAX_EXIT_HOOKS) {
    perror("ERROR. add_exit_hook: Out of exit hook slots\n");
    exit(-1);
  }
  exit_hooks[num_exit_hooks++] = hook;
}

uc_err add_mmio_region(uc_engine *uc, uint64_t begin, uint64_t end) {
  if (!py_default_mmio_user_data) {
    perror("ERROR. add_mmio_region: py_default_mmio_user_data is NULL (did you "
           "not register handler first?)\n");
    return UC_ERR_EXCEPTION;
  }

  uc_hook tmp;
  printf("add_mmio_region called! hooking 0x%08lx - 0x%08lx\n", begin, end);
  return uc_hook_add(uc, &tmp, UC_HOOK_MEM_READ, hook_mmio_access,
                     py_default_mmio_user_data, begin, end);
}

void hook_block_cond_py_handlers(uc_engine *uc, uint64_t address, uint32_t size,
                                 void *user_data) {
  uint64_t next_val;

  // Search for address in value list and invoke python handler if found
  for (int i = 0; i < num_handlers; ++i) {
    next_val = bb_handler_locs[i];
    if (next_val > address) {
      break;
    } else if (next_val == address) {
      py_hle_handler_hook(uc, address, size, user_data);
    }
  }
}

uc_err register_cond_py_handler_hook(uc_engine *uc,
                                     uc_cb_hookcode_t py_mmio_callback,
                                     uint64_t *addrs, int num_addrs,
                                     void *user_data) {
  py_hle_handler_hook = py_mmio_callback;
  num_handlers = num_addrs;

  bb_handler_locs = malloc(num_addrs * sizeof(uint64_t));
  if (!bb_handler_locs) {
    perror("allocating handler location struct failed\n");
    return -1;
  }

  memcpy(bb_handler_locs, addrs, num_addrs * sizeof(uint64_t));

  // shouldn't be many entries, just sort ascending this way
  for (int i = 0; i < num_addrs; i++) {
    for (int j = 0; j < num_addrs; j++) {
      if (bb_handler_locs[j] > bb_handler_locs[i]) {
        uint64_t tmp = bb_handler_locs[i];
        bb_handler_locs[i] = bb_handler_locs[j];
        bb_handler_locs[j] = tmp;
      }
    }
  }

  // Register unconditional hook for checking for handler presence
  return uc_hook_add(uc, &hook_block_cond_py_handlers_handle,
                     UC_HOOK_BLOCK_UNCONDITIONAL, hook_block_cond_py_handlers,
                     user_data, 1, 0);
}

uc_err remove_function_handler_hook_address(uc_engine *uc, uint64_t address) {
  for (int i = 0; i < num_handlers; i++) {
    if (bb_handler_locs[i] == address) {
      // Found the handler location, now move everything else to the front
      for (int j = i; j < num_handlers - 1; ++j) {
        bb_handler_locs[j] = bb_handler_locs[j + 1];
      }

      --num_handlers;
      // Now fully remove the (unconditional) hook if we can
      if (!num_handlers) {
        uc_hook_del(uc, hook_block_cond_py_handlers_handle);
      }
      return UC_ERR_OK;
    }
  }

  perror("[NATIVE ERROR] remove_function_handler_hook_address: could not find "
         "address to be removed\n");
  exit(-1);
}

uc_err register_py_handled_mmio_ranges(uc_engine *uc,
                                       uc_cb_hookmem_t py_mmio_callback,
                                       uint64_t *starts, uint64_t *ends,
                                       int num_ranges) {
  uint64_t start, end;

  if (py_default_mmio_user_data == NULL) {
    perror("ERROR. register_py_handled_mmio_ranges: python user data pointer "
           "not set up (did you forget to call init before?)\n");
    return UC_ERR_EXCEPTION;
  }

  for (int i = 0; i < num_ranges; ++i) {
    start = starts[i];
    end = ends[i];
    if (add_mmio_subregion_handler(uc, py_mmio_callback, start, end,
                                   MMIO_HOOK_PC_ALL_ACCESS_SITES,
                                   py_default_mmio_user_data) != UC_ERR_OK) {
      return UC_ERR_EXCEPTION;
    }
  }

  return UC_ERR_OK;
}

void linear_mmio_model_handler(uc_engine *uc, uc_mem_type type, uint64_t addr,
                               int size, int64_t value, void *user_data) {
  struct linear_mmio_model_config *model_state =
      (struct linear_mmio_model_config *)user_data;

  model_state->val += model_state->step;

#ifdef DEBUG
  uint32_t pc;
  uc_reg_read(uc, UC_ARM_REG_PC, &pc);
  printf("[0x%08x] Native Linear MMIO handler: [0x%08lx] = [0x%x]\n", pc, addr,
         model_state->val);
  fflush(stdout);
#endif

  uc_mem_write(uc, addr, &model_state->val, sizeof(model_state->val));
}

void constant_mmio_model_handler(uc_engine *uc, uc_mem_type type, uint64_t addr,
                                 int size, int64_t value, void *user_data) {
  struct constant_mmio_model_config *model_state =
      (struct constant_mmio_model_config *)user_data;
  uint64_t val = model_state->val;

#ifdef DEBUG
  uint32_t pc;
  uc_reg_read(uc, UC_ARM_REG_PC, &pc);
  printf("[0x%08x] Native Constant MMIO handler: [0x%08lx] = [0x%lx]\n", pc,
         addr, val);
  fflush(stdout);
#endif

  // TODO: This assumes shared endianness between host and target
  uc_mem_write(uc, addr, &val, size);
}

void bitextract_mmio_model_handler(uc_engine *uc, uc_mem_type type,
                                   uint64_t addr, int size, int64_t value,
                                   void *user_data) {
  struct bitextract_mmio_model_config *config =
      (struct bitextract_mmio_model_config *)user_data;
  uint64_t result_val = 0;
  uint64_t fuzzer_val = 0;
  DataTracker *fifo_dt = NULL;
  bool fifo_used = false;

  // 数据源选择：DT FIFO 优先，get_fuzz 后备
  if (hash_table != NULL) {
    khint_t k = kh_get(dr_dt, hash_table, addr);
    if (k != kh_end(hash_table)) {
      DataTracker *dt = kh_value(hash_table, k);
      if (!fifo_get_fuzz(uc, dt, (uint8_t *)(&fuzzer_val), config->byte_size)) {
        fifo_dt = dt;
        fifo_used = true;
        goto apply_model;
      }
      bounds_log_dr_fifo_empty(uc, "bitextract", addr, config->byte_size, dt);
    }
  }
  if (get_fuzz(uc, (uint8_t *)(&fuzzer_val), config->byte_size)) {
    return;
  }

apply_model:
  result_val = fuzzer_val << config->left_shift;
  if (fifo_used) {
    bounds_log_dr_fifo_read(uc, "bitextract", addr, config->byte_size,
                            fuzzer_val, result_val, fifo_dt);
  }

#ifdef DEBUG
  uint32_t _pc;
  uc_reg_read(uc, UC_ARM_REG_PC, &_pc);
  printf("[0x%08x] Native Bitextract MMIO handler: [0x%08lx] = [0x%lx] "
         "from %d byte input: %lx\n",
         _pc, addr, result_val, config->byte_size, fuzzer_val);
  fflush(stdout);
#endif

  uc_mem_write(uc, addr, &result_val, size);
}

void value_set_mmio_model_handler(uc_engine *uc, uc_mem_type type,
                                  uint64_t addr, int size, int64_t value,
                                  void *user_data) {
  struct value_set_mmio_model_config *config =
      (struct value_set_mmio_model_config *)user_data;

  uint64_t result_val;
  uint8_t fuzzer_val = 0;
  DataTracker *fifo_dt = NULL;
  bool fifo_used = false;
  // #ifdef DEBUG
  uint32_t pc;
  uc_reg_read(uc, UC_ARM_REG_PC, &pc);
  // #endif

  if (config->num_vals > 1) {
    // 数据源选择：DT FIFO 优先，get_fuzz 后备
    if (hash_table != NULL) {
      khint_t k = kh_get(dr_dt, hash_table, addr);
      if (k != kh_end(hash_table)) {
        DataTracker *dt = kh_value(hash_table, k);
        if (!fifo_get_fuzz(uc, dt, (uint8_t *)&fuzzer_val, 1)) {
          fifo_dt = dt;
          fifo_used = true;
          goto apply_value_set;
        }
        bounds_log_dr_fifo_empty(uc, "value_set", addr, 1, dt);
      }
    }
    if (get_fuzz(uc, (uint8_t *)&fuzzer_val, 1)) {
      return;
    }
apply_value_set:
    result_val = config->values[fuzzer_val % config->num_vals];
    if (fifo_used) {
      bounds_log_dr_fifo_read(uc, "value_set", addr, 1, fuzzer_val,
                              result_val, fifo_dt);
    }
  } else {
    result_val = config->values[0];
  }

#ifdef DEBUG
  printf("[0x%08x] Native Set MMIO handler: [0x%08lx] = [0x%lx] from input: %x "
         "[values: ",
         pc, addr, result_val, fuzzer_val);
  for (uint32_t i = 0; i < config->num_vals; ++i) {
    if (i) {
      printf(", ");
    }
    printf("%x", config->values[i]);
  }
  printf("]\n");
  fflush(stdout);
#endif
  uc_mem_write(uc, addr, (uint8_t *)&result_val, size);
}

uc_err register_constant_mmio_models(uc_engine *uc, uint64_t *starts,
                                     uint64_t *ends, uint32_t *pcs,
                                     uint32_t *vals, int num_ranges) {
  struct constant_mmio_model_config *model_configs =
      calloc(num_ranges, sizeof(struct constant_mmio_model_config));

  for (int i = 0; i < num_ranges; ++i) {
#ifdef DEBUG
    printf(
        "Registering constant model for range: [%x] %lx - %lx with val: %x\n",
        pcs[i], starts[i], ends[i], vals[i]);
    fflush(stdout);
#endif

    model_configs[i].val = vals[i];

    if (add_mmio_subregion_handler(uc, constant_mmio_model_handler, starts[i],
                                   ends[i], pcs[i],
                                   &model_configs[i]) != UC_ERR_OK) {
      return UC_ERR_EXCEPTION;
    }
  }

  return UC_ERR_OK;
}

uc_err register_linear_mmio_models(uc_engine *uc, uint64_t *starts,
                                   uint64_t *ends, uint32_t *pcs,
                                   uint32_t *init_vals, uint32_t *steps,
                                   int num_ranges) {
  // TODO: support cleanup, currently we just allocate, hand out pointers and
  // forget about them
  struct linear_mmio_model_config *model_configs =
      calloc(num_ranges, sizeof(struct linear_mmio_model_config));

  for (int i = 0; i < num_ranges; ++i) {
#ifdef DEBUG
    printf("Registering linear model for range: [%x] %lx - %lx with step: %x\n",
           pcs[i], starts[i], ends[i], steps[i]);
    fflush(stdout);
#endif
    model_configs[i].val = init_vals[i];
    model_configs[i].step = steps[i];

    if (add_mmio_subregion_handler(uc, linear_mmio_model_handler, starts[i],
                                   ends[i], pcs[i],
                                   &model_configs[i]) != UC_ERR_OK) {
      return UC_ERR_EXCEPTION;
    }
  }

  return UC_ERR_OK;
}

uc_err register_bitextract_mmio_models(uc_engine *uc, uint64_t *starts,
                                       uint64_t *ends, uint32_t *pcs,
                                       uint8_t *byte_sizes,
                                       uint8_t *left_shifts, uint32_t *masks,
                                       int num_ranges) {
  struct bitextract_mmio_model_config *model_configs =
      calloc(num_ranges, sizeof(struct bitextract_mmio_model_config));

  for (int i = 0; i < num_ranges; ++i) {
    model_configs[i].mask = masks[i];
    model_configs[i].byte_size = byte_sizes[i];
    model_configs[i].left_shift = left_shifts[i];
    model_configs[i].mask_hamming_weight = 0;

    uint32_t mask = masks[i];
    while (mask) {
      if (mask & 1) {
        ++model_configs[i].mask_hamming_weight;
      }
      mask >>= 1;
    }

    #ifdef DEBUG
    printf("Registering bitextract model for range: [%x] %lx - %lx with size, "
           "left_shift: %d, %d. Mask: %08x, hw: %d\n",
           pcs[i], starts[i], ends[i], byte_sizes[i], left_shifts[i], masks[i],
           model_configs[i].mask_hamming_weight);
    fflush(stdout);
    #endif

    if (add_mmio_subregion_handler(uc, bitextract_mmio_model_handler, starts[i],
                                   ends[i], pcs[i],
                                   &model_configs[i]) != UC_ERR_OK) {
      return UC_ERR_EXCEPTION;
    }
  }

  return UC_ERR_OK;
}

uc_err register_value_set_mmio_models(uc_engine *uc, uint64_t *starts,
                                      uint64_t *ends, uint32_t *pcs,
                                      uint32_t *value_nums,
                                      uint32_t **value_lists, int num_ranges) {
  struct value_set_mmio_model_config *model_configs =
      calloc(num_ranges, sizeof(struct value_set_mmio_model_config));

  printf("Registering incoming Value Set models\n");

  for (int i = 0; i < num_ranges; ++i) {
#ifdef DEBUG
    uint32_t pc;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    printf("Registering value set model: [%x] %lx - %lx with numvalues, "
           "value_set: %d, [",
           pcs[i], starts[i], ends[i], value_nums[i]);
    for (uint32_t j = 0; j < value_nums[i]; ++j) {
      if (j) {
        printf(", ");
      }
      printf("%x", value_lists[i][j]);
    }
    printf("]\n");
    fflush(stdout);
#endif

    model_configs[i].num_vals = value_nums[i];
    model_configs[i].values = calloc(value_nums[i], sizeof(**value_lists));
    for (int j = 0; j < value_nums[i]; ++j) {
      model_configs[i].values[j] = value_lists[i][j];
    }

    if (add_mmio_subregion_handler(uc, value_set_mmio_model_handler, starts[i],
                                   ends[i], pcs[i],
                                   &model_configs[i]) != UC_ERR_OK) {
      return UC_ERR_EXCEPTION;
    }
  }

  return UC_ERR_OK;
}

uc_err set_ignored_mmio_addresses(uint64_t *addresses, uint32_t *pcs,
                                  int num_addresses) {
  assert(sizeof(*addresses) == sizeof(*ignored_addresses));
  assert(sizeof(*pcs) == sizeof(*ignored_address_pcs));

  if (num_addresses <= MAX_IGNORED_ADDRESSES) {
#ifdef DEBUG
    for (int i = 0; i < num_addresses; ++i) {
      printf("Registering passthrough address: [%x] %lx\n", pcs[i],
             addresses[i]);
    }
#endif
    memcpy(ignored_addresses, addresses,
           num_addresses * sizeof(*ignored_addresses));
    memcpy(ignored_address_pcs, pcs,
           num_addresses * sizeof(*ignored_address_pcs));
    num_ignored_addresses = num_addresses;
    return UC_ERR_OK;
  } else {
    printf("Too many ignored addresses to be registered");
    return UC_ERR_EXCEPTION;
  }
}

uc_err load_fuzz(const char *path) {
  FILE *fp;
  long leftover_size;

  if (input_mode_SHM) {
    // shm inputs: <size_u32> contents ...
    fuzz_size = (*(uint32_t *)fuzz) + sizeof(uint32_t);
    fuzz_cursor = sizeof(uint32_t);
    init_delivery_budget();
    return 0;
  }

  leftover_size = fuzz_size - fuzz_cursor;

  if (leftover_size != 0) {
    perror("Got prefix input which is not fully consumed. Exiting...\n");
    exit(-1);
  }

  if (!(fp = fopen(path, "r"))) {
    perror("Opening file failed\n");
    return -1;
  }

  if (fseek(fp, 0L, SEEK_END)) {
    perror("fseek failed\n");
    return -1;
  }

  if ((fuzz_size = ftell(fp)) < 0) {
    perror("ftell failed\n");
    return -1;
  }
  rewind(fp);

#ifdef DEBUG
  printf("leftover_size = %ld, fuzz_size = %ld (path: %s)\n", leftover_size,
         fuzz_size, path);
#endif

  if (fuzz_size > PREALLOCED_FUZZ_BUF_SIZE) {
    // As we may need to copy over leftover contents, keep ref

    if (!(fuzz = calloc(fuzz_size, 1))) {
      perror("Allocating fuzz buffer failed\n");
      return -1;
    }

#ifdef DEBUG
    printf("Allocated new oversized fuzz buffer of size 0x%lx\n", fuzz_size);
#endif
  }

  fuzz_cursor = 0;

  // Give reading the input multiple chunk tries
  size_t num_chunks, already_read = 0, last_read, to_be_read = fuzz_size;
  for (num_chunks = 0; to_be_read && num_chunks < FREAD_NMAX_CHUNKS;
       ++num_chunks) {
    last_read = fread(&fuzz[already_read], 1, to_be_read, fp);
    to_be_read -= last_read;
    already_read += last_read;
  }
  fclose(fp);

  if (to_be_read) {
    perror("fread failed\n");
    return -1;
  }

  init_delivery_budget();
  return 0;
}

static void *init_bitmap(uc_engine *uc) {
  // Use local backup bitmap to run without AFL
  void *bitmap = &coverage_bitmap[0];

  // Indicate to possible afl++ that we can use SHM fuzzing
  uint32_t tmp = FS_OPT_ENABLED | FS_OPT_SHDMEM_FUZZ;
  char *id_str;
  int shm_id;

  /* Tell AFL once that we are here  */
  id_str = getenv(SHM_ENV_VAR);
  if (id_str) {
    shm_id = atoi(id_str);
    bitmap = shmat(shm_id, NULL, 0);

    if (bitmap == (void *)-1) {
      // We allow this case so we can use the emulator in a forkserver-aware
      // trace gen worker
      puts("[FORKSERVER SETUP] Could not map SHM, reverting to local buffer");
      bitmap = &coverage_bitmap[0];
    }

    if (write(FORKSRV_FD + 1, &tmp, 4) == 4) {
      do_fuzz = 1;
    } else {
      puts("[FORKSERVER SETUP] Got shared memory region, but no pipe. going "
           "for single input");
      do_fuzz = 0;
    }
  } else {
    puts("[FORKSERVER SETUP] It looks like we are not running under AFL, "
         "going "
         "for single input");
    do_fuzz = 0;
  }

  uc_fuzzer_init_cov(uc, bitmap, MAP_SIZE);

  return bitmap;
}

static inline int run_single(uc_engine *uc) {
  int status;
  uint64_t pc = 0;
  int sig = -1;

  uc_reg_read(uc, UC_ARM_REG_PC, &pc);

  status = uc_emu_start(uc, pc | 1, 0, 0, 0);

  if (custom_exit_reason != UC_ERR_OK) {
    status = custom_exit_reason;
  }

  if (status != UC_ERR_OK) {
    if (do_print_exit_info) {
      printf("Execution failed with error code: %d -> %s\n", status,
             uc_strerror(status));
      print_state(uc);
    }
    sig = uc_err_to_sig(status);
  }

  for (uint32_t i = 0; i < num_exit_hooks; ++i) {
    exit_hooks[i](status, sig);
  }

  return sig == -1 ? status : sig;
}

uc_err add_mmio_subregion_handler(uc_engine *uc, uc_cb_hookmem_t callback,
                                  uint64_t start, uint64_t end, uint32_t pc,
                                  void *user_data) {
  if (num_mmio_callbacks >= MAX_MMIO_CALLBACKS) {
    printf("ERROR add_mmio_subregion_handler: Maximum number of mmio callbacks "
           "exceeded\n");
    return -1;
  }

  if (!num_mmio_regions) {
    printf("ERROR add_mmio_subregion_handler: mmio start and end addresses not "
           "configured, yet\n");
    return UC_ERR_EXCEPTION;
  }

  int custom_region = 1;
  for (int i = 0; i < num_mmio_regions; ++i) {
    if (!(start < mmio_region_starts[i] || end > mmio_region_ends[i])) {
      custom_region = 0;
    }
  }

  if (custom_region) {
    printf("Attaching native listener to custom mmio subregion 0x%08lx-0x%08lx",
           start, end);
    add_mmio_region(uc, start, end);
  }

  struct mmio_callback *cb = calloc(1, sizeof(struct mmio_callback));
  cb->callback = callback;
  cb->start = start;
  cb->user_data = user_data;
  cb->end = end;
  cb->pc = pc;

  mmio_callbacks[num_mmio_callbacks++] = cb;

  return UC_ERR_OK;
}

void fuzz_consumption_timeout_cb(uc_engine *uc, uint32_t id, void *user_data) {
  if (do_print_exit_info) {
    printf("Fuzzing input not consumed for %ld basic blocks, exiting\n",
           fuzz_consumption_timeout);
  }
  printf("fuzz_consumption_timeout_cb called, do_exit\n");
  do_exit(uc, UC_ERR_OK);
}

#ifdef DEBUG_INJECT_TIMER
void test_timeout_cb(uc_engine *uc, uint32_t id, void *user_data) {
  if (!is_discovery_child) {
    uint32_t pc;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    fflush(NULL);
  }
}
#endif

void instr_limit_timeout_cb(uc_engine *uc, uint32_t id, void *user_data) {
  if (do_print_exit_info) {
    uint32_t pc;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    printf("Ran into instruction limit of %lu at 0x%08x - exiting\n",
           get_timer_reload_val(instr_limit_timer_id), pc);
  }
  printf("instr_limit_timeout_cb called, do_exit\n");
  do_exit(uc, UC_ERR_OK);
}

void *mmio_models_take_snapshot(uc_engine *uc) {
  size_t size = num_ignored_addresses * sizeof(uint32_t);
  uint32_t *passthrough_init_vals = malloc(size);

  for (int i = 0; i < num_ignored_addresses; ++i) {
    uc_mem_read(uc, ignored_addresses[i], &passthrough_init_vals[i],
                sizeof(*passthrough_init_vals));
  }

  return passthrough_init_vals;
}

void mmio_models_restore_snapshot(uc_engine *uc, void *snapshot) {
  uint32_t *passthrough_init_vals = (uint32_t *)snapshot;

  // Restore the initial passthrough MMIO values
  for (int i = 0; i < num_ignored_addresses; ++i) {
    uc_mem_write(uc, ignored_addresses[i], &passthrough_init_vals[i],
                 sizeof(*passthrough_init_vals));
  }
}

void mmio_models_discard_snapshot(uc_engine *uc, void *snapshot) {
  free(snapshot);
}

uc_err init(uc_engine *uc, exit_hook_t p_exit_hook, int p_num_mmio_regions,
            uint64_t *p_mmio_starts, uint64_t *p_mmio_ends,
            void *p_py_default_mmio_user_data, uint32_t num_exit_at_bbls,
            uint64_t *exit_at_bbls, uint32_t p_exit_at_hit_limit,
            int p_do_print_exit_info, uint64_t p_fuzz_consumption_timeout,
            uint64_t p_instr_limit) {
  // TODO: assumes shared endianness
  uc_mem_write(uc, CPUID_ADDR, &CPUID_CORTEX_M4, sizeof(CPUID_CORTEX_M4));

  if (p_exit_hook) {
    add_exit_hook(p_exit_hook);
  }

  exit_at_hit_limit = p_exit_at_hit_limit;
  do_print_exit_info = p_do_print_exit_info;

  if (do_print_exit_info) {
    uc_hook_add(uc, &invalid_mem_hook_handle,
                UC_HOOK_MEM_WRITE_INVALID | UC_HOOK_MEM_READ_INVALID |
                    UC_HOOK_MEM_FETCH_INVALID,
                hook_debug_mem_invalid_access, 0, 1, 0);
  }

  if (!g_bounds_dispatch_hook) {
    if (uc_hook_add(uc, &g_bounds_dispatch_hook, UC_HOOK_CODE,
                    hook_bounds_dispatch, NULL,
                    g_code_hook_begin, g_code_hook_end) != UC_ERR_OK) {
      perror("Could not register bounds dispatch hook\n");
      return UC_ERR_EXCEPTION;
    }
    dt_learning_log("[BOUNDS] DISPATCH_HOOK_ADD begin=0x%llx end=0x%llx",
                    (unsigned long long)g_code_hook_begin,
                    (unsigned long long)g_code_hook_end);
  }

  // Add fuzz consumption timeout as timer
  fuzz_consumption_timeout = p_fuzz_consumption_timeout;
  fuzz_consumption_timer_id =
      add_timer(fuzz_consumption_timeout, fuzz_consumption_timeout_cb, NULL,
                TIMER_IRQ_NOT_USED);
  if (fuzz_consumption_timeout) {
    start_timer(uc, fuzz_consumption_timer_id);
  }

#ifdef DEBUG_INJECT_TIMER
  // debug timer to debug precise timing consistencies
  start_timer(uc, add_timer(DEBUG_TIMER_TIMEOUT, test_timeout_cb, NULL,
                            TIMER_IRQ_NOT_USED));
#endif

  instr_limit = p_instr_limit;
  instr_limit_timer_id =
      add_timer(instr_limit, instr_limit_timeout_cb, NULL, TIMER_IRQ_NOT_USED);
  if (instr_limit) {
    start_timer(uc, instr_limit_timer_id);
  }

  py_default_mmio_user_data = p_py_default_mmio_user_data;

  for (uint32_t i = 0; i < num_exit_at_bbls; ++i) {
    uint64_t tmp;
    uint64_t bbl_addr = exit_at_bbls[i] & (~1LL);
    if (uc_hook_add(uc, &tmp, UC_HOOK_BLOCK, hook_block_exit_at, 0, bbl_addr,
                    bbl_addr) != UC_ERR_OK) {
      perror("Could not register exit-at block hook...\n");
      return -1;
    }
  }

  if (!(fuzz = calloc(PREALLOCED_FUZZ_BUF_SIZE, 1))) {
    perror("Allocating fuzz buffer failed\n");
    return -1;
  }

  // Register read hooks for mmio regions
  num_mmio_regions = p_num_mmio_regions;
  mmio_region_starts = calloc(num_mmio_regions, sizeof(*p_mmio_starts));
  mmio_region_ends = calloc(num_mmio_regions, sizeof(*p_mmio_ends));
  memcpy(mmio_region_starts, p_mmio_starts,
         num_mmio_regions * sizeof(*p_mmio_starts));
  memcpy(mmio_region_ends, p_mmio_ends,
         num_mmio_regions * sizeof(*p_mmio_ends));

  for (int i = 0; i < num_mmio_regions; ++i) {
    if (add_mmio_region(uc, mmio_region_starts[i], mmio_region_ends[i]) !=
        UC_ERR_OK) {
      perror("[native init] could not register mmio region.\n");
      return UC_ERR_EXCEPTION;
    }
  }

  // Snapshotting
  init_interrupt_triggering(uc);

  init_uc_state_snapshotting(uc);

  subscribe_state_snapshotting(uc, mmio_models_take_snapshot,
                               mmio_models_restore_snapshot,
                               mmio_models_discard_snapshot);

  initialize_data_tracker_arrays();
  return UC_ERR_OK;
}

static void restore_snapshot(uc_engine *uc) {
  // Restore all subscribed snapshot parts
  trigger_restore(uc);

  // Also reset fuzzing input cursor and exit detection
  fuzz_cursor = fuzz_size;
  input_already_given = 0;
  duplicate_exit = false;
  custom_exit_reason = UC_ERR_OK;
}

uc_err emulate(uc_engine *uc, char *p_input_path, char *prefix_input_path) {
  uint64_t pc = 0;
  fflush(stdout);

  uc_reg_read(uc, UC_ARM_REG_PC, &pc);
  init_bitmap(uc);

  /*
   * Pre-execute deterministic part of target execution (the execution prefix)
   * Anything before consuming dynamic fuzzing input for the first time is
   * deterministic. This includes a potential prefix input which we will also
   * consume during this stage to effectively restore a snapshot (which the
   * prefix input leads us to).
   */

  // Set input path for the fuzz reading handler to pick up on later
  input_path = p_input_path;
  // Pre-load prefix input
  if (prefix_input_path) {
    if (load_fuzz(prefix_input_path) != 0) {
      _exit(-1);
    }
  }

  /*
   * This part of executing the execution prefix is a bit tricky:
   * We cannot simply run up to the first MMIO access, as this will leave our
   * execution context in the middle of an MMIO access, which would leave
   * unicorn in a state which we cannot snapshot. So instead, we fork and
   * discover how much execution we have ahead of us before running into the
   * first fuzzing input-consuming MMIO access. We report this number from the
   * forked child to the parent via a pipe.
   */
  pid_t child_pid;
  uint64_t required_ticks = -1;
  if (pipe(pipe_to_parent)) {
    puts("[ERROR] Could not create pipe for discovery forking");
    exit(-1);
  }

  // For every run (and to keep consistency between single and fuzzing runs),
  // find out how many basic blocks we can execute before hitting the first
  // MMIO read
  child_pid = fork();
  if (child_pid) {
    // parent: wait for the discovery child to report back the number of tbs
    // we need to execute
    if (read(pipe_to_parent[0], &required_ticks, sizeof(required_ticks)) !=
        sizeof(required_ticks)) {
      puts("[ERROR] Could not retrieve the number of required ticks during "
           "discovery forking");
      exit(-1);
    }
    waitpid(child_pid, &child_pid, 0);

    close(pipe_to_parent[0]);
    close(pipe_to_parent[1]);

    printf("[DISCOVERY FORK PARENT] Got number of ticks to step: %ld\n",
           required_ticks);

    if (required_ticks > 2) {
      // Set up a timer that will make use stop after executing the prefix
      set_timer_reload_val(instr_limit_timer_id, required_ticks - 2);

      // Execute the prefix
      if (uc_emu_start(uc, pc | 1, 0, 0, 0)) {
        puts("[ERROR] Could not execute the first some steps");
        exit(-1);
      }
    }
    puts("[+] Initial constant execution (including optional prefix input) "
         "done, starting input execution.");
    fflush(stdout);
  } else {
    // child: Run until we hit an input consumption
    is_discovery_child = 1;
    uc_err child_emu_status = uc_emu_start(uc, pc | 1, 0, 0, 0);

    // We do not expect to get here. The child should exit by itself in
    // get_fuzz
    printf("[ERROR] Emulation stopped using just the prefix input (%d: %s)\n",
           child_emu_status, uc_strerror(child_emu_status));

    // Write wrong amount of data to notify parent of failure
    if (write(pipe_to_parent[1], emulate, 1) != 1) {
      puts("[Discovery Child] Error: Could not notify parent of failure...");
      fflush(stdout);
    }
    _exit(-1);
  }

  // After consuming first part of input and executing the prefix, set input
  // mode
  determine_input_mode();
  // Set the proper instruction limit (after using a fake one to execute exec
  // prefix)
  set_timer_reload_val(instr_limit_timer_id, instr_limit);

  // Upon exiting emulation, Unicorn will trigger basic block hits.
  // This ticks off timers two times. This is an issue because this
  // makes timings slightly differ when splitting an input to an input prefix
  // and the remaining input file. Adjust for this offset here.
  // TODO: adjusting the timer has to be done when it is caused.
  // TODO: This seems to be the case when unicorn is stopped, but need to
  // re-visit adjust_timers_for_unicorn_exit();

  if (do_fuzz) {
    uc_fuzzer_reset_cov(uc, 1);
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    trigger_snapshotting(uc);

    // Initial per-round setup: read JSON, build DT arrays, hooks, and pending DRs
    per_round_reload(uc);

    // AFL-compatible Forkserver loop
    child_pid = getpid();
    int count = 0;
    int tmp = 0;
    int sig;
    input_already_given = 0;
    duplicate_exit = false;
    for (;;) {
      ++count;

      /* Wait until we are allowed to run  */
      if (read(FORKSRV_FD, &tmp, 4) != 4) {
        if (count == 1) {
          puts("[FORKSERVER MAIN LOOP] ERROR: Read from FORKSRV_FD to start "
               "new execution failed. Exiting");
          exit(-1);
        } else {
          puts("[FORKSERVER MAIN LOOP] Forkserver pipe now closed. Exiting");
          exit(0);
        }
      }

      uc_fuzzer_reset_cov(uc, 0);

      /* Send AFL the child pid thus it can kill it on timeout   */
      if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) {
        printf("[FORKSERVER MAIN LOOP] ERROR: Write to FORKSRV_FD+1 to send "
               "fake "
               "child PID failed. errno: %d. Description: '%s'. Count: %d\n",
               errno, strerror(errno), count);
        fflush(stdout);
        exit(-1);
      }

      sig = run_single(uc);

      if (write(FORKSRV_FD + 1, &sig, 4) != 4) {
        puts("[MAIN LOOP] Write to FORKSRV_FD+1 to send status failed");
        _exit(-1);
      }

      restore_snapshot(uc);

      // Ghidra daemon may have patched JSON → trigger reload
      {
        struct stat st;
        if (stat("/tmp/ghidra_done", &st) == 0) {
          unlink("/tmp/ghidra_done");
          g_discovery_occurred = true;
        }
      }

      // Channel discovery: if a new DT was discovered this round, reload config
      if (g_discovery_occurred) {
        per_round_reload(uc);
        g_discovery_occurred = false;
      }
    }
  } else {
    puts("Running without a fork server");
    duplicate_exit = false;

    // Initial per-round setup for single-run mode
    per_round_reload(uc);

    // Not running under fork server
    int sig = run_single(uc);

    if (do_print_exit_info) {
      if (sig) {
        // Crash occurred
        printf("Emulation crashed with signal %d\n", sig);
      } else {
        // Non-crashing exit (includes different timeouts)
        uint32_t pc;
        uc_reg_read(uc, UC_ARM_REG_PC, &pc);
        printf("Exited without crash at 0x%08x - If no other reason, we ran "
               "into one of the limits\n",
               pc);
      }
    }
  }

  return UC_ERR_OK;
}

void initialize_data_tracker_arrays() {
  printf("Initializing data tracker arrays\n");
  main_dt_array = malloc(DATATRACKER_SIZE * sizeof(DataTracker));
  irq_dt_array = malloc(DATATRACKER_SIZE * sizeof(DataTracker));
  pending_dt_array = malloc(MAX_PENDING_DRS * sizeof(DataTracker));
  // Check for NULL if allocation fails and handle it appropriately
  if (!main_dt_array || !irq_dt_array || !pending_dt_array) {
    // Handle memory allocation error
    // For example, you could print an error message and exit
    fprintf(stderr, "Failed to allocate memory for data tracker arrays\n");
    exit(EXIT_FAILURE);
  }
  memset(main_dt_array, 0, DATATRACKER_SIZE * sizeof(DataTracker));
  memset(irq_dt_array, 0, DATATRACKER_SIZE * sizeof(DataTracker));
  memset(pending_dt_array, 0, MAX_PENDING_DRS * sizeof(DataTracker));
  printf("Data tracker arrays initialized\n");
}

int fill_data_tracker_main_dt_array(uint32_t dr, uint32_t callread_pc,
                                    uint32_t read_pc, uint32_t buffer_addr,
                                    uint32_t irq_pc, uint32_t avail_pc,
                                    uint32_t rx_head, uint32_t rx_tail,
                                    short buffer_len, short buffer_min_len,
                                    short consume_count) {

  main_dt_array[main_dt_array_index].dr = dr;
  main_dt_array[main_dt_array_index].callread_pc = callread_pc;
  main_dt_array[main_dt_array_index].read_pc = read_pc;
  main_dt_array[main_dt_array_index].buffer_addr = buffer_addr;
  main_dt_array[main_dt_array_index].irq_pc = irq_pc;
  main_dt_array[main_dt_array_index].avail_pc = avail_pc;
  main_dt_array[main_dt_array_index].rx_head = rx_head;
  main_dt_array[main_dt_array_index].rx_tail = rx_tail;
  main_dt_array[main_dt_array_index].buffer_len = buffer_len;
  main_dt_array[main_dt_array_index].buffer_min_len = buffer_min_len;
  main_dt_array[main_dt_array_index].irq_num = 0;
  main_dt_array[main_dt_array_index].fifo_head = 0;
  main_dt_array[main_dt_array_index].fifo_tail = 0;
  if (hash_table == NULL) {
    init_dr_dt_hash();
  }
  // 插入元素
  int ret = 0;
  khint_t k = kh_put(dr_dt, hash_table, dr, &ret); // 插入键
  if (ret != -1) { // 如果 ret 不是 -1，说明插入成功
    kh_value(hash_table, k) =
        &main_dt_array[main_dt_array_index]; // 设置键对应的值
  }
  main_dt_array_index++;
  return 0;
}

int fill_data_tracker_irq_dt_array(uint32_t dr, uint32_t callread_pc,
                                   uint32_t read_pc, uint32_t buffer_addr,
                                   uint32_t irq_pc, uint32_t avail_pc,
                                   uint32_t rx_head, uint32_t rx_tail,
                                   short buffer_len, short buffer_min_len,
                                   short consume_count, uint32_t vtor) {

  irq_dt_array[irq_dt_array_index].dr = dr;
  irq_dt_array[irq_dt_array_index].callread_pc = callread_pc;
  irq_dt_array[irq_dt_array_index].read_pc = read_pc;
  irq_dt_array[irq_dt_array_index].buffer_addr = buffer_addr;
  irq_dt_array[irq_dt_array_index].irq_pc = irq_pc;
  irq_dt_array[irq_dt_array_index].avail_pc = avail_pc;
  irq_dt_array[irq_dt_array_index].rx_head = rx_head;
  irq_dt_array[irq_dt_array_index].rx_tail = rx_tail;
  irq_dt_array[irq_dt_array_index].buffer_len = buffer_len;
  irq_dt_array[irq_dt_array_index].buffer_min_len = buffer_min_len;
  irq_dt_array[irq_dt_array_index].irq_num = 0;
  irq_dt_array[irq_dt_array_index].fifo_head = 0;
  irq_dt_array[irq_dt_array_index].fifo_tail = 0;
  irq_dt_array[irq_dt_array_index].interrupt_times = 0;
  vtor_num = vtor;
  if (hash_table == NULL) {
    init_dr_dt_hash();
  }
  // 插入元素
  int ret = 0;
  khint_t k = kh_put(dr_dt, hash_table, dr, &ret); // 插入键
  if (ret != -1) { // 如果 ret 不是 -1，说明插入成功
    kh_value(hash_table, k) =
        &irq_dt_array[irq_dt_array_index]; // 设置键对应的值
  }
  irq_dt_array_index++;
  return 0;
}

static bool irq_dt_is_complete_for_delivery(DataTracker *dt) {
  return dt &&
         dt->avail_pc != 0 &&
         dt->buffer_len > 1 &&
         dt->buffer_min_len > 0 &&
         dt->buffer_min_len <= dt->buffer_len;
}

static int add_avail_dispatch_entry(uint32_t pc, DataTracker *dt, bool is_main) {
  if (!pc || !dt) return 0;
  if (g_num_avail_hooks >= MAX_AVAIL_HOOKS) {
    dt_learning_log("[AVAIL_DISPATCH] SKIP pc=0x%x dr=0x%x reason=full",
                    pc, dt->dr);
    return -1;
  }

  g_avail_dispatch_entries[g_num_avail_hooks++] =
      (AvailDispatchEntry){ .pc = pc, .dt = dt, .is_main = is_main };
  return 0;
}

int ufuzz_adapter_add_avail_hook(uc_engine *uc) {
  (void)uc;
  g_num_avail_hooks = 0;
  memset(g_avail_dispatch_entries, 0, sizeof(g_avail_dispatch_entries));

  for (int i = 0; i < main_dt_array_index; i++) {
    if (main_dt_array[i].avail_pc != 0) {
      if (add_avail_dispatch_entry(main_dt_array[i].avail_pc,
                                   &main_dt_array[i], true) != 0) {
        return -1;
      }
    }
  }

  for (int i = 0; i < irq_dt_array_index; i++) {
    if (irq_dt_is_complete_for_delivery(&irq_dt_array[i])) {
      if (add_avail_dispatch_entry(irq_dt_array[i].avail_pc,
                                   &irq_dt_array[i], false) != 0) {
        return -1;
      }
    }
  }

  dt_learning_log("[AVAIL_DISPATCH] REFRESH entries=%d main_dt=%d irq_dt=%d",
                  g_num_avail_hooks, main_dt_array_index, irq_dt_array_index);
  return 0;
}

uc_err main_proc_avail_hook_handler(uc_engine *uc, uint64_t pc, uint32_t size,
                                    void *user_data) {
  read_times++;
  // DataTracker *dt = (DataTracker *)user_data;

  // // 主逻辑读：FIFO 空则装填，无中断触发
  // if (dt->fifo_head == dt->fifo_tail) {
  //   int len_si = compute_delivery_size(dt);
  //   if (len_si == 0) {
  //     printf("***main dt budget exhausted\n");
  //     return UC_ERR_OK;
  //   }
  //   fill_data(dt, len_si, uc);
  //   delivery_LenFI = delivery_LenFI - len_si + delivery_X;
  //   if (delivery_LenFI < 0) delivery_LenFI = 0;
  //   delivery_LenR  = delivery_LenR - delivery_X;
  //   if (delivery_LenR == 0) delivery_X = 0;
  //   printf("***main fill fifo: %d bytes, LenFI=%d, LenR=%d\n",
  //          len_si, delivery_LenFI, delivery_LenR);
  // }
  return UC_ERR_OK;
}

uc_err irq_avail_hook_handler(uc_engine *uc, uint64_t pc, uint32_t size,
                              void *user_data) {
  my_debug_log("irq_avail_hook_handler\n");
  DataTracker *dt = (DataTracker *)user_data;

  // ---- 解析 IRQ 号 ----
  if (dt->irq_pc < 256) {
    dt->irq_num = dt->irq_pc;
  } else if (dt->irq_pc == 256) {
    return UC_ERR_OK;
  } else {
    // 每次重新查询，避免 NVIC 未启用时缓存
    int resolved = get_match_irq_num(uc, dt->irq_pc);
    if (resolved < 0) {
      return UC_ERR_OK;  // 中断尚未启用 / 未匹配，等下次
    }
    dt->irq_num = (short)resolved;
  }

  // ---- FIFO 空则装填 ----
  if (!dt->interrupt_times) {
    if (g_delivery_budget_closed) {
      return UC_ERR_OK;
    }

    int len_si = compute_delivery_size(dt);
    if (len_si == 0) {
      delivery_log("BUDGET_EXHAUSTED dr=0x%x LenFI=%d LenR=%u X=%u cursor=%ld fuzz_size=%ld",
                   dt->dr, delivery_LenFI, delivery_LenR, delivery_X,
                   fuzz_cursor, fuzz_size);
      g_delivery_budget_closed = true;
      return UC_ERR_OK;
    }
    fill_data(dt, len_si, uc);
    delivery_LenFI = delivery_LenFI - len_si + delivery_X;
    if (delivery_LenFI < 0) delivery_LenFI = 0;
    delivery_LenR  = delivery_LenR - delivery_X;
    if (delivery_LenR == 0) delivery_X = 0;
    dt->interrupt_times = len_si;
    delivery_log("COMMIT dr=0x%x plan=%d irq_times=%d LenFI=%d LenR=%u X=%u cursor=%ld fuzz_size=%ld",
                 dt->dr, len_si, dt->interrupt_times,
                 delivery_LenFI, delivery_LenR, delivery_X,
                 fuzz_cursor, fuzz_size);
    return UC_ERR_OK;
  }

  // ---- 触发中断 ----
  nvic_set_pending(uc, dt->irq_num, false);
  dt->interrupt_times--;
  return UC_ERR_OK;
}

static bool dispatch_complete_dt_avail_hook(uc_engine *uc, uint32_t pc,
    uint64_t address, uint32_t size) {
  bool handled = false;

  for (int i = 0; i < g_num_avail_hooks; i++) {
    AvailDispatchEntry *entry = &g_avail_dispatch_entries[i];
    if (entry->pc != pc || !entry->dt) continue;

    if (entry->is_main) {
      main_proc_avail_hook_handler(uc, address, size, entry->dt);
    } else {
      irq_avail_hook_handler(uc, address, size, entry->dt);
    }
    handled = true;
  }

  return handled;
}

// ====== 替换 get_current_partition/random_split 系列函数 ======

// 初始化交付预算（ 行 1-13）：估算 N、X、LenR
void init_delivery_budget(void) {
  delivery_N = 0;
  delivery_X = 0xFFFFFFFF;
  delivery_LenR = 0;
  delivery_LenFI = 0;
  g_delivery_budget_closed = false;

  for (int i = 0; i < irq_dt_array_index; i++) {
    DataTracker *dt = &irq_dt_array[i];
    if (!irq_dt_is_complete_for_delivery(dt)) continue;

    delivery_N++;
    uint32_t low = (uint32_t)dt->buffer_min_len;
    if (low < delivery_X) delivery_X = low;
  }

  if (delivery_N == 0) {
    delivery_X = 1;
    delivery_LenR = 0;
    delivery_LenFI = fuzz_size;
    delivery_log("INIT_SKIP reason=no_complete_irq_dt fuzz_size=%ld fuzz_cursor=%ld",
                 fuzz_size, fuzz_cursor);
    return;
  }

  if (delivery_X == 0xFFFFFFFF || delivery_X == 0) delivery_X = 1;
  delivery_LenR = delivery_N * delivery_X;
  uint32_t old_N = delivery_N;
  while (fuzz_size < delivery_LenR && delivery_N > 1) {
    delivery_N--;
    delivery_LenR = delivery_N * delivery_X;
  }
  if (old_N != delivery_N) {
    delivery_log("INIT_DEGRADE old_N=%u new_N=%u X=%u LenR=%u fuzz_size=%ld fuzz_cursor=%ld",
                 old_N, delivery_N, delivery_X, delivery_LenR,
                 fuzz_size, fuzz_cursor);
  }
  delivery_LenFI = fuzz_size - delivery_LenR;
  delivery_log("INIT N=%u X=%u LenR=%u LenFI=%d fuzz_size=%ld fuzz_cursor=%ld",
               delivery_N, delivery_X, delivery_LenR, delivery_LenFI,
               fuzz_size, fuzz_cursor);
}

// 计算本次投递长度 LenSI（ 行 17-26）
int compute_delivery_size(DataTracker *dt) {
  int32_t len_fi = delivery_LenFI;                                    // LenFI
  uint32_t X      = delivery_X > 0 ? delivery_X : 1;
  uint32_t low_p  = dt->buffer_min_len > 0 ? dt->buffer_min_len : 1; // LOWp
  uint32_t up_p   = dt->buffer_len;                                   // UPp
  if (low_p > 1 && low_p < 4 && up_p >= 4) low_p = 4;  // 原版阈值 clamp
  if (up_p < low_p) {
    delivery_log("COMPUTE_SKIP dr=0x%x reason=invalid_bounds low=%u up=%u LenFI=%d LenR=%u X=%u cursor=%ld fuzz_size=%ld",
                 dt->dr, low_p, up_p, len_fi, delivery_LenR, X,
                 fuzz_cursor, fuzz_size);
    return 0;
  }

  //  行 14
  if (len_fi + delivery_LenR == 0) {
    delivery_log("COMPUTE_SKIP dr=0x%x reason=budget_empty low=%u up=%u LenFI=%d LenR=%u X=%u cursor=%ld fuzz_size=%ld",
                 dt->dr, low_p, up_p, len_fi, delivery_LenR, X,
                 fuzz_cursor, fuzz_size);
    return 0;
  }
  if (up_p == low_p) {
    delivery_log("COMPUTE dr=0x%x branch=fixed plan=%u low=%u up=%u LenFI=%d LenR=%u X=%u cursor=%ld fuzz_size=%ld",
                 dt->dr, up_p, low_p, up_p, len_fi, delivery_LenR, X,
                 fuzz_cursor, fuzz_size);
    return up_p;
  }

  //  行 17: Δ = LenFI + X - LOWp
  int delta = (int)(len_fi + X) - (int)low_p;
  int len_si;
  if (delta <= 0) {
    //  行 18-20: LenSI = LOWp, 补零 |Δ| 字节
    len_si = (int)low_p;
    delivery_log("COMPUTE dr=0x%x branch=base delta=%d plan=%d low=%u up=%u LenFI=%d LenR=%u X=%u cursor=%ld fuzz_size=%ld",
                 dt->dr, delta, len_si, low_p, up_p, len_fi,
                 delivery_LenR, X, fuzz_cursor, fuzz_size);
  } else {
    //  行 23-24: LenSI = Rand(FI[Pos]) mod t + LOWp
    uint32_t upper = (len_fi + X < up_p) ? (len_fi + X) : up_p;
    int t = (int)upper - (int)low_p + 1;
    uint32_t seed = (fuzz_cursor < fuzz_size) ? fuzz[fuzz_cursor] : 0;
    len_si = (seed % t) + low_p;
    delivery_log("COMPUTE dr=0x%x branch=random delta=%d plan=%d range=[%u,%u] seed=%u seed_pos=%ld LenFI=%d LenR=%u X=%u up=%u cursor=%ld fuzz_size=%ld",
                 dt->dr, delta, len_si, low_p, upper, seed,
                 fuzz_cursor, len_fi, delivery_LenR, X, up_p,
                 fuzz_cursor, fuzz_size);
  }
  return len_si;
}

// 检查某个 IRQ 是否正被任意 DataTracker 管理
bool is_irq_managed_by_dt(int irq_num) {
  for (int i = 0; i < irq_dt_array_index; i++) {
    if (irq_dt_array[i].irq_num == irq_num)
      return true;
  }
  return false;
}

// ====== 替换结束 ======

// 用于检测是否存在头尾指针并且判断是否相等
// Function to fill data from fuzz input into DataTracker's FIFO
// Fills exactly container_len bytes, zero-padding if fuzz is exhausted
int fill_data(DataTracker *dt, size_t container_len, uc_engine *uc) {
  size_t remain = (fuzz_size > fuzz_cursor) ? (fuzz_size - fuzz_cursor) : 0;

  if (remain <= 0) {
    delivery_log("FILL_SKIP dr=0x%x reason=no_input plan=%zu cursor=%ld fuzz_size=%ld",
                 dt ? dt->dr : 0, container_len, fuzz_cursor, fuzz_size);
    // do_exit(uc, UC_ERR_OK);
    return 0;
  }

  int actual_len = (remain < container_len) ? (int)remain : (int)container_len;
  int padding    = (int)container_len - actual_len;
  long cursor_before = fuzz_cursor;
  uint8_t data_input[container_len];
  memset(data_input, 0, container_len);

  if (actual_len > 0) {
    memcpy(data_input, fuzz + fuzz_cursor, actual_len);
    fuzz_cursor += actual_len;
  }

  int write_len = write_byte_to_data_reg(dt, data_input, container_len, uc);
  delivery_log("FILL dr=0x%x plan=%zu actual=%d pad=%d cursor_before=%ld cursor_after=%ld fuzz_size=%ld write_len=%d",
               dt ? dt->dr : 0, container_len, actual_len, padding,
               cursor_before, fuzz_cursor, fuzz_size, write_len);
  return write_len;
}

int write_byte_to_data_reg(DataTracker *dt, uint8_t *data, int len,
                           uc_engine *uc) {
  memcpy(dt->fifo, data, len);                                                                                                                                                                                
  dt->fifo_head = len;    // 修复：应该是 len 而非 len-1                                   
  dt->fifo_tail = 0;                                                                                                                                                                                          
  delivery_log("FIFO_WRITE dr=0x%x len=%d head=%d tail=%d",
               dt ? dt->dr : 0, len,
               dt ? dt->fifo_head : 0, dt ? dt->fifo_tail : 0);
  return len;     
}

void my_debug_log(const char *format) {
#ifdef MYDEBUG
  FILE *debugFile;

  // 打开文件，如果文件不存在则创建，如果存在则追加写入
  debugFile = fopen("/tmp/debug.txt", "a");

  if (debugFile == NULL) {
    fprintf(stderr, "无法打开文件\n");
  }

  // 写入调试信息到文件
  fprintf(debugFile, "%s", format);

  // 关闭文件
  fclose(debugFile);
#endif
  return;
}

static int get_irq_num_from_vector_table(uc_engine *uc, uint32_t irq_pc) {
  uint32_t vtor = 0;
  if (uc_mem_read(uc, SYSCTL_VTOR, &vtor, sizeof(vtor)) != UC_ERR_OK ||
      vtor == 0) {
    vtor = vtor_num;
  }
  if (vtor == 0 || irq_pc == 0) return 0;

  uint32_t target = irq_pc & ~1u;
  for (int irq_num = EXCEPTION_NO_EXTERNAL_START;
       irq_num < NVIC_NUM_SUPPORTED_INTERRUPTS; irq_num++) {
    uint32_t handler_val = 0;
    uint64_t handler_addr = (uint64_t)vtor + ((uint64_t)irq_num * 4);
    if (uc_mem_read(uc, handler_addr, &handler_val,
                    sizeof(handler_val)) != UC_ERR_OK) {
      continue;
    }
    if (handler_val == 0 || handler_val == 0xffffffff) continue;

    uint32_t handler_pc = handler_val & ~1u;
    int diff = abs((int)handler_pc - (int)target);
    if (diff <= 4) {
      vtor_num = vtor;
      return irq_num;
    }
  }

  return 0;
}

// Returns the matching IRQ number, or 0 if no enabled IRQ matches irq_pc.
int get_match_irq_num(uc_engine *uc, uint32_t irq_pc) {
  int num_enabled = get_num_enabled();
  int irq_num = 0;
  int best_irq = 0;
  int best_diff = 0x7FFFFFFF;
  // printf("[GET_IRQ] irq_pc=0x%x vtor=0x%x enabled=%d\n",
  //        irq_pc, vtor_num, num_enabled);
  for (int i = 1; i <= num_enabled; i++) {
    irq_num = nth_enabled_irq_num(i);
    uint64_t handler_addr = vtor_num + irq_num * 4;
    int handler_val;
    uc_mem_read(uc, handler_addr, &handler_val, sizeof(handler_val));
    int diff = abs((int)(handler_val - (int)irq_pc));
    // printf("[GET_IRQ]   i=%d irq=%d handler=0x%x diff=%d\n",
    //        i, irq_num, handler_val, diff);
    if (diff <= 4) {
      // printf("[GET_IRQ] MATCH irq=%d\n", irq_num);
      return irq_num;
    }
    if (diff < best_diff) {
      best_diff = diff;
      best_irq = irq_num;
    }
  }
  // printf("[GET_IRQ] no exact match, best irq=%d diff=%d\n", best_irq, best_diff);
  return 0;
}

static int resolve_irq_num_for_pc(uc_engine *uc, uint32_t irq_pc,
                                  const char **source) {
  if (source) *source = "none";
  if (irq_pc == 0 || irq_pc == 256) return 0;
  if (irq_pc < 256) {
    if (source) *source = "direct";
    return (int)irq_pc;
  }

  int resolved = get_irq_num_from_vector_table(uc, irq_pc);
  if (resolved > 0) {
    if (source) *source = "vector";
    return resolved;
  }

  resolved = get_match_irq_num(uc, irq_pc);
  if (resolved > 0) {
    if (source) *source = "enabled";
    return resolved;
  }

  return 0;
}

void reset_datatrcker_and_global_vars() {
  read_times = 0;
  delivery_LenFI = 0;
  g_delivery_budget_closed = false;
  for (int i = 0; i < main_dt_array_index; i++) {
    main_dt_array[i].fifo_head = 0;
    main_dt_array[i].fifo_tail = 0;
  }
  for (int i = 0; i < irq_dt_array_index; i++) {
    irq_dt_array[i].fifo_head = 0;
    irq_dt_array[i].fifo_tail = 0;
    irq_dt_array[i].interrupt_times = 0;
  }
  // Refill pending DT FIFOs each round (snapshot restore doesn't touch C heap)
  for (int i = 0; i < pending_dt_array_index; i++) {
    memset(pending_dt_array[i].fifo, 0xAA, 1);
    pending_dt_array[i].fifo_head = 1;
    pending_dt_array[i].fifo_tail = 0;
  }
}

int init_dr_dt_hash() {

  // 创建哈希表
  khash_t(dr_dt) *h = kh_init(dr_dt);
  hash_table = h;
  return 0;

  // 销毁哈希表
  // kh_destroy(dr_dt, h);
}

// ====== Channel Discovery: Init-time Setup ======
int store_dr_sr_list(uint32_t *dr_addrs, int num_drs,
                     uint32_t *sr_addrs, int num_srs,
                     const char *json_path, uint32_t vtor) {
  vtor_num = vtor;
  g_num_dr_addrs = (num_drs < MAX_DR_ADDRS) ? num_drs : MAX_DR_ADDRS;
  memcpy(g_all_dr_addrs, dr_addrs, g_num_dr_addrs * sizeof(uint32_t));
  g_num_sr_addrs = (num_srs < MAX_SR_ADDRS) ? num_srs : MAX_SR_ADDRS;
  memcpy(g_all_sr_addrs, sr_addrs, g_num_sr_addrs * sizeof(uint32_t));
  if (json_path && json_path[0]) {
    strncpy(g_json_file_path, json_path, sizeof(g_json_file_path) - 1);
  }

  if (!pending_dt_array) {
    pending_dt_array = calloc(MAX_PENDING_DRS, sizeof(DataTracker));
  }

  dt_learning_log("[STORE_DR_SR] drs=%d srs=%d json=%s vtor=0x%x",
                  g_num_dr_addrs, g_num_sr_addrs, g_json_file_path, vtor_num);
  return 0;
}

// ====== Channel Discovery: Per-round Hook Management ======

// Cleanup all avail and pending hooks from previous round
void cleanup_avail_and_pending_hooks(uc_engine *uc) {
  g_num_avail_hooks = 0;
  memset(g_avail_dispatch_entries, 0, sizeof(g_avail_dispatch_entries));

  for (int i = 0; i < g_num_pending_hooks; i++) {
    if (g_pending_hook_handles[i]) {
      uc_hook_del(uc, g_pending_hook_handles[i]);
      g_pending_hook_handles[i] = 0;
    }
  }
  g_num_pending_hooks = 0;

  // Clean up any lingering discovery hooks
  if (g_discovery_mem_write_hook) {
    uc_hook_del(uc, g_discovery_mem_write_hook);
    g_discovery_mem_write_hook = 0;
  }
  if (g_discovery_buffer_read_hook) {
    uc_hook_del(uc, g_discovery_buffer_read_hook);
    g_discovery_buffer_read_hook = 0;
  }
  g_in_discovery_mode = false;

  // Clean up post-static-analysis bounds learning hooks.
  if (g_bounds_write_hook) { uc_hook_del(uc, g_bounds_write_hook); g_bounds_write_hook = 0; }
  memset(g_bounds_diag_entries, 0, sizeof(g_bounds_diag_entries));
  g_bounds_num_diag_hooks = 0;
#if BOUNDS_PC_TRACE_ENABLE
  if (g_bounds_pc_trace_fp) {
    fprintf(g_bounds_pc_trace_fp,
            "[ROUND_END] round=%u count=%u avail_hit=%d pends=%d\n",
            g_bounds_pc_trace_round,
            g_bounds_pc_trace_count,
            g_bounds_avail_hit ? 1 : 0,
            g_bounds_irq_pend_count);
    fclose(g_bounds_pc_trace_fp);
    g_bounds_pc_trace_fp = NULL;
  }
#endif
}

// Reset all tracker state for re-population
void reset_all_tracker_state(void) {
  main_dt_array_index = 0;
  irq_dt_array_index = 0;
  pending_dt_array_index = 0;
  memset(main_dt_array, 0, DATATRACKER_SIZE * sizeof(DataTracker));
  memset(irq_dt_array, 0, DATATRACKER_SIZE * sizeof(DataTracker));
  memset(pending_dt_array, 0, MAX_PENDING_DRS * sizeof(DataTracker));

  // Clear hash table by re-creating it
  if (hash_table) {
    kh_destroy(dr_dt, hash_table);
  }
  hash_table = kh_init(dr_dt);

  // Reset discovery state
  g_in_discovery_mode = false;
  g_discovery_dr = 0;
  g_discovery_taint = 0;
  g_discovery_irq_pc = 0;
  g_discovery_addr_count = 0;
  g_discovery_buffer_addr = 0;
  g_discovery_mem_write_hook = 0;
  g_discovery_occurred = false;

  // Reset read_pc discovery state
  g_discovery_read_pc = 0;
  g_discovery_callread_pc = 0;
  g_discovery_buffer_read_hook = 0;
  g_read_pc_done = false;

  // Reset post-static-analysis bounds learning state.
  g_bounds_state = 0;
  g_bounds_dt_idx = -1;
  g_bounds_dt_dr = 0;
  g_bounds_irq = 0;
  g_bounds_avail_hit = false;
  g_bounds_avail_pass_next = false;
  g_bounds_fifo_seeded = false;
  g_bounds_chain_started = false;
  g_bounds_chain_min = 0;
  g_bounds_chain_max = 0;
  g_bounds_miss_count = 0;
  g_bounds_irq_pend_count = 0;
  g_bounds_dr_read_log_count = 0;
  g_bounds_taint_write_log_count = 0;
  g_bounds_need_upper = false;
  g_bounds_need_min = false;
  g_bounds_upper_done = false;
  g_bounds_upper_len = 0;
  g_bounds_min_done = false;
  g_bounds_min_len = 0;
  g_bounds_preparing_exit = false;
  g_bounds_consumer_log_count = 0;
  g_bounds_read_entry_guess_pc = 0;
  g_bounds_write_hook = 0;
  memset(g_bounds_consume_pcs, 0, sizeof(g_bounds_consume_pcs));
  g_bounds_num_consume_pcs = 0;
  memset(g_bounds_diag_entries, 0, sizeof(g_bounds_diag_entries));
  g_bounds_num_diag_hooks = 0;
#if BOUNDS_PC_TRACE_ENABLE
  g_bounds_pc_trace_fp = NULL;
  g_bounds_pc_trace_count = 0;
#endif

  reset_datatrcker_and_global_vars();
}

// Minimal JSON integer/hex parser: extract value for a given key from a JSON object string
// Returns 0 if not found
static uint32_t json_extract_int(const char *json_obj, const char *key) {
  char search[128];
  snprintf(search, sizeof(search), "\"%s\":", key);
  const char *pos = strstr(json_obj, search);
  if (!pos) return 0;
  pos += strlen(search);

  // Skip whitespace
  while (*pos == ' ' || *pos == '\t') pos++;

  if (*pos == '"') {
    // Hex string like "0x..."
    pos++;
    uint32_t val = 0;
    if (strncmp(pos, "0x", 2) == 0) {
      sscanf(pos, "%x", &val);
    } else {
      sscanf(pos, "%u", &val);
    }
    return val;
  } else {
    // Plain integer
    int val = 0;
    sscanf(pos, "%d", &val);
    return (uint32_t)val;
  }
}

// Parse a JSON fragment like "[\"0x804fcde\", \"0x804fcef\"]" into an array of uint32 PCs.
// Handles quoted/unquoted hex (0x...), skips whitespace/commas/brackets, filters 0 values.
// Returns the number of PCs extracted (capped at `max`).
static int parse_consume_pcs(const char *json, uint32_t *out, int max) {
  if (!json || !out || max <= 0) return 0;
  int n = 0;
  const char *p = json;
  while (*p && n < max) {
    // Skip separators / decoration
    while (*p && (*p == '"' || *p == ' ' || *p == ',' ||
                  *p == '[' || *p == ']' || *p == '\t' ||
                  *p == '\n' || *p == '\r')) {
      p++;
    }
    if (!*p) break;
    // Recognise 0x... only; ignore decimals to stay safe
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
      uint32_t pc = 0;
      if (sscanf(p, "%x", &pc) == 1 && pc != 0) {
        out[n++] = pc;
      }
    }
    // Advance to next separator
    while (*p && *p != ',' && *p != ']' && *p != '"') p++;
  }
  return n;
}

// Reload DT arrays from JSON file
void json_reload_dt_arrays(uc_engine *uc) {
  if (g_json_file_path[0] == 0) {
    printf("[JSON_RELOAD] No JSON path configured, skipping\n");
    return;
  }

  FILE *fp = fopen(g_json_file_path, "r");
  if (!fp) {
    printf("[JSON_RELOAD] File not found: %s, starting fresh\n", g_json_file_path);
    return;
  }

  fseek(fp, 0, SEEK_END);
  long fsize = ftell(fp);
  rewind(fp);
  if (fsize <= 0 || fsize > 1048576) {  // max 1MB
    fclose(fp);
    return;
  }

  char *buf = malloc(fsize + 1);
  if (!buf) { fclose(fp); return; }
  fread(buf, 1, fsize, fp);
  buf[fsize] = '\0';
  fclose(fp);

  // Parse irq_dt_set array
  const char *irq_section = strstr(buf, "\"irq_dt_set\":");
  if (irq_section) {
    const char *p = strstr(irq_section, "[");
    if (p) {
      p++; // skip '['
      while (*p) {
        // Skip whitespace and stop if array ended
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
        if (*p == ']') break;
        // Find next DT object
        const char *obj_start = strstr(p, "{");
        if (!obj_start) break;
        const char *obj_end = strstr(obj_start, "}");
        if (!obj_end) break;

        // Extract fields
        uint32_t dr = json_extract_int(obj_start, "dr");
        if (dr == 0) { p = obj_end + 1; continue; }

        uint32_t callread_pc = json_extract_int(obj_start, "callread_pc");
        uint32_t read_pc     = json_extract_int(obj_start, "read_pc");
        uint32_t buffer_addr = json_extract_int(obj_start, "buffer_addr");
        uint32_t irq_pc      = json_extract_int(obj_start, "irq_pc");
        uint32_t avail_pc    = json_extract_int(obj_start, "avail_pc");
        uint32_t rx_head     = json_extract_int(obj_start, "rx_head");
        uint32_t rx_tail     = json_extract_int(obj_start, "rx_tail");
        short buffer_len     = (short)json_extract_int(obj_start, "buffer_len");
        short buffer_min_len = (short)json_extract_int(obj_start, "buffer_min_len");
        int consume_count    = (int)json_extract_int(obj_start, "consume_count");

        printf("[JSON_RELOAD] irq_dt: dr=0x%x irq_pc=0x%x buf=0x%x avail=0x%x\n",
               dr, irq_pc, buffer_addr, avail_pc);

        fill_data_tracker_irq_dt_array(dr, callread_pc, read_pc, buffer_addr,
                                       irq_pc, avail_pc, rx_head, rx_tail,
                                       buffer_len, buffer_min_len, consume_count,
                                       vtor_num);
        // Extract per-DT consume_pc_set
        {
          const char *cp = strstr(obj_start, "\"consume_pc_set\":");
          if (cp && cp < obj_end) {
            const char *s = strstr(cp, "[");
            const char *e = strstr(cp, "]");
            if (s && e && e > s && e < obj_end) {
              int n = e - s + 1;
              if (n < 256) {
                memcpy(irq_dt_array[irq_dt_array_index-1].consume_pcs, s, n);
                irq_dt_array[irq_dt_array_index-1].consume_pcs[n] = 0;
              }
            }
          }
        }

        p = obj_end + 1;
        // Stop at array boundary: if ] appears before next {, we're done
        const char *next_brace = strstr(p, "{");
        const char *next_bracket = strstr(p, "]");
        if (!next_brace || (next_bracket && next_bracket < next_brace)) break;
      }
    }
  }

  // Parse main_dt_set array
  const char *main_section = strstr(buf, "\"main_dt_set\":");
  if (main_section) {
    const char *p = strstr(main_section, "[");
    if (p) {
      p++;
      while (*p) {
        // Skip whitespace and stop if array ended
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
        if (*p == ']') break;
        const char *obj_start = strstr(p, "{");
        if (!obj_start) break;
        const char *obj_end = strstr(obj_start, "}");
        if (!obj_end) break;

        uint32_t dr = json_extract_int(obj_start, "dr");
        if (dr == 0) { p = obj_end + 1; continue; }

        uint32_t callread_pc = json_extract_int(obj_start, "callread_pc");
        uint32_t read_pc     = json_extract_int(obj_start, "read_pc");
        uint32_t buffer_addr = json_extract_int(obj_start, "buffer_addr");
        uint32_t irq_pc      = json_extract_int(obj_start, "irq_pc");
        uint32_t avail_pc    = json_extract_int(obj_start, "avail_pc");
        uint32_t rx_head     = json_extract_int(obj_start, "rx_head");
        uint32_t rx_tail     = json_extract_int(obj_start, "rx_tail");
        short buffer_len     = (short)json_extract_int(obj_start, "buffer_len");
        short buffer_min_len = (short)json_extract_int(obj_start, "buffer_min_len");
        int consume_count    = (int)json_extract_int(obj_start, "consume_count");

        printf("[JSON_RELOAD] main_dt: dr=0x%x read_pc=0x%x avail=0x%x\n",
               dr, read_pc, avail_pc);

        fill_data_tracker_main_dt_array(dr, callread_pc, read_pc, buffer_addr,
                                        irq_pc, avail_pc, rx_head, rx_tail,
                                        buffer_len, buffer_min_len, consume_count);
        // Extract per-DT consume_pc_set
        {
          const char *cp = strstr(obj_start, "\"consume_pc_set\":");
          if (cp && cp < obj_end) {
            const char *s = strstr(cp, "[");
            const char *e = strstr(cp, "]");
            if (s && e && e > s && e < obj_end) {
              int n = e - s + 1;
              if (n < 256) {
                memcpy(main_dt_array[main_dt_array_index-1].consume_pcs, s, n);
                main_dt_array[main_dt_array_index-1].consume_pcs[n] = 0;
              }
            }
          }
        }

        p = obj_end + 1;
        // Stop at array boundary
        const char *next_brace2 = strstr(p, "{");
        const char *next_bracket2 = strstr(p, "]");
        if (!next_brace2 || (next_bracket2 && next_bracket2 < next_brace2)) break;
      }
    }
  }

  free(buf);

  dt_learning_log("[JSON_RELOAD] irq_dt=%d main_dt=%d",
                  irq_dt_array_index, main_dt_array_index);
}

// Check if a DR address is already managed by a known DT
static bool dr_has_known_dt(uint32_t dr) {
  khint_t k = kh_get(dr_dt, hash_table, dr);
  return (k != kh_end(hash_table));
}

// Rebuild placeholder DTs and monitor hooks for unknown DRs
void rebuild_pending_drs(uc_engine *uc) {
  for (int i = 0; i < g_num_dr_addrs; i++) {
    uint32_t dr = g_all_dr_addrs[i];

    // Skip if already has a known DT (from JSON)
    if (dr_has_known_dt(dr)) {
      continue;
    }

    // Skip if already has a pending entry
    bool already_pending = false;
    for (int j = 0; j < pending_dt_array_index; j++) {
      if (pending_dt_array[j].dr == dr) {
        already_pending = true;
        break;
      }
    }
    if (already_pending) continue;

    // Create placeholder DataTracker
    DataTracker *dt = &pending_dt_array[pending_dt_array_index];
    memset(dt, 0, sizeof(DataTracker));
    dt->dr = dr;

    // Fill FIFO with magic token 0xAA as initial taint
    memset(dt->fifo, 0xAA, 1);
    dt->fifo_head = 1;
    dt->fifo_tail = 0;

    // Insert into hash table
    int ret = 0;
    khint_t k = kh_put(dr_dt, hash_table, dr, &ret);
    if (ret != -1) {
      kh_value(hash_table, k) = dt;
    }

    // Add MEM_READ_AFTER hook for this DR
    uc_hook hook_handle = 0;
    uc_err err = uc_hook_add(uc, &hook_handle, UC_HOOK_MEM_READ_AFTER,
                              hook_pending_dr_read_after, NULL, dr, dr);
    if (err == UC_ERR_OK && g_num_pending_hooks < MAX_PENDING_HOOKS) {
      g_pending_hook_handles[g_num_pending_hooks++] = hook_handle;
    }

    pending_dt_array_index++;
    dt_learning_log("[PENDING] dr=0x%x placeholder created", dr);
  }
  dt_learning_log("[PENDING] total=%d", pending_dt_array_index);
}

// Per-round reload: called after restore_snapshot when discovery occurred
int per_round_reload(uc_engine *uc) {
  printf("[PER_ROUND] Starting reload...\n");
  fflush(stdout);

  // 1. Clean up old hooks
  cleanup_avail_and_pending_hooks(uc);

  // 2. Reset state
  reset_all_tracker_state();

  // 3. Read JSON & fill known DT arrays
  json_reload_dt_arrays(uc);

  // 4. Add normal avail hooks for DTs that are already complete. Incomplete
  // irq_dt entries are intentionally skipped here and handled by bounds
  // learning below.
  ufuzz_adapter_add_avail_hook(uc);

  // 5. Prefer post-static-analysis bounds learning for incomplete irq_dt
  // entries. Pending DR discovery remains disabled while bounds is active, but
  // complete DTs keep their normal avail hooks installed.
  if (start_bounds_learning_if_needed(uc)) {
    printf("[PER_ROUND] Bounds learning active: %d main_dt, %d irq_dt, %d pending\n",
           main_dt_array_index, irq_dt_array_index, pending_dt_array_index);
    return 0;
  }

  // 6. Create placeholder DTs for unknown DRs
  rebuild_pending_drs(uc);

  // // Init delivery budget
  // init_delivery_budget();

  printf("[PER_ROUND] Reload complete: %d main_dt, %d irq_dt, %d pending\n",
         main_dt_array_index, irq_dt_array_index, pending_dt_array_index);
  return 0;
}

// ====== Channel Discovery: JSON Append Helpers ======

// Write a complete JSON file with semu-fuzz compatible format
static int write_full_json(void) {
  if (g_json_file_path[0] == 0) return -1;

  FILE *fp = fopen(g_json_file_path, "w");
  if (!fp) {
    printf("[JSON_WRITE] Cannot open %s for writing\n", g_json_file_path);
    return -1;
  }

  fprintf(fp, "{\n");

  // irq_dt_set
  fprintf(fp, "  \"irq_dt_set\": [\n");
  for (int i = 0; i < irq_dt_array_index; i++) {
    DataTracker *dt = &irq_dt_array[i];
    fprintf(fp, "    {\"dr\": \"0x%x\", \"callread_pc\": \"0x%x\", "
            "\"read_pc\": \"0x%x\", \"buffer_addr\": \"0x%x\", "
            "\"irq_pc\": \"0x%x\", \"avail_pc\": \"0x%x\", "
            "\"rx_head\": %u, \"rx_tail\": %u, "
            "\"buffer_len\": %d, \"buffer_min_len\": %d, "
            "\"consume_count\": 0, "
            "\"consume_pc_set\": %s}%s\n",
            dt->dr, dt->callread_pc, dt->read_pc, dt->buffer_addr,
            dt->irq_pc, dt->avail_pc, dt->rx_head, dt->rx_tail,
            dt->buffer_len, dt->buffer_min_len,
            dt->consume_pcs[0] ? dt->consume_pcs : "[]",
            (i < irq_dt_array_index - 1 || main_dt_array_index > 0) ? "," : "");
  }
  fprintf(fp, "  ],\n");

  // main_dt_set
  fprintf(fp, "  \"main_dt_set\": [\n");
  for (int i = 0; i < main_dt_array_index; i++) {
    DataTracker *dt = &main_dt_array[i];
    fprintf(fp, "    {\"dr\": \"0x%x\", \"callread_pc\": \"0x%x\", "
            "\"read_pc\": \"0x%x\", \"buffer_addr\": \"0x%x\", "
            "\"irq_pc\": \"0x%x\", \"avail_pc\": \"0x%x\", "
            "\"rx_head\": %u, \"rx_tail\": %u, "
            "\"buffer_len\": %d, \"buffer_min_len\": %d, "
            "\"consume_count\": 0, "
            "\"consume_pc_set\": %s}%s\n",
            dt->dr, dt->callread_pc, dt->read_pc, dt->buffer_addr,
            dt->irq_pc, dt->avail_pc, dt->rx_head, dt->rx_tail,
            dt->buffer_len, dt->buffer_min_len,
            dt->consume_pcs[0] ? dt->consume_pcs : "[]",
            (i < main_dt_array_index - 1) ? "," : "");
  }
  fprintf(fp, "  ],\n");

  // dt_created_dr
  fprintf(fp, "  \"dt_created_dr\": [");
  int created_count = 0;
  for (int i = 0; i < irq_dt_array_index; i++) {
    fprintf(fp, "%s\"0x%x\"", created_count > 0 ? ", " : "", irq_dt_array[i].dr);
    created_count++;
  }
  for (int i = 0; i < main_dt_array_index; i++) {
    fprintf(fp, "%s\"0x%x\"", created_count > 0 ? ", " : "", main_dt_array[i].dr);
    created_count++;
  }
  fprintf(fp, "],\n");

  // Remaining fields (empty, for semu-fuzz compatibility)
  fprintf(fp, "  \"blacklist\": [],\n");
  fprintf(fp, "  \"indirect_src_addrs\": [],\n");
  fprintf(fp, "  \"data_regs\": [],\n");
  fprintf(fp, "  \"avail_dt_dict\": {},\n");
  fprintf(fp, "  \"consume_dt_dict\": {},\n");
  fprintf(fp, "  \"global_vars\": []\n");
  fprintf(fp, "}\n");

  fclose(fp);
  dt_learning_log("[JSON_WRITE] irq_dt=%d main_dt=%d path=%s",
                  irq_dt_array_index, main_dt_array_index, g_json_file_path);
  return 0;
}

// ====== Ghidra callback management ======

void set_code_hook_range(uint64_t begin, uint64_t size) {
  if (size == 0) {
    dt_learning_log("[BOUNDS] CODE_HOOK_RANGE_KEEP begin=0x%llx end=0x%llx reason=zero_size",
                    (unsigned long long)g_code_hook_begin,
                    (unsigned long long)g_code_hook_end);
    return;
  }

  g_code_hook_begin = begin;
  if (UINT64_MAX - begin < size - 1) {
    g_code_hook_end = UINT64_MAX;
  } else {
    g_code_hook_end = begin + size - 1;
  }

  dt_learning_log("[BOUNDS] CODE_HOOK_RANGE_SET begin=0x%llx end=0x%llx size=0x%llx",
                  (unsigned long long)g_code_hook_begin,
                  (unsigned long long)g_code_hook_end,
                  (unsigned long long)size);
}

void set_ghidra_callback(void *cb) {
    g_ghidra_callback = cb;
}

// ====== Channel Discovery: Callbacks ======

// UC_HOOK_MEM_READ_AFTER callback for pending DRs
void hook_pending_dr_read_after(uc_engine *uc, uc_mem_type type,
    uint64_t address, int size, int64_t value, void *user_data) {

  uint32_t dr = (uint32_t)address;

  if (g_in_discovery_mode) {
    // Already in discovery, ignore further DR reads
    return;
  }

  uint32_t ipsr = 0;
  uc_reg_read(uc, UC_ARM_REG_IPSR, &ipsr);
  uint32_t pc = 0;
  uc_reg_read(uc, UC_ARM_REG_PC, &pc);

  if (ipsr != 0) {
    // === IRQ context → interrupt-read type ===
    dt_learning_log("[DISCOVERY] IRQ_DR_READ dr=0x%x ipsr=0x%x pc=0x%x",
                    dr, ipsr, pc);

    g_discovery_dr = dr;
    g_discovery_taint = 0xAA;  // magic token byte, not full word

    // Read VTOR from CPU register
    uint32_t vtor = 0;
    uc_mem_read(uc, 0xE000ED08, &vtor, 4);
    vtor_num = vtor;  // also cache globally

    // Calculate IRQ PC from vector table
    uint64_t handler_addr = vtor + ((uint64_t)ipsr * 4);
    uint32_t handler_val = 0;
    uc_mem_read(uc, handler_addr, &handler_val, sizeof(handler_val));
    g_discovery_irq_pc = handler_val - 1;  // thumb bit adjustment

    dt_learning_log("[DISCOVERY] IRQ_PC dr=0x%x irq_pc=0x%x vtor=0x%x ipsr=0x%x",
                    dr, g_discovery_irq_pc, vtor, ipsr);

    // // Remove ALL pending DR hooks to prevent interference this round.
    // // They will be properly rebuilt by per_round_reload next round.
    // for (int i = 0; i < g_num_pending_hooks; i++) {
    //   if (g_pending_hook_handles[i]) {
    //     uc_hook_del(uc, g_pending_hook_handles[i]);
    //     g_pending_hook_handles[i] = 0;
    //   }
    // }
    // g_num_pending_hooks = 0;

    // Add global discovery tracking hooks
    uc_hook_add(uc, &g_discovery_mem_write_hook, UC_HOOK_MEM_WRITE,
                hook_discovery_mem_write, NULL, 0, 0xFFFFFFFF);

    g_in_discovery_mode = true;
    g_discovery_addr_count = 0;
    g_discovery_buffer_addr = 0;

  } else {
    // === Main loop context → firmware-read type (main_read) ===
    dt_learning_log("[DISCOVERY] MAIN_DR_READ dr=0x%x pc=0x%x", dr, pc);

    uint32_t lr = 0;
    uc_reg_read(uc, UC_ARM_REG_LR, &lr);

    // Create main_dt with read_pc and callread_pc
    DataTracker *dt = &main_dt_array[main_dt_array_index];
    memset(dt, 0, sizeof(DataTracker));
    dt->dr = dr;
    dt->read_pc = pc;
    dt->callread_pc = lr;  // raw LR, corrected by Ghidra correct_lr later
    dt->irq_pc = 0;
    dt->buffer_addr = 0;
    dt->avail_pc = 0;  // deferred to static analysis

    // Insert into hash table
    int ret = 0;
    khint_t k = kh_put(dr_dt, hash_table, dr, &ret);
    if (ret != -1) {
      kh_value(hash_table, k) = dt;
    }
    main_dt_array_index++;

    dt_learning_log("[DISCOVERY] MAIN_DT dr=0x%x read_pc=0x%x callread_pc=0x%x",
                    dr, pc, lr);

    // Signal Ghidra daemon: write JSON path to pending file
    if (g_ghidra_callback) {
      int fd = open("/tmp/ghidra_pending", O_CREAT | O_WRONLY | O_TRUNC, 0600);
      if (fd >= 0) {
        write(fd, g_json_file_path, strlen(g_json_file_path));
        close(fd);
        dt_learning_log("[GHIDRA_PENDING] path=%s reason=main_dt dr=0x%x",
                        g_json_file_path, dr);
      }
    }

    // Write updated JSON
    write_full_json();

    g_discovery_occurred = true;
    do_exit(uc, UC_ERR_OK);
  }
}

// UC_HOOK_MEM_WRITE callback during discovery — track buffer writes
void hook_discovery_mem_write(uc_engine *uc, uc_mem_type type,
    uint64_t address, int size, int64_t value, void *user_data) {

  if (!g_in_discovery_mode) return;

  uint32_t ipsr = 0;
  uc_reg_read(uc, UC_ARM_REG_IPSR, &ipsr);

  if (ipsr != 0) {
    // ---- In IRQ context: track taint-matching writes ----
    if ((uint32_t)value == g_discovery_taint) {
      // Always track write addresses (Phase 1 buffer-addr discovery)
      if (g_discovery_addr_count < MAX_DISCOVERY_ADDRS) {
        g_discovery_addr_list[g_discovery_addr_count++] = (uint32_t)address;
        dt_learning_log("[DISCOVERY] TAINT_WRITE #%d addr=0x%x val=0x%x",
                        g_discovery_addr_count, (uint32_t)address,
                        (uint32_t)value);
      }
    }
  } else {
    // ---- In main loop context ----
    if (g_discovery_addr_count > 0 && g_discovery_buffer_addr == 0) {
      // buffer_addr just found; capture the main-loop read site next.
      g_discovery_buffer_addr =
          g_discovery_addr_list[g_discovery_addr_count - 1];
      dt_learning_log("[DISCOVERY] BUFFER_ADDR dr=0x%x buf=0x%x writes=%d",
                      g_discovery_dr, g_discovery_buffer_addr,
                      g_discovery_addr_count);

      // Static analysis needs buffer_addr plus the main-loop read site.
      // Upper/lower bounds are learned later, after Ghidra fills avail_pc and
      // consume_pc_set, so do not start chain fill in discovery anymore.
      uc_hook_add(uc, &g_discovery_buffer_read_hook, UC_HOOK_MEM_READ_AFTER,
                  hook_phase1_buffer_read, NULL,
                  g_discovery_buffer_addr, g_discovery_buffer_addr);
    }

    try_finalize(uc);
  }
}

// ====== Channel Discovery: Phase 1 buffer read callback ======

// Fires when main loop reads the discovered buffer address.
// Captures read_pc (PC at buffer read) and callread_pc (LR = caller).
// Bounds are inferred later, after static analysis supplies avail/consume PCs.
void hook_phase1_buffer_read(uc_engine *uc, uc_mem_type type,
    uint64_t address, int size, int64_t value, void *user_data) {

  if (!g_in_discovery_mode) return;
  if (g_read_pc_done) return;

  uint32_t ipsr = 0;
  uc_reg_read(uc, UC_ARM_REG_IPSR, &ipsr);
  if (ipsr != 0) return; // only capture in main loop

  uint32_t pc = 0;
  uint32_t lr = 0;
  uc_reg_read(uc, UC_ARM_REG_PC, &pc);
  uc_reg_read(uc, UC_ARM_REG_LR, &lr);

  g_discovery_read_pc = pc;
  g_discovery_callread_pc = lr;  // raw LR, corrected by Ghidra correct_lr later
  g_read_pc_done = true;

  if (g_discovery_buffer_read_hook) {
    uc_hook_del(uc, g_discovery_buffer_read_hook);
    g_discovery_buffer_read_hook = 0;
  }

  dt_learning_log("[DISCOVERY] BUFFER_READ_PC dr=0x%x read_pc=0x%x callread_pc=0x%x",
                  g_discovery_dr, g_discovery_read_pc,
                  g_discovery_callread_pc);

  try_finalize(uc);
}

// ====== Post-static-analysis buffer bounds inference ======

static void bounds_cleanup_hooks(uc_engine *uc) {
  if (g_bounds_write_hook) { uc_hook_del(uc, g_bounds_write_hook); g_bounds_write_hook = 0; }
  (void)uc;
  memset(g_bounds_diag_entries, 0, sizeof(g_bounds_diag_entries));
  g_bounds_num_diag_hooks = 0;
}

static DataTracker *bounds_find_dt(void) {
  if (g_bounds_dt_dr == 0) return NULL;
  for (int i = 0; i < irq_dt_array_index; i++) {
    if (irq_dt_array[i].dr == g_bounds_dt_dr) {
      return &irq_dt_array[i];
    }
  }
  return NULL;
}

#if DT_DIAG_HOOK_ENABLE
static bool bounds_consumer_log_allowed(void) {
  if (g_bounds_consumer_log_count >= BOUNDS_CONSUMER_LOG_LIMIT) return false;
  g_bounds_consumer_log_count++;
  return true;
}

static bool bounds_read_u32(uc_engine *uc, uint32_t addr, uint32_t *out) {
  if (!addr || !out) return false;
  *out = 0;
  return uc_mem_read(uc, addr, out, sizeof(*out)) == UC_ERR_OK;
}

static bool bounds_read_u16(uc_engine *uc, uint32_t addr, uint16_t *out) {
  if (!addr || !out) return false;
  *out = 0;
  return uc_mem_read(uc, addr, out, sizeof(*out)) == UC_ERR_OK;
}

static bool bounds_read_u8(uc_engine *uc, uint32_t addr, uint8_t *out) {
  if (!addr || !out) return false;
  *out = 0;
  return uc_mem_read(uc, addr, out, sizeof(*out)) == UC_ERR_OK;
}

static void bounds_add_diag_hook(uc_engine *uc, uint32_t pc,
    uc_cb_hookcode_t cb, const char *name) {
  if (!pc || !cb) return;
  if (g_bounds_num_diag_hooks >= BOUNDS_DIAG_HOOK_MAX) {
    dt_learning_log("[BOUNDS] DIAG_HOOK_SKIP name=%s pc=0x%x reason=full",
                    name ? name : "unknown", pc);
    return;
  }

  (void)uc;
  g_bounds_diag_entries[g_bounds_num_diag_hooks++] =
      (BoundsDiagDispatchEntry){ .pc = pc, .cb = cb, .name = name };
  dt_learning_log("[BOUNDS] DIAG_DISPATCH_ADD name=%s pc=0x%x",
                  name ? name : "unknown", pc);
}

static void hook_bounds_avail_return(uc_engine *uc, uint64_t address,
    uint32_t size, void *user_data) {
  (void)size; (void)user_data;
  if (g_bounds_state != 1) return;
  if (!bounds_consumer_log_allowed()) return;

  uint32_t r0 = 0;
  uint32_t ipsr = 0;
  uc_reg_read(uc, UC_ARM_REG_R0, &r0);
  uc_reg_read(uc, UC_ARM_REG_IPSR, &ipsr);
  DataTracker *dt = bounds_find_dt();

  dt_learning_log("[BOUNDS] AVAIL_RET pc=0x%x ipsr=0x%x r0=0x%x dr=0x%x pends=%d upper_done=%d min_done=%d",
                  (uint32_t)address, ipsr, r0, dt ? dt->dr : g_bounds_dt_dr,
                  g_bounds_irq_pend_count,
                  g_bounds_upper_done ? 1 : 0,
                  g_bounds_min_done ? 1 : 0);
}

static void hook_bounds_process_call(uc_engine *uc, uint64_t address,
    uint32_t size, void *user_data) {
  (void)size; (void)user_data;
  if (g_bounds_state != 1) return;
  if (!bounds_consumer_log_allowed()) return;

  uint32_t r0 = 0;
  uint32_t ipsr = 0;
  uc_reg_read(uc, UC_ARM_REG_R0, &r0);
  uc_reg_read(uc, UC_ARM_REG_IPSR, &ipsr);

  dt_learning_log("[BOUNDS] PROCESS_INPUT_CALL pc=0x%x ipsr=0x%x r0=0x%x pends=%d",
                  (uint32_t)address, ipsr, r0, g_bounds_irq_pend_count);
}

static void hook_bounds_callread_before(uc_engine *uc, uint64_t address,
    uint32_t size, void *user_data) {
  (void)size; (void)user_data;
  if (g_bounds_state != 1) return;
  if (!bounds_consumer_log_allowed()) return;

  uint32_t r0 = 0;
  uint32_t r3 = 0;
  uint32_t lr = 0;
  uint32_t ipsr = 0;
  uc_reg_read(uc, UC_ARM_REG_R0, &r0);
  uc_reg_read(uc, UC_ARM_REG_R3, &r3);
  uc_reg_read(uc, UC_ARM_REG_LR, &lr);
  uc_reg_read(uc, UC_ARM_REG_IPSR, &ipsr);

  dt_learning_log("[BOUNDS] CALLREAD_BEFORE pc=0x%x ipsr=0x%x this=0x%x target=0x%x lr=0x%x pends=%d",
                  (uint32_t)address, ipsr, r0, r3, lr,
                  g_bounds_irq_pend_count);
}

static void hook_bounds_callread_return(uc_engine *uc, uint64_t address,
    uint32_t size, void *user_data) {
  (void)size; (void)user_data;
  if (g_bounds_state != 1) return;
  if (!bounds_consumer_log_allowed()) return;

  uint32_t r0 = 0;
  uint32_t ipsr = 0;
  uc_reg_read(uc, UC_ARM_REG_R0, &r0);
  uc_reg_read(uc, UC_ARM_REG_IPSR, &ipsr);

  dt_learning_log("[BOUNDS] CALLREAD_RET pc=0x%x ipsr=0x%x r0=0x%x empty=%d pends=%d",
                  (uint32_t)address, ipsr, r0,
                  r0 == 0xffffffffu ? 1 : 0,
                  g_bounds_irq_pend_count);
}

static void hook_bounds_read_entry_guess(uc_engine *uc, uint64_t address,
    uint32_t size, void *user_data) {
  (void)size; (void)user_data;
  if (g_bounds_state != 1) return;
  if (!bounds_consumer_log_allowed()) return;

  uint32_t this_ptr = 0;
  uint32_t ipsr = 0;
  uint32_t buf = 0;
  uint16_t head = 0;
  uint16_t tail = 0;
  uc_reg_read(uc, UC_ARM_REG_R0, &this_ptr);
  uc_reg_read(uc, UC_ARM_REG_IPSR, &ipsr);

  bool buf_ok = bounds_read_u32(uc, this_ptr + 0x130, &buf);
  bool head_ok = bounds_read_u16(uc, this_ptr + 0x134, &head);
  bool tail_ok = bounds_read_u16(uc, this_ptr + 0x136, &tail);
  DataTracker *dt = bounds_find_dt();

  dt_learning_log("[BOUNDS] READ_ENTRY_GUESS pc=0x%x ipsr=0x%x this=0x%x buf=0x%x buf_ok=%d head=%u head_ok=%d tail=%u tail_ok=%d empty=%d dt_buf=0x%x pends=%d",
                  (uint32_t)address, ipsr, this_ptr,
                  buf_ok ? buf : 0, buf_ok ? 1 : 0,
                  head, head_ok ? 1 : 0,
                  tail, tail_ok ? 1 : 0,
                  (head_ok && tail_ok && head == tail) ? 1 : 0,
                  dt ? dt->buffer_addr : 0,
                  g_bounds_irq_pend_count);
}

static void hook_bounds_read_pc_diag(uc_engine *uc, uint64_t address,
    uint32_t size, void *user_data) {
  (void)size; (void)user_data;
  if (g_bounds_state != 1) return;
  if (!bounds_consumer_log_allowed()) return;

  uint32_t r2 = 0;
  uint32_t r3 = 0;
  uint32_t ipsr = 0;
  uint8_t byte = 0;
  uc_reg_read(uc, UC_ARM_REG_R2, &r2);
  uc_reg_read(uc, UC_ARM_REG_R3, &r3);
  uc_reg_read(uc, UC_ARM_REG_IPSR, &ipsr);

  uint32_t read_addr = r2 + r3;
  bool byte_ok = bounds_read_u8(uc, read_addr, &byte);
  dt_learning_log("[BOUNDS] READ_PC_HIT pc=0x%x ipsr=0x%x buf_reg=0x%x tail_reg=%u read_addr=0x%x byte=0x%x byte_ok=%d pends=%d",
                  (uint32_t)address, ipsr, r2, r3, read_addr,
                  byte_ok ? byte : 0, byte_ok ? 1 : 0,
                  g_bounds_irq_pend_count);
}
#endif

static void bounds_fill_fifo(DataTracker *dt) {
  memset(dt->fifo, 0xAA, BOUNDS_FIFO_SIZE);
  dt->fifo_head = BOUNDS_FIFO_SIZE;
  dt->fifo_tail = 0;
  g_bounds_fifo_seeded = true;
}

static bool bounds_value_has_taint(int size, int64_t value) {
  int width = size;
  if (width <= 0) return false;
  if (width > 8) width = 8;
  for (int i = 0; i < width; i++) {
    if (((uint64_t)value >> (i * 8) & 0xff) == 0xAA) {
      return true;
    }
  }
  return false;
}

static uint32_t bounds_current_len(void) {
  if (!g_bounds_chain_started || g_bounds_chain_max < g_bounds_chain_min) {
    return 0;
  }
  return g_bounds_chain_max - g_bounds_chain_min + 1;
}

static void bounds_reset_upper_chain(DataTracker *dt, const char *reason,
                                     uint32_t upper) {
  uint32_t old_min = g_bounds_chain_min;
  uint32_t old_max = g_bounds_chain_max;
  int old_misses = g_bounds_miss_count;

  g_bounds_chain_started = false;
  g_bounds_chain_min = dt && dt->buffer_addr ? dt->buffer_addr : 0;
  g_bounds_chain_max = dt && dt->buffer_addr ? dt->buffer_addr - 1 : 0;
  g_bounds_miss_count = 0;

  dt_learning_log("[BOUNDS] UPPER_CHAIN_RESET reason=%s dr=0x%x invalid_upper=%u old_min=0x%x old_max=0x%x old_misses=%d",
                  reason, dt ? dt->dr : 0, upper, old_min, old_max,
                  old_misses);
}

static bool bounds_apply_partial_result(DataTracker *dt) {
  if (!dt) return false;
  bool changed = false;

  if (g_bounds_upper_done && g_bounds_upper_len > 1 &&
      dt->buffer_len != g_bounds_upper_len) {
    dt->buffer_len = g_bounds_upper_len;
    changed = true;
  }

  if (g_bounds_min_done && g_bounds_min_len > 0) {
    short min_len = g_bounds_min_len;
    if (dt->buffer_len > 1 && min_len > dt->buffer_len) {
      min_len = dt->buffer_len;
    }
    if (dt->buffer_min_len != min_len) {
      dt->buffer_min_len = min_len;
      changed = true;
    }
  }

  return changed;
}

static bool bounds_is_complete(DataTracker *dt) {
  return dt && dt->buffer_len > 1 && dt->buffer_min_len > 0;
}

static void bounds_prepare_retry_on_exit(uc_engine *uc, const char *reason) {
  if (g_bounds_state != 1 || g_bounds_preparing_exit) return;
  g_bounds_preparing_exit = true;

  DataTracker *dt = bounds_find_dt();
  if (!dt) {
    dt_learning_log("[BOUNDS] RETRY_EXIT reason=%s result_lost dr=0x%x pends=%d",
                    reason, g_bounds_dt_dr, g_bounds_irq_pend_count);
    bounds_cleanup_hooks(uc);
    g_bounds_state = 0;
    g_discovery_occurred = true;
    return;
  }

  bool changed = bounds_apply_partial_result(dt);
  if (changed) {
    write_full_json();
  }

  dt_learning_log("[BOUNDS] RETRY_EXIT reason=%s dr=0x%x pends=%d upper_done=%d upper=%d min_done=%d min=%d json_upper=%d json_min=%d changed=%d",
                  reason, dt->dr, g_bounds_irq_pend_count,
                  g_bounds_upper_done ? 1 : 0, g_bounds_upper_len,
                  g_bounds_min_done ? 1 : 0, g_bounds_min_len,
                  dt->buffer_len, dt->buffer_min_len, changed ? 1 : 0);
  bounds_cleanup_hooks(uc);
  g_bounds_state = 0;
  g_discovery_occurred = true;
}

static void bounds_finish_round(uc_engine *uc, const char *reason) {
  bounds_prepare_retry_on_exit(uc, reason);
  do_exit(uc, UC_ERR_OK);
}

static void bounds_mark_upper_if_valid(uc_engine *uc, const char *reason) {
  if (!g_bounds_need_upper || g_bounds_upper_done) return;

  DataTracker *dt = bounds_find_dt();
  if (!dt) {
    bounds_finish_round(uc, "upper_dt_lost");
    return;
  }

  uint32_t upper = bounds_current_len();
  if (upper > 0x7fff) upper = 0x7fff;
  if (upper <= 1) {
    dt_learning_log("[BOUNDS] UPPER_INVALID reason=%s dr=0x%x upper=%u",
                    reason, dt->dr, upper);
    bounds_reset_upper_chain(dt, reason, upper);
    return;
  }

  g_bounds_upper_len = (short)upper;
  g_bounds_upper_done = true;
  dt->buffer_len = g_bounds_upper_len;
  write_full_json();
  dt_learning_log("[BOUNDS] UPPER_DONE reason=%s dr=0x%x upper=%d min_done=%d min=%d",
                  reason, dt->dr, g_bounds_upper_len,
                  g_bounds_min_done ? 1 : 0, g_bounds_min_len);

  if (bounds_is_complete(dt)) {
    bounds_finish_round(uc, "bounds_complete");
  } else {
    bounds_finish_round(uc, "upper_done_wait_min_next_round");
  }
}

static void hook_bounds_avail(uc_engine *uc, uint64_t address, uint32_t size,
    void *user_data) {
  (void)address; (void)size; (void)user_data;
  if (g_bounds_state != 1) return;

  DataTracker *dt = bounds_find_dt();
  if (!dt) return;

  if (g_bounds_avail_pass_next) {
    g_bounds_avail_pass_next = false;
    dt_learning_log("[BOUNDS] AVAIL_PASS avail=0x%x dr=0x%x pends=%d upper_done=%d min_done=%d",
                    dt->avail_pc, dt->dr, g_bounds_irq_pend_count,
                    g_bounds_upper_done ? 1 : 0,
                    g_bounds_min_done ? 1 : 0);
    return;
  }

  if (!g_bounds_avail_hit) {
    g_bounds_avail_hit = true;
    dt_learning_log("[BOUNDS] AVAIL_HIT avail=0x%x dr=0x%x",
                    dt->avail_pc, dt->dr);
  }

  if (!g_bounds_fifo_seeded || dt->fifo_tail >= dt->fifo_head) {
    bounds_fill_fifo(dt);
    dt_learning_log("[BOUNDS] FIFO_SEED avail=0x%x dr=0x%x size=%d",
                    dt->avail_pc, dt->dr, BOUNDS_FIFO_SIZE);
  }

  if (g_bounds_irq <= 0) {
    const char *irq_source = NULL;
    g_bounds_irq = resolve_irq_num_for_pc(uc, dt->irq_pc, &irq_source);
    if (g_bounds_irq > 0) {
      dt->irq_num = (short)g_bounds_irq;
      dt_learning_log("[BOUNDS] IRQ_FILTER_ADD_AVAIL source=%s dr=0x%x irq_pc=0x%x irq=%d",
                      irq_source, dt->dr, dt->irq_pc, g_bounds_irq);
    } else {
      dt_learning_log("[BOUNDS] IRQ_UNRESOLVED dr=0x%x irq_pc=0x%x",
                      dt->dr, dt->irq_pc);
      return;
    }
  }

  if (g_bounds_irq_pend_count >= BOUNDS_MAX_IRQ_PENDS) {
    dt_learning_log("[BOUNDS] IRQ_BUDGET_DONE dr=0x%x pends=%d max=%d upper_started=%d upper_done=%d min_done=%d",
                    dt->dr, g_bounds_irq_pend_count, BOUNDS_MAX_IRQ_PENDS,
                    g_bounds_chain_started ? 1 : 0,
                    g_bounds_upper_done ? 1 : 0,
                    g_bounds_min_done ? 1 : 0);
    bounds_finish_round(uc, "irq_budget");
    return;
  }

  nvic_set_pending(uc, g_bounds_irq, false);
  g_bounds_avail_pass_next = true;
  g_bounds_irq_pend_count++;
  dt_learning_log("[BOUNDS] PEND_IRQ avail=0x%x dr=0x%x irq=%d count=%d max=%d",
                  dt->avail_pc, dt->dr, g_bounds_irq,
                  g_bounds_irq_pend_count, BOUNDS_MAX_IRQ_PENDS);
}

static void hook_bounds_buffer_write(uc_engine *uc, uc_mem_type type,
    uint64_t address, int size, int64_t value, void *user_data) {
  (void)type; (void)user_data;
  if (g_bounds_state != 1) return;
  if (!bounds_value_has_taint(size, value)) return;

  uint32_t ipsr = 0;
  uc_reg_read(uc, UC_ARM_REG_IPSR, &ipsr);
  if (ipsr == 0) return;

  DataTracker *dt = bounds_find_dt();
  if (!dt || !dt->buffer_addr) return;

  uint32_t addr = (uint32_t)address;
  if (g_bounds_taint_write_log_count < 128) {
    uint32_t pc = 0;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    int32_t rel = dt->buffer_addr ? (int32_t)(addr - dt->buffer_addr) : 0;
    dt_learning_log("[BOUNDS] TAINT_WRITE pc=0x%x ipsr=0x%x addr=0x%x size=%d val=0x%llx buf=0x%x rel=%d in_scan=%d",
                    pc, ipsr, addr, size, (unsigned long long)value,
                    dt->buffer_addr, rel,
                    (dt->buffer_addr &&
                     addr >= dt->buffer_addr &&
                     addr < dt->buffer_addr + BOUNDS_MAX_SCAN) ? 1 : 0);
    g_bounds_taint_write_log_count++;
  }
  if (addr < dt->buffer_addr || addr >= dt->buffer_addr + BOUNDS_MAX_SCAN) {
    return;
  }

  uint32_t write_end = addr + (uint32_t)((size > 0) ? size : 1) - 1;
  if (!g_bounds_chain_started) {
    if (addr == dt->buffer_addr) {
      g_bounds_chain_started = true;
      g_bounds_chain_min = addr;
      g_bounds_chain_max = write_end;
      g_bounds_miss_count = 0;
      dt_learning_log("[BOUNDS] CHAIN_START addr=0x%x size=%d len=%u",
                      addr, size, bounds_current_len());
    }
    return;
  }

  if (addr == g_bounds_chain_max + 1) {
    g_bounds_chain_max = write_end;
    g_bounds_miss_count = 0;
    dt_learning_log("[BOUNDS] CHAIN_EXTEND addr=0x%x size=%d len=%u",
                    addr, size, bounds_current_len());
    return;
  }

  if (addr == g_bounds_chain_min && g_bounds_chain_max > g_bounds_chain_min) {
    dt_learning_log("[BOUNDS] WRAP addr=0x%x upper=%u",
                    addr, bounds_current_len());
    bounds_mark_upper_if_valid(uc, "wrap");
    return;
  }

  g_bounds_miss_count++;
  if (g_bounds_miss_count >= BOUNDS_MISS_LIMIT) {
    dt_learning_log("[BOUNDS] MISS_DONE misses=%d upper=%u last_addr=0x%x",
                    g_bounds_miss_count, bounds_current_len(), addr);
    bounds_mark_upper_if_valid(uc, "miss");
  }
}

static void hook_bounds_consume(uc_engine *uc, uint64_t address, uint32_t size,
    void *user_data) {
  (void)size; (void)user_data;
  if (g_bounds_state != 1) return;

  uint32_t ipsr = 0;
  uc_reg_read(uc, UC_ARM_REG_IPSR, &ipsr);
  uint32_t len = bounds_current_len();
  dt_learning_log("[BOUNDS] CONSUME_HIT pc=0x%x ipsr=0x%x len=%u need_min=%d min_done=%d upper_done=%d upper=%d",
                  (uint32_t)address, ipsr, len,
                  g_bounds_need_min ? 1 : 0,
                  g_bounds_min_done ? 1 : 0,
                  g_bounds_upper_done ? 1 : 0,
                  g_bounds_upper_len);

  if (!g_bounds_need_min) return;
  if (g_bounds_min_done) return;
  if (ipsr != 0) return;

  if (len == 0) return;
  if (len > 0x7fff) len = 0x7fff;

  g_bounds_min_len = (short)len;
  if (g_bounds_min_len < 1) g_bounds_min_len = 1;
  g_bounds_min_done = true;
  DataTracker *dt = bounds_find_dt();
  if (dt) {
    if (dt->buffer_len > 1 && g_bounds_min_len > dt->buffer_len) {
      g_bounds_min_len = dt->buffer_len;
    }
    dt->buffer_min_len = g_bounds_min_len;
    write_full_json();
  }
  dt_learning_log("[BOUNDS] MIN_DONE pc=0x%x min=%d upper_done=%d upper=%d",
                  (uint32_t)address, g_bounds_min_len,
                  g_bounds_upper_done ? 1 : 0, g_bounds_upper_len);
  if (bounds_is_complete(dt)) {
    bounds_finish_round(uc, "bounds_complete");
  }
}

static bool start_bounds_learning_if_needed(uc_engine *uc) {
  int target_idx = -1;
  for (int i = 0; i < irq_dt_array_index; i++) {
    DataTracker *dt = &irq_dt_array[i];
    if (!dt->avail_pc) continue;
    if (!dt->buffer_addr) continue;
    if (!dt->consume_pcs[0]) continue;
    if (dt->buffer_len > 1 && dt->buffer_min_len > 0) continue;
    target_idx = i;
    break;
  }

  if (target_idx < 0) return false;

  DataTracker *dt = &irq_dt_array[target_idx];
  g_bounds_num_consume_pcs = parse_consume_pcs(dt->consume_pcs,
                                               g_bounds_consume_pcs, 16);
  if (g_bounds_num_consume_pcs == 0) {
    dt_learning_log("[BOUNDS] NO_CONSUME_PCS dt=%d dr=0x%x",
                    target_idx, dt->dr);
    return false;
  }

  g_bounds_state = 1;
  g_bounds_dt_idx = target_idx;
  g_bounds_dt_dr = dt->dr;
  g_bounds_irq = 0;
  g_bounds_avail_hit = false;
  g_bounds_avail_pass_next = false;
  g_bounds_fifo_seeded = false;
  g_bounds_chain_started = false;
  g_bounds_chain_min = dt->buffer_addr;
  g_bounds_chain_max = dt->buffer_addr ? dt->buffer_addr - 1 : 0;
  g_bounds_miss_count = 0;
  g_bounds_irq_pend_count = 0;
  g_bounds_dr_read_log_count = 0;
  g_bounds_taint_write_log_count = 0;
  g_bounds_need_upper = dt->buffer_len <= 1;
  g_bounds_need_min = dt->buffer_min_len <= 0;
  g_bounds_upper_done = !g_bounds_need_upper;
  g_bounds_upper_len = dt->buffer_len;
  g_bounds_min_done = !g_bounds_need_min;
  g_bounds_min_len = dt->buffer_min_len;
  g_bounds_preparing_exit = false;
  g_bounds_consumer_log_count = 0;
  g_bounds_read_entry_guess_pc = dt->read_pc > 0x12 ? dt->read_pc - 0x12 : 0;
  memset(g_bounds_diag_entries, 0, sizeof(g_bounds_diag_entries));
  g_bounds_num_diag_hooks = 0;

  // Resolve/filter the target IRQ only after avail_pc is reached. Before that,
  // this stage only installs the hooks needed for bounds learning.

  // The bounds UC_HOOK_CODE callbacks are dispatched by the early global
  // hook_bounds_dispatch hook. Registering them here would miss already
  // translated TBs and would duplicate avail/consume handling.
  uc_hook_add(uc, &g_bounds_write_hook, UC_HOOK_MEM_WRITE,
              hook_bounds_buffer_write, NULL, 0, 0xFFFFFFFF);

#if BOUNDS_PC_TRACE_ENABLE
  g_bounds_pc_trace_round++;
  g_bounds_pc_trace_count = 0;

  char pc_trace_path[128];
  snprintf(pc_trace_path, sizeof(pc_trace_path),
           "/tmp/bounds_pc_trace_%d.log", getpid());
  g_bounds_pc_trace_fp = fopen(pc_trace_path, "a");
  if (g_bounds_pc_trace_fp) {
    fprintf(g_bounds_pc_trace_fp,
            "\n[ROUND_START] round=%u dr=0x%x avail=0x%x buf=0x%x read=0x%x callread=0x%x consume_pcs=%d\n",
            g_bounds_pc_trace_round,
            dt->dr,
            dt->avail_pc,
            dt->buffer_addr,
            dt->read_pc,
            dt->callread_pc,
            g_bounds_num_consume_pcs);
    fflush(g_bounds_pc_trace_fp);
  }
#endif

#if DT_DIAG_HOOK_ENABLE
  bounds_add_diag_hook(uc, dt->avail_pc + 4,
                       hook_bounds_avail_return, "avail_ret");
  bounds_add_diag_hook(uc, dt->avail_pc + 8,
                       hook_bounds_process_call, "process_call");
  if (dt->callread_pc) {
    bounds_add_diag_hook(uc, dt->callread_pc,
                         hook_bounds_callread_before, "callread_before");
    bounds_add_diag_hook(uc, dt->callread_pc + 2,
                         hook_bounds_callread_return, "callread_ret");
  }
  if (dt->read_pc) {
    bounds_add_diag_hook(uc, g_bounds_read_entry_guess_pc,
                         hook_bounds_read_entry_guess, "read_entry_guess");
    bounds_add_diag_hook(uc, dt->read_pc,
                         hook_bounds_read_pc_diag, "read_pc");
  }
#endif

  dt_learning_log("[BOUNDS] START dt=%d dr=0x%x avail=0x%x buf=0x%x read=0x%x callread=0x%x read_entry_guess=0x%x consume_pcs=%d diag_hooks=%d need_upper=%d need_min=%d",
                  target_idx, dt->dr, dt->avail_pc, dt->buffer_addr,
                  dt->read_pc, dt->callread_pc, g_bounds_read_entry_guess_pc,
                  g_bounds_num_consume_pcs, g_bounds_num_diag_hooks,
                  g_bounds_need_upper ? 1 : 0,
                  g_bounds_need_min ? 1 : 0);
  return true;
}

// Finalize once buffer_addr and read_pc/callread_pc are known.
static void try_finalize(uc_engine *uc) {
  if (g_read_pc_done && g_discovery_buffer_addr != 0)
    finalize_discovery(uc);
}

// ====== Channel Discovery: finalize_discovery ======

static void finalize_discovery(uc_engine *uc) {
  // 1. Remove discovery hooks
  if (g_discovery_mem_write_hook) {
    uc_hook_del(uc, g_discovery_mem_write_hook);
    g_discovery_mem_write_hook = 0;
  }
  if (g_discovery_buffer_read_hook) {
    uc_hook_del(uc, g_discovery_buffer_read_hook);
    g_discovery_buffer_read_hook = 0;
  }
  g_in_discovery_mode = false;

  // 2. Create full irq_dt from discovery data
  uint32_t dr = g_discovery_dr;
  DataTracker *dt = &irq_dt_array[irq_dt_array_index];
  memset(dt, 0, sizeof(DataTracker));
  dt->dr = dr;
  dt->irq_pc = g_discovery_irq_pc;
  dt->buffer_addr = g_discovery_buffer_addr;
  dt->read_pc = g_discovery_read_pc;
  dt->callread_pc = g_discovery_callread_pc;
  dt->avail_pc = 0;          // filled by Ghidra daemon later
  dt->buffer_len = 0;        // learned after avail_pc static analysis
  dt->buffer_min_len = 0;    // learned after avail_pc static analysis

  dt->rx_head = 0;
  dt->rx_tail = 0;

  // Signal Ghidra daemon: write JSON path to pending file
  if (g_ghidra_callback) {
    int fd = open("/tmp/ghidra_pending", O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd >= 0) {
      write(fd, g_json_file_path, strlen(g_json_file_path));
      close(fd);
      dt_learning_log("[GHIDRA_PENDING] path=%s reason=irq_dt dr=0x%x",
                      g_json_file_path, dr);
    }
  }

  dt_learning_log("[DISCOVERY] IRQ_DT_PENDING dr=0x%x irq_pc=0x%x buf=0x%x read_pc=0x%x callread_pc=0x%x",
                  dt->dr, dt->irq_pc, dt->buffer_addr,
                  dt->read_pc, dt->callread_pc);

  // Update hash table (replace placeholder)
  int ret = 0;
  khint_t k = kh_put(dr_dt, hash_table, dr, &ret);
  if (ret != -1) {
    kh_value(hash_table, k) = dt;
  }
  irq_dt_array_index++;

  // 3. Write updated JSON
  write_full_json();

  // Clean up pending reference to this DR
  for (int i = 0; i < pending_dt_array_index; i++) {
    if (pending_dt_array[i].dr == dr) {
      memset(&pending_dt_array[i], 0, sizeof(DataTracker));
      break;
    }
  }

  g_discovery_occurred = true;

  dt_learning_log("[DISCOVERY] COMPLETE_PENDING dr=0x%x irq_pc=0x%x buf=0x%x read_pc=0x%x callread_pc=0x%x",
                  dr, g_discovery_irq_pc, g_discovery_buffer_addr,
                  g_discovery_read_pc, g_discovery_callread_pc);

  do_exit(uc, UC_ERR_OK);
}

bool fifo_get_fuzz(uc_engine *uc, DataTracker *dt, uint8_t *buf,
                   uint32_t size) {
  if (dt->fifo_head == dt->fifo_tail) {
    return true;
  }
  int available = dt->fifo_head - dt->fifo_tail;
  int copy_size = (available < (int)size) ? available : (int)size;
  memcpy(buf, &dt->fifo[dt->fifo_tail], copy_size);
  dt->fifo_tail += copy_size;
  return false;
}

int stop_for_firmware_read_datareg() {
  stop_count = 0;
  return stop_count;
}
