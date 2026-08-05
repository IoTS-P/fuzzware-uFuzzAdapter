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
#include <ctype.h>
#include <stddef.h>

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
// Hardcode a Cortex-M exception/vector index here to trace its runtime IRQ PC.
// External IRQn values should be converted with: vector_index = IRQn + 16.
#define DEBUG_TARGET_IRQ_NUM 0

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

#define DISCOVERY_READ_TOKEN_MAX 32
#define MAX_DISCOVERY_CANDIDATES 64
#define DISCOVERY_ADDR_MERGE_GAP 4
#define DISCOVERY_TOKEN_MAX_AGE 4

typedef struct {
  uint32_t value;
  uint32_t read_pc;
  uint32_t callread_pc;
  uint32_t ipsr;
  uint32_t order;
  bool matched;
} DiscoveryReadToken;

typedef struct {
  uint32_t start;
  uint32_t end;
  uint32_t source_read_pc;
  uint32_t source_callread_pc;
  uint32_t source_ipsr;
  uint32_t first_order;
  uint32_t last_order;
  uint32_t write_count;
  bool seen_irq_read;
  bool seen_main_read;
  uint32_t main_read_pc;
  uint32_t main_callread_pc;
} DiscoveryCandidate;

// Channel discovery globals
DataTracker *pending_dt_array = NULL;
short pending_dt_array_index = 0;

IrqBridge *irq_bridge_array = NULL;
short irq_bridge_array_index = 0;
IrqBridge *irq_bridge_candidate_array = NULL;
short irq_bridge_candidate_array_index = 0;

uint32_t g_all_dr_addrs[MAX_DR_ADDRS] = {0};
int g_num_dr_addrs = 0;

bool g_in_discovery_mode = false;
uint32_t g_discovery_dr = 0;
uint32_t g_discovery_taint = 0;
uint32_t g_discovery_irq_pc = 0;
uint32_t g_discovery_irq_ipsr = 0;
int g_discovery_cross_irq_skip_count = 0;
int g_discovery_irq_read_skip_count = 0;
uint32_t g_discovery_addr_list[MAX_DISCOVERY_ADDRS] = {0};
int g_discovery_addr_count = 0;
uint32_t g_discovery_buffer_addr = 0;
uc_hook g_discovery_mem_write_hook = 0;
bool g_discovery_occurred = false;
char g_json_file_path[512] = {0};

// Phase 0: buffer-addr discovery (taint tracking, no refill)
// After buffer_addr is found, capture read_pc/callread_pc on the first read.
uint32_t g_discovery_read_pc = 0;
uint32_t g_discovery_callread_pc = 0;
uc_hook g_discovery_buffer_read_hook = 0;
bool g_read_pc_done = false;
uc_hook g_discovery_candidate_read_hook = 0;
static bool g_dt_callstack_early_requested = false;
static bool g_dt_callstack_early_active = false;
static DiscoveryReadToken g_discovery_read_tokens[DISCOVERY_READ_TOKEN_MAX] = {0};
static int g_num_discovery_read_tokens = 0;
static DiscoveryCandidate g_discovery_candidates[MAX_DISCOVERY_CANDIDATES] = {0};
static int g_num_discovery_candidates = 0;
static uint32_t g_discovery_order = 0;


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
#define MAX_INDIRECT_CALL_SITES 4096
#define MAX_PSEUDO_CHANNELS 1024
#define MAX_MAIN_DT_FAILURES 1024
#define MAX_ACTIVE_PSEUDO_DRS 64
#define MAX_FUNCTION_ENTRIES 8192
#define DT_CALLSTACK_MAX 128
#define PSEUDO_MAX_RETRY 5
#define MAIN_DT_MAX_RETRY 5
#define PSEUDO_DIRTY_BYTE 0xBB
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
  uint32_t src_pc;
  uint32_t null_count;
  bool null_reported;
} IndirectCallSite;
typedef struct {
  uint32_t callread_pc;
  uint32_t dr;
  uint32_t read_pc;
  uint32_t irq_pc;
  uint32_t buffer_addr;
  uint32_t escape_block;
  uint32_t retry_count;
} PseudoChannel;

typedef struct {
  uint32_t dr;
  uint32_t read_pc;
  uint32_t callread_pc;
  uint32_t retry_count;
} MainDtFailure;
typedef struct {
  uint32_t func_entry;
  uint32_t return_pc;
  uint32_t callsite_pc;
  uint32_t ipsr;
  uint32_t sp;
} DtCallFrame;
static IndirectCallSite g_indirect_sites[MAX_INDIRECT_CALL_SITES] = {0};
static int g_num_indirect_sites = 0;
static bool g_indirect_enabled = true;
static char g_indirect_map_path[512] = {0};
static char g_json_blacklist_raw[8192] = "[]";
static char g_json_pseudo_channels_raw[8192] = "[]";
static char g_json_main_dt_failures_raw[8192] = "[]";
static PseudoChannel g_pseudo_channels[MAX_PSEUDO_CHANNELS] = {0};
static int g_num_pseudo_channels = 0;
static MainDtFailure g_main_dt_failures[MAX_MAIN_DT_FAILURES] = {0};
static int g_num_main_dt_failures = 0;
static uint32_t g_function_entries[MAX_FUNCTION_ENTRIES] = {0};
static int g_num_function_entries = 0;
static DtCallFrame g_dt_callstack[DT_CALLSTACK_MAX] = {0};
static int g_dt_callstack_depth = 0;
static uint32_t g_dt_prev_pc = 0;
static uint32_t g_dt_prev_ipsr = 0;
static int g_dt_callstack_overflow_count = 0;
static bool g_pseudo_active = false;
static uint32_t g_pseudo_callread_pc = 0;
static uint32_t g_pseudo_dr = 0;
static uint32_t g_pseudo_active_drs[MAX_ACTIVE_PSEUDO_DRS] = {0};
static int g_pseudo_active_dr_count = 0;
static uint32_t g_pseudo_escape_block = 0;
static uint32_t g_pseudo_prev_block = 0;
static int g_pseudo_dr_read_diag_count = 0;
static int g_pseudo_escape_skip_irq_log_count = 0;
static uc_hook g_pseudo_block_hook = 0;
typedef struct {
  uint32_t pc;
  uc_cb_hookcode_t cb;
  const char *name;
} BoundsDiagDispatchEntry;
static BoundsDiagDispatchEntry g_bounds_diag_entries[BOUNDS_DIAG_HOOK_MAX] = {0};
static int g_bounds_num_diag_hooks = 0;
static int g_irq_bridge_validation_idx = -1;
static uint32_t g_irq_bridge_validation_budget = 0;
static bool g_irq_bridge_validation_active = false;
static bool g_irq_bridge_seen_avail = false;
static bool g_irq_bridge_seen_irq = false;
static bool g_irq_bridge_seen_cmp = false;
static bool g_irq_bridge_seen_main_read = false;
typedef struct {
  bool armed;
  bool waiting_read;
  uint32_t wait_budget;
  uint64_t pend_log_count;
  uint64_t rearm_log_count;
} IrqBridgeRuntimeState;
static IrqBridgeRuntimeState g_irq_bridge_rt[MAX_IRQ_BRIDGES] = {0};
#define IRQ_BRIDGE_VALIDATION_BUDGET 100000u
#define IRQ_BRIDGE_REARM_BUDGET 100000u
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
static void hook_pseudo_escape_block(uc_engine *uc, uint64_t address,
    uint32_t size, void *user_data);
static void dispatch_indirect_call(uc_engine *uc, uint32_t pc);
static void dispatch_pseudo_callread(uc_engine *uc, uint32_t pc);
static void dt_callstack_on_code(uc_engine *uc, uint32_t pc);
static void dt_callstack_reset(void);
static bool discovery_multi_candidate_enabled(void);
static bool discovery_seed_enabled(void);
static uint32_t resolve_callread_pc_for_read(uc_engine *uc, uint32_t read_pc,
    uint32_t ipsr, const char *reason);
static bool dispatch_complete_dt_avail_hook(uc_engine *uc, uint32_t pc,
    uint64_t address, uint32_t size);
static int write_full_json(void);
static void dispatch_irq_bridge_hook(uc_engine *uc, uint32_t pc);
static void dispatch_irq_bridge_validation(uc_engine *uc, uint32_t pc);
static bool start_irq_bridge_validation_if_needed(uc_engine *uc);
static void bounds_prepare_retry_on_exit(uc_engine *uc, const char *reason);
static void bounds_finish_round(uc_engine *uc, const char *reason);
static DataTracker *bounds_find_dt(void);
static bool start_bounds_learning_if_needed(uc_engine *uc);
uc_err main_proc_avail_hook_handler(uc_engine *uc, uint64_t pc, uint32_t size,
                                    void *user_data);
uc_err irq_avail_hook_handler(uc_engine *uc, uint64_t pc, uint32_t size,
                              void *user_data);

#ifndef DT_LEARNING_LOG_ENABLE
#define DT_LEARNING_LOG_ENABLE 1
#endif

static void dt_learning_log(const char *fmt, ...) {
#if DT_LEARNING_LOG_ENABLE
  FILE *fp = fopen(DT_LEARNING_LOG_PATH, "a");
  if (!fp) return;

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

#ifndef DT_DELIVERY_LOG_ENABLE
#define DT_DELIVERY_LOG_ENABLE 0
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

static int compare_indirect_site(const void *a, const void *b) {
  const IndirectCallSite *ia = (const IndirectCallSite *)a;
  const IndirectCallSite *ib = (const IndirectCallSite *)b;
  if (ia->src_pc < ib->src_pc) return -1;
  if (ia->src_pc > ib->src_pc) return 1;
  return 0;
}

static int compare_u32_value(const void *a, const void *b) {
  uint32_t va = *(const uint32_t *)a;
  uint32_t vb = *(const uint32_t *)b;
  if (va < vb) return -1;
  if (va > vb) return 1;
  return 0;
}

static int find_indirect_site_index(uint32_t pc) {
  pc &= ~1u;
  int lo = 0;
  int hi = g_num_indirect_sites - 1;
  while (lo <= hi) {
    int mid = lo + (hi - lo) / 2;
    uint32_t mid_pc = g_indirect_sites[mid].src_pc;
    if (pc == mid_pc) {
      return mid;
    }
    if (pc < mid_pc) {
      hi = mid - 1;
    } else {
      lo = mid + 1;
    }
  }
  return -1;
}

static bool is_function_entry(uint32_t pc) {
  pc &= ~1u;
  int lo = 0;
  int hi = g_num_function_entries - 1;
  while (lo <= hi) {
    int mid = lo + (hi - lo) / 2;
    uint32_t mid_pc = g_function_entries[mid];
    if (pc == mid_pc) return true;
    if (pc < mid_pc) {
      hi = mid - 1;
    } else {
      lo = mid + 1;
    }
  }
  return false;
}

static bool code_addr_in_text(uint32_t addr) {
  uint64_t pc = (uint64_t)(addr & ~1u);
  return pc >= g_code_hook_begin && pc <= g_code_hook_end;
}

static uint32_t find_function_entry_for_pc(uint32_t pc) {
  pc &= ~1u;
  if (!code_addr_in_text(pc) || g_num_function_entries <= 0) {
    return 0;
  }

  int lo = 0;
  int hi = g_num_function_entries - 1;
  uint32_t best = 0;
  while (lo <= hi) {
    int mid = lo + (hi - lo) / 2;
    uint32_t mid_pc = g_function_entries[mid];
    if (mid_pc <= pc) {
      best = mid_pc;
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }

  return code_addr_in_text(best) ? best : 0;
}

static bool dt_callstack_enabled(void) {
  return g_num_function_entries > 0 &&
         (g_dt_callstack_early_active ||
          g_in_discovery_mode ||
          g_discovery_buffer_read_hook != 0 ||
          g_discovery_candidate_read_hook != 0);
}

static bool thumb_pc_is_link_call(uc_engine *uc, uint32_t pc,
                                  const char **kind) {
  pc &= ~1u;
  if (!code_addr_in_text(pc)) {
    return false;
  }

  uint16_t h1 = 0;
  if (uc_mem_read(uc, pc, &h1, sizeof(h1)) != UC_ERR_OK) {
    return false;
  }

  if ((h1 & 0xff87u) == 0x4780u) {
    if (kind) *kind = "BLX_REG";
    return true;
  }

  uint16_t h2 = 0;
  if (!code_addr_in_text(pc + 2) ||
      uc_mem_read(uc, pc + 2, &h2, sizeof(h2)) != UC_ERR_OK) {
    return false;
  }

  if ((h1 & 0xf800u) == 0xf000u && (h2 & 0xc000u) == 0xc000u) {
    if (kind) *kind = (h2 & 0x1000u) ? "BL" : "BLX_IMM";
    return true;
  }

  return false;
}

static uint32_t return_addr_to_callsite(uc_engine *uc, uint32_t lr) {
  uint32_t ret = lr & ~1u;
  const char *kind = NULL;

  if (ret >= 2 && thumb_pc_is_link_call(uc, ret - 2, &kind)) {
    return ret - 2;
  }
  if (ret >= 4 && thumb_pc_is_link_call(uc, ret - 4, &kind)) {
    return ret - 4;
  }

  uint16_t h = 0;
  if (ret >= 4 && code_addr_in_text(ret - 4) &&
      uc_mem_read(uc, ret - 4, &h, sizeof(h)) == UC_ERR_OK &&
      get_instruction_size(h, true) == 4) {
    return ret - 4;
  }
  if (ret >= 2 && code_addr_in_text(ret - 2)) {
    return ret - 2;
  }

  return 0;
}

static void dt_callstack_reset(void) {
  memset(g_dt_callstack, 0, sizeof(g_dt_callstack));
  g_dt_callstack_depth = 0;
  g_dt_prev_pc = 0;
  g_dt_prev_ipsr = 0;
}

static void dt_callstack_set_early_active(bool active, const char *reason) {
  if (g_dt_callstack_early_active == active) {
    return;
  }

  g_dt_callstack_early_active = active;
  dt_callstack_reset();

  dt_learning_log("[CALLSTACK] EARLY_%s reason=%s drs=%d funcs=%d",
                  active ? "ON" : "OFF",
                  reason ? reason : "unknown",
                  g_num_dr_addrs,
                  g_num_function_entries);
}

static void dt_callstack_pop_returns(uint32_t pc, uint32_t ipsr) {
  pc &= ~1u;
  while (g_dt_callstack_depth > 0) {
    DtCallFrame *top = &g_dt_callstack[g_dt_callstack_depth - 1];
    if (top->return_pc != pc || top->ipsr != ipsr) {
      break;
    }
    memset(top, 0, sizeof(*top));
    g_dt_callstack_depth--;
  }
}

static void dt_callstack_push(uint32_t func_entry, uint32_t return_pc,
                              uint32_t callsite_pc, uint32_t ipsr,
                              uint32_t sp) {
  func_entry &= ~1u;
  return_pc &= ~1u;
  callsite_pc &= ~1u;

  if (func_entry == 0 || return_pc == 0 || callsite_pc == 0) {
    return;
  }

  if (g_dt_callstack_depth > 0) {
    DtCallFrame *top = &g_dt_callstack[g_dt_callstack_depth - 1];
    if (top->func_entry == func_entry && top->return_pc == return_pc &&
        top->callsite_pc == callsite_pc && top->ipsr == ipsr) {
      top->sp = sp;
      return;
    }
  }

  if (g_dt_callstack_depth >= DT_CALLSTACK_MAX) {
    memmove(&g_dt_callstack[0], &g_dt_callstack[1],
            (DT_CALLSTACK_MAX - 1) * sizeof(g_dt_callstack[0]));
    g_dt_callstack_depth = DT_CALLSTACK_MAX - 1;
    if (g_dt_callstack_overflow_count < 16) {
      dt_learning_log("[CALLSTACK] OVERFLOW drop_oldest max=%d", DT_CALLSTACK_MAX);
      g_dt_callstack_overflow_count++;
    }
  }

  DtCallFrame *frame = &g_dt_callstack[g_dt_callstack_depth++];
  frame->func_entry = func_entry;
  frame->return_pc = return_pc;
  frame->callsite_pc = callsite_pc;
  frame->ipsr = ipsr;
  frame->sp = sp;
}

static uint32_t dt_callstack_find_callsite(uint32_t func_entry, uint32_t ipsr) {
  func_entry &= ~1u;
  for (int i = g_dt_callstack_depth - 1; i >= 0; i--) {
    DtCallFrame *frame = &g_dt_callstack[i];
    if (frame->func_entry == func_entry && frame->ipsr == ipsr &&
        frame->callsite_pc != 0) {
      return frame->callsite_pc;
    }
  }
  return 0;
}

static void dt_callstack_on_code(uc_engine *uc, uint32_t pc) {
  if (!dt_callstack_enabled()) {
    g_dt_prev_pc = 0;
    g_dt_prev_ipsr = 0;
    return;
  }

  pc &= ~1u;
  uint32_t ipsr = 0;
  uc_reg_read(uc, UC_ARM_REG_IPSR, &ipsr);

  dt_callstack_pop_returns(pc, ipsr);

  if (is_function_entry(pc)) {
    uint32_t lr = 0;
    uint32_t sp = 0;
    uc_reg_read(uc, UC_ARM_REG_LR, &lr);
    uc_reg_read(uc, UC_ARM_REG_SP, &sp);

    uint32_t return_pc = lr & ~1u;
    if (code_addr_in_text(return_pc)) {
      uint32_t callsite_pc = 0;
      const char *kind = NULL;
      if (g_dt_prev_pc != 0 && g_dt_prev_ipsr == ipsr &&
          thumb_pc_is_link_call(uc, g_dt_prev_pc, &kind)) {
        callsite_pc = g_dt_prev_pc & ~1u;
      } else {
        callsite_pc = return_addr_to_callsite(uc, lr);
      }
      dt_callstack_push(pc, return_pc, callsite_pc, ipsr, sp);
    }
  }

  g_dt_prev_pc = pc;
  g_dt_prev_ipsr = ipsr;
}

static uint32_t resolve_callread_pc_for_read(uc_engine *uc, uint32_t read_pc,
                                             uint32_t ipsr,
                                             const char *reason) {
  read_pc &= ~1u;
  uint32_t read_func = find_function_entry_for_pc(read_pc);
  if (read_func != 0) {
    uint32_t callread_pc = dt_callstack_find_callsite(read_func, ipsr);
    if (callread_pc != 0) {
      dt_learning_log("[CALLREAD] RESOLVE reason=%s read_pc=0x%x read_func=0x%x callread=0x%x ipsr=0x%x depth=%d",
                      reason ? reason : "unknown", read_pc, read_func,
                      callread_pc, ipsr, g_dt_callstack_depth);
      return callread_pc;
    }
  }

  uint32_t lr = 0;
  uc_reg_read(uc, UC_ARM_REG_LR, &lr);
  uint32_t fallback = return_addr_to_callsite(uc, lr);
  dt_learning_log("[CALLREAD] FALLBACK reason=%s read_pc=0x%x read_func=0x%x raw_lr=0x%x callread=0x%x ipsr=0x%x depth=%d",
                  reason ? reason : "unknown", read_pc, read_func, lr,
                  fallback, ipsr, g_dt_callstack_depth);
  return fallback;
}

static int find_pseudo_channel_index(uint32_t pc) {
  pc &= ~1u;
  for (int i = 0; i < g_num_pseudo_channels; i++) {
    if (g_pseudo_channels[i].callread_pc == pc) {
      return i;
    }
  }
  return -1;
}

static PseudoChannel *find_pseudo_buffer_hint(uint32_t dr, uint32_t irq_pc) {
  irq_pc &= ~1u;
  for (int i = 0; i < g_num_pseudo_channels; i++) {
    PseudoChannel *ch = &g_pseudo_channels[i];
    if (ch->dr == dr && ch->irq_pc == irq_pc && ch->buffer_addr != 0) {
      return ch;
    }
  }
  return NULL;
}

static bool is_known_pseudo_callread(uint32_t dr, uint32_t observed_callread_pc,
                                     uint32_t *matched_callread,
                                     uint32_t *retry_count) {
  uint32_t observed = observed_callread_pc & ~1u;

  for (int i = 0; i < g_num_pseudo_channels; i++) {
    PseudoChannel *ch = &g_pseudo_channels[i];
    if (ch->dr != dr) {
      continue;
    }

    uint32_t pc = ch->callread_pc & ~1u;
    if (observed == pc || observed == pc + 2 || observed == pc + 4) {
      if (matched_callread) {
        *matched_callread = pc;
      }
      if (retry_count) {
        *retry_count = ch->retry_count;
      }
      return true;
    }
  }

  return false;
}

static bool is_known_main_dt_failure(uint32_t dr, uint32_t read_pc,
                                     uint32_t observed_callread_pc,
                                     uint32_t *matched_callread,
                                     uint32_t *retry_count) {
  uint32_t read_addr = read_pc & ~1u;
  uint32_t observed = observed_callread_pc & ~1u;

  for (int i = 0; i < g_num_main_dt_failures; i++) {
    MainDtFailure *failure = &g_main_dt_failures[i];
    if (failure->dr != dr || ((failure->read_pc & ~1u) != read_addr)) {
      continue;
    }

    uint32_t pc = failure->callread_pc & ~1u;
    if (observed == pc || observed == pc + 2 || observed == pc + 4) {
      if (matched_callread) {
        *matched_callread = pc;
      }
      if (retry_count) {
        *retry_count = failure->retry_count;
      }
      return true;
    }
  }

  return false;
}

static bool pseudo_active_has_dr(uint32_t dr) {
  for (int i = 0; i < g_pseudo_active_dr_count; i++) {
    if (g_pseudo_active_drs[i] == dr) {
      return true;
    }
  }
  return false;
}

static void pseudo_active_add_dr(uint32_t dr) {
  if (pseudo_active_has_dr(dr)) {
    return;
  }
  if (g_pseudo_active_dr_count < MAX_ACTIVE_PSEUDO_DRS) {
    g_pseudo_active_drs[g_pseudo_active_dr_count++] = dr;
  }
}

static void pseudo_clear_state(const char *reason, uint32_t pc) {
  if (g_pseudo_active) {
    dt_learning_log("[PSEUDO] ESCAPE reason=%s pc=0x%x callread=0x%x dr=0x%x escape=0x%x prev=0x%x",
                    reason ? reason : "unknown", pc, g_pseudo_callread_pc,
                    g_pseudo_dr, g_pseudo_escape_block, g_pseudo_prev_block);
  }
  g_pseudo_active = false;
  g_pseudo_callread_pc = 0;
  g_pseudo_dr = 0;
  g_pseudo_active_dr_count = 0;
  g_pseudo_escape_block = 0;
}

static void dispatch_pseudo_callread(uc_engine *uc, uint32_t pc) {
  (void)uc;
  int idx = find_pseudo_channel_index(pc);
  if (idx < 0) {
    return;
  }

  PseudoChannel *ch = &g_pseudo_channels[idx];
  g_pseudo_active = true;
  g_pseudo_callread_pc = ch->callread_pc;
  g_pseudo_dr = ch->dr;
  g_pseudo_escape_block = ch->escape_block;
  g_pseudo_active_dr_count = 0;
  for (int i = 0; i < g_num_pseudo_channels; i++) {
    PseudoChannel *cur = &g_pseudo_channels[i];
    if (cur->callread_pc != ch->callread_pc) {
      continue;
    }
    pseudo_active_add_dr(cur->dr);
    if (g_pseudo_escape_block == 0 && cur->escape_block != 0) {
      g_pseudo_escape_block = cur->escape_block;
    }
  }
  dt_learning_log("[PSEUDO] HIT callread=0x%x dr=0x%x read=0x%x escape=0x%x prev=0x%x active_drs=%d",
                  ch->callread_pc, ch->dr, ch->read_pc,
                  ch->escape_block, g_pseudo_prev_block,
                  g_pseudo_active_dr_count);
}

static void hook_pseudo_escape_block(uc_engine *uc, uint64_t address,
    uint32_t size, void *user_data) {
  (void)size; (void)user_data;
  uint32_t pc = (uint32_t)address & ~1u;
  uint32_t ipsr = 0;
  uc_reg_read(uc, UC_ARM_REG_IPSR, &ipsr);

  if (g_pseudo_active && g_pseudo_escape_block != 0 &&
      ipsr == 0 && is_function_entry(pc) && g_pseudo_prev_block != 0 &&
      g_pseudo_prev_block != g_pseudo_escape_block) {
    pseudo_clear_state("function_entry", pc);
  }

  if (g_pseudo_active && g_pseudo_escape_block != 0 &&
      ipsr != 0 && is_function_entry(pc) &&
      g_pseudo_escape_skip_irq_log_count < 64) {
    dt_learning_log("[PSEUDO] ESCAPE_SKIP_IRQ pc=0x%x ipsr=0x%x callread=0x%x dr=0x%x escape=0x%x prev=0x%x",
                    pc, ipsr, g_pseudo_callread_pc, g_pseudo_dr,
                    g_pseudo_escape_block, g_pseudo_prev_block);
    g_pseudo_escape_skip_irq_log_count++;
  }

  g_pseudo_prev_block = pc;
}

static bool pseudo_get_dirty_input(const char *model, uint64_t addr,
                                   uint8_t *buf, uint32_t size) {
  uint32_t dr = (uint32_t)addr;
  if (!g_pseudo_active || !pseudo_active_has_dr(dr) || !buf || size == 0) {
    return false;
  }

  memset(buf, PSEUDO_DIRTY_BYTE, size);
  dt_learning_log("[PSEUDO] DIRTY model=%s callread=0x%x dr=0x%x addr=0x%llx dirty_len=%u",
                  model ? model : "unknown", g_pseudo_callread_pc,
                  dr, (unsigned long long)addr, size);
  return true;
}

static void remove_indirect_site_at(int idx) {
  if (idx < 0 || idx >= g_num_indirect_sites) {
    return;
  }
  if (idx < g_num_indirect_sites - 1) {
    memmove(&g_indirect_sites[idx],
            &g_indirect_sites[idx + 1],
            (g_num_indirect_sites - idx - 1) * sizeof(g_indirect_sites[0]));
  }
  g_num_indirect_sites--;
}

static bool read_arm_reg_by_index(uc_engine *uc, int reg_idx, uint32_t *value) {
  int reg = 0;
  switch (reg_idx) {
    case 0: reg = UC_ARM_REG_R0; break;
    case 1: reg = UC_ARM_REG_R1; break;
    case 2: reg = UC_ARM_REG_R2; break;
    case 3: reg = UC_ARM_REG_R3; break;
    case 4: reg = UC_ARM_REG_R4; break;
    case 5: reg = UC_ARM_REG_R5; break;
    case 6: reg = UC_ARM_REG_R6; break;
    case 7: reg = UC_ARM_REG_R7; break;
    case 8: reg = UC_ARM_REG_R8; break;
    case 9: reg = UC_ARM_REG_R9; break;
    case 10: reg = UC_ARM_REG_R10; break;
    case 11: reg = UC_ARM_REG_R11; break;
    case 12: reg = UC_ARM_REG_R12; break;
    case 13: reg = UC_ARM_REG_SP; break;
    case 14: reg = UC_ARM_REG_LR; break;
    case 15: reg = UC_ARM_REG_PC; break;
    default: return false;
  }
  return uc_reg_read(uc, reg, value) == UC_ERR_OK;
}

static bool decode_thumb_bx_blx_target(uc_engine *uc, uint32_t pc,
                                       uint32_t *target, const char **kind) {
  uint16_t insn = 0;
  if (uc_mem_read(uc, pc, &insn, sizeof(insn)) != UC_ERR_OK) {
    return false;
  }

  bool is_bx = ((insn & 0xff87u) == 0x4700u);
  bool is_blx = ((insn & 0xff87u) == 0x4780u);
  if (!is_bx && !is_blx) {
    return false;
  }

  int rm = (insn >> 3) & 0xf;
  uint32_t raw_target = 0;
  if (!read_arm_reg_by_index(uc, rm, &raw_target)) {
    return false;
  }

  *target = raw_target & ~1u;
  *kind = is_blx ? "BLX" : "BX";
  return true;
}

static bool indirect_target_in_text(uint32_t target) {
  return target >= g_code_hook_begin && target <= g_code_hook_end;
}

static void append_indirect_map_record(uint32_t src, uint32_t target,
                                       const char *kind) {
  if (g_indirect_map_path[0] == 0) {
    return;
  }

  FILE *fp = fopen(g_indirect_map_path, "a");
  if (!fp) {
    dt_learning_log("[INDIRECT] WRITE_FAIL path=%s src=0x%x target=0x%x",
                    g_indirect_map_path, src, target);
    return;
  }

  fprintf(fp,
          "{\"src\":\"0x%x\",\"target\":\"0x%x\",\"kind\":\"%s\",\"pid\":%ld}\n",
          src, target, kind, (long)getpid());
  fclose(fp);
}

static void dispatch_indirect_call(uc_engine *uc, uint32_t pc) {
  if (!g_indirect_enabled || g_num_indirect_sites <= 0) {
    return;
  }

  int idx = find_indirect_site_index(pc);
  if (idx < 0) {
    return;
  }

  IndirectCallSite *site = &g_indirect_sites[idx];
  uint32_t target = 0;
  const char *kind = NULL;
  if (!decode_thumb_bx_blx_target(uc, pc, &target, &kind)) {
    return;
  }

  if (target == 0) {
    if (site->null_count != UINT32_MAX) {
      site->null_count++;
    }
    if (!site->null_reported) {
      site->null_reported = true;
      dt_learning_log("[INDIRECT] NULL_TARGET src=0x%x kind=%s count=%u",
                      pc, kind, site->null_count);
    }
    return;
  }

  if (!indirect_target_in_text(target)) {
    dt_learning_log("[INDIRECT] OUT_OF_TEXT src=0x%x target=0x%x kind=%s",
                    pc, target, kind);
    return;
  }

  append_indirect_map_record(pc, target, kind);
  dt_learning_log("[INDIRECT] RESOLVE src=0x%x target=0x%x kind=%s "
                  "null_count=%u remaining=%d",
                  pc, target, kind, site->null_count,
                  g_num_indirect_sites - 1);
  remove_indirect_site_at(idx);
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

  dt_callstack_on_code(uc, pc);
  dispatch_indirect_call(uc, pc);
  dispatch_pseudo_callread(uc, pc);

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

  dispatch_irq_bridge_validation(uc, pc);
  dispatch_irq_bridge_hook(uc, pc);
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
void hook_discovery_candidate_read(uc_engine *uc, uc_mem_type type,
    uint64_t address, int size, int64_t value, void *user_data);
static void discovery_reset_candidates(void);
static void discovery_note_dr_read(uc_engine *uc, uint32_t dr, uint32_t pc,
    uint32_t ipsr, int size, int64_t value);
static void seed_pending_discovery_fifo(DataTracker *dt, uint32_t dr,
    bool should_log);

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
    if (g_discovery_candidate_read_hook) {
      uc_hook_del(uc, g_discovery_candidate_read_hook);
      g_discovery_candidate_read_hook = 0;
    }
    discovery_reset_candidates();
    g_in_discovery_mode = false;
  }

  dt_callstack_reset();
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
    printf("get_fuzz called do_exit\n");
    do_exit(uc, UC_ERR_OK);
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
    // my_debug_log("do_exit:ran out of fuzz\n");
    // fuzz_cursor = 0;
    // if (size && fuzz_cursor + size <= fuzz_size) {
    //   uint8_t *res = &fuzz[fuzz_cursor];
    //   fuzz_cursor += size;

    //   // We are consuming fuzzing input, reset watchdog
    //   reload_timer(fuzz_consumption_timer_id);

    //   return res;
    // }
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

  if (pseudo_get_dirty_input("default", addr, (uint8_t *)&val, (uint32_t)size)) {
    goto write_val;
  }

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

  if (pseudo_get_dirty_input("bitextract", addr, (uint8_t *)&fuzzer_val,
                             config->byte_size)) {
    goto apply_model;
  }

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
    if (pseudo_get_dirty_input("value_set", addr, &fuzzer_val, 1)) {
      goto apply_value_set;
    }

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

  if (!g_pseudo_block_hook) {
    if (uc_hook_add(uc, &g_pseudo_block_hook, UC_HOOK_BLOCK,
                    hook_pseudo_escape_block, NULL,
                    g_code_hook_begin, g_code_hook_end) != UC_ERR_OK) {
      perror("Could not register pseudo escape block hook\n");
      return UC_ERR_EXCEPTION;
    }
    dt_learning_log("[PSEUDO] BLOCK_HOOK_ADD begin=0x%llx end=0x%llx",
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
  irq_bridge_array = malloc(MAX_IRQ_BRIDGES * sizeof(IrqBridge));
  irq_bridge_candidate_array = malloc(MAX_IRQ_BRIDGES * sizeof(IrqBridge));
  // Check for NULL if allocation fails and handle it appropriately
  if (!main_dt_array || !irq_dt_array || !pending_dt_array ||
      !irq_bridge_array || !irq_bridge_candidate_array) {
    // Handle memory allocation error
    // For example, you could print an error message and exit
    fprintf(stderr, "Failed to allocate memory for data tracker arrays\n");
    exit(EXIT_FAILURE);
  }
  memset(main_dt_array, 0, DATATRACKER_SIZE * sizeof(DataTracker));
  memset(irq_dt_array, 0, DATATRACKER_SIZE * sizeof(DataTracker));
  memset(pending_dt_array, 0, MAX_PENDING_DRS * sizeof(DataTracker));
  memset(irq_bridge_array, 0, MAX_IRQ_BRIDGES * sizeof(IrqBridge));
  memset(irq_bridge_candidate_array, 0, MAX_IRQ_BRIDGES * sizeof(IrqBridge));
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
                                   short consume_count, short irq_num, uint32_t vtor) {

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
  irq_dt_array[irq_dt_array_index].irq_num = irq_num;
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

static bool irq_num_is_valid(short irq_num) {
  return irq_num > 0 && irq_num < NVIC_NUM_SUPPORTED_INTERRUPTS;
}

static bool irq_dt_is_complete_for_delivery(DataTracker *dt) {
  return dt &&
         dt->avail_pc != 0 &&
         dt->buffer_len > 1 &&
         dt->buffer_min_len > 0 &&
         dt->buffer_min_len <= dt->buffer_len &&
         irq_num_is_valid(dt->irq_num);
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
  if (!dt) {
    return UC_ERR_OK;
  }
  bool fill_only = dt->irq_num == 157;

  // IRQ DT stores raw IPSR captured when the DR hook fired.
  if (!irq_num_is_valid(dt->irq_num)) {
    delivery_log("IRQ_SKIP dr=0x%x reason=invalid_irq_num irq_num=%d",
                 dt->dr, dt->irq_num);
    return UC_ERR_OK;
  }

  // ---- FIFO 空则装填 ----
  if (!dt->interrupt_times) {
    if (g_delivery_budget_closed) {
      return UC_ERR_OK;
    }
    if (fill_only && dt->fifo_head != dt->fifo_tail) {
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
    if (fill_only) {
      delivery_log("COMMIT_FILL_ONLY dr=0x%x irq=%d plan=%d LenFI=%d LenR=%u X=%u cursor=%ld fuzz_size=%ld",
                   dt->dr, dt->irq_num, len_si,
                   delivery_LenFI, delivery_LenR, delivery_X,
                   fuzz_cursor, fuzz_size);
      return UC_ERR_OK;
    }
    dt->interrupt_times = len_si;
    delivery_log("COMMIT dr=0x%x plan=%d irq_times=%d LenFI=%d LenR=%u X=%u cursor=%ld fuzz_size=%ld",
                 dt->dr, len_si, dt->interrupt_times,
                 delivery_LenFI, delivery_LenR, delivery_X,
                 fuzz_cursor, fuzz_size);
    return UC_ERR_OK;
  }

  if (fill_only) {
    delivery_log("FILL_ONLY_SKIP_IRQ dr=0x%x irq=%d irq_times=%d",
               dt->dr, dt->irq_num, dt->interrupt_times);
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
  for (int i = 0; i < irq_bridge_array_index; i++) {
    IrqBridge *bridge = &irq_bridge_array[i];
    if (bridge->enabled && bridge->irq_num == irq_num)
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

static bool resolve_irq_pc_from_vtor(uc_engine *uc, uint32_t vtor,
                                     uint32_t ipsr,
                                     uint32_t *out_irq_pc) {
  if (vtor == 0xffffffff) {
    return false;
  }

  uint64_t handler_addr = (uint64_t)vtor + ((uint64_t)ipsr * 4);
  uint32_t handler_val = 0;
  if (uc_mem_read(uc, handler_addr, &handler_val,
                  sizeof(handler_val)) != UC_ERR_OK) {
    return false;
  }

  if (handler_val == 0 || handler_val == 0xffffffff) {
    return false;
  }

  uint32_t handler_pc = handler_val & ~1u;
  if (handler_pc < g_code_hook_begin || handler_pc > g_code_hook_end) {
    return false;
  }

  if (out_irq_pc) {
    *out_irq_pc = handler_pc;
  }
  return true;
}

static bool debug_target_irq_is_enabled(void) {
  if (DEBUG_TARGET_IRQ_NUM <= 0) return false;

  int num_enabled = get_num_enabled();
  for (int i = 1; i <= num_enabled; i++) {
    if (nth_enabled_irq_num(i) == DEBUG_TARGET_IRQ_NUM) {
      return true;
    }
  }
  return false;
}

static void debug_log_target_irq_pc(uc_engine *uc, const char *reason) {
  if (DEBUG_TARGET_IRQ_NUM <= 0) return;

  uint32_t mem_vtor = 0;
  uint32_t handler_pc = 0;
  const char *source = "none";

  uc_mem_read(uc, SYSCTL_VTOR, &mem_vtor, sizeof(mem_vtor));

  if (resolve_irq_pc_from_vtor(uc, mem_vtor, DEBUG_TARGET_IRQ_NUM,
                               &handler_pc)) {
    source = "mem_vtor";
    vtor_num = mem_vtor;
  } else if (resolve_irq_pc_from_vtor(uc, vtor_num, DEBUG_TARGET_IRQ_NUM,
                                      &handler_pc)) {
    source = "cached_vtor";
  } else if (resolve_irq_pc_from_vtor(uc, (uint32_t)g_code_hook_begin,
                                      DEBUG_TARGET_IRQ_NUM, &handler_pc)) {
    source = "code_begin";
  }

  dt_learning_log("[IRQ_TARGET] reason=%s irq=%d enabled=%d irq_pc=0x%x source=%s mem_vtor=0x%x cached_vtor=0x%x code_begin=0x%llx",
                  reason ? reason : "unknown", DEBUG_TARGET_IRQ_NUM,
                  debug_target_irq_is_enabled() ? 1 : 0, handler_pc, source,
                  mem_vtor, vtor_num,
                  (unsigned long long)g_code_hook_begin);
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
    if (pending_dt_array[i].dr != 0) {
      seed_pending_discovery_fifo(&pending_dt_array[i],
                                  pending_dt_array[i].dr, false);
    }
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
int store_dr_list(uint32_t *dr_addrs, int num_drs,
                  const char *json_path, uint32_t vtor) {
  vtor_num = vtor;
  g_num_dr_addrs = (num_drs < MAX_DR_ADDRS) ? num_drs : MAX_DR_ADDRS;
  memcpy(g_all_dr_addrs, dr_addrs, g_num_dr_addrs * sizeof(uint32_t));
  if (json_path && json_path[0]) {
    strncpy(g_json_file_path, json_path, sizeof(g_json_file_path) - 1);
  }

  if (!pending_dt_array) {
    pending_dt_array = calloc(MAX_PENDING_DRS, sizeof(DataTracker));
  }

  g_dt_callstack_early_requested = (g_num_dr_addrs > 0);
  dt_callstack_set_early_active(g_dt_callstack_early_requested,
                                "store_dr_list");

  dt_learning_log("[STORE_DR] drs=%d json=%s vtor=0x%x",
                  g_num_dr_addrs, g_json_file_path, vtor_num);
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
  if (g_discovery_candidate_read_hook) {
    uc_hook_del(uc, g_discovery_candidate_read_hook);
    g_discovery_candidate_read_hook = 0;
  }
  discovery_reset_candidates();
  g_in_discovery_mode = false;
  g_discovery_irq_ipsr = 0;
  g_discovery_cross_irq_skip_count = 0;
  g_discovery_irq_read_skip_count = 0;

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
  irq_bridge_array_index = 0;
  irq_bridge_candidate_array_index = 0;
  memset(main_dt_array, 0, DATATRACKER_SIZE * sizeof(DataTracker));
  memset(irq_dt_array, 0, DATATRACKER_SIZE * sizeof(DataTracker));
  memset(pending_dt_array, 0, MAX_PENDING_DRS * sizeof(DataTracker));
  memset(irq_bridge_array, 0, MAX_IRQ_BRIDGES * sizeof(IrqBridge));
  memset(irq_bridge_candidate_array, 0, MAX_IRQ_BRIDGES * sizeof(IrqBridge));
  memset(g_irq_bridge_rt, 0, sizeof(g_irq_bridge_rt));

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
  g_discovery_irq_ipsr = 0;
  g_discovery_cross_irq_skip_count = 0;
  g_discovery_irq_read_skip_count = 0;
  g_discovery_addr_count = 0;
  g_discovery_buffer_addr = 0;
  g_discovery_mem_write_hook = 0;
  g_discovery_occurred = false;

  // Reset read_pc discovery state
  g_discovery_read_pc = 0;
  g_discovery_callread_pc = 0;
  g_discovery_buffer_read_hook = 0;
  g_discovery_candidate_read_hook = 0;
  g_read_pc_done = false;
  discovery_reset_candidates();

  dt_callstack_reset();
  dt_learning_log("[CALLSTACK] RESET reason=tracker_reset early=%d",
                  g_dt_callstack_early_active ? 1 : 0);

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
  g_pseudo_active = false;
  g_pseudo_callread_pc = 0;
  g_pseudo_dr = 0;
  g_pseudo_active_dr_count = 0;
  g_pseudo_escape_block = 0;
  g_pseudo_prev_block = 0;
  g_pseudo_dr_read_diag_count = 0;
  g_pseudo_escape_skip_irq_log_count = 0;
  memset(g_bounds_consume_pcs, 0, sizeof(g_bounds_consume_pcs));
  g_bounds_num_consume_pcs = 0;
  g_irq_bridge_validation_idx = -1;
  g_irq_bridge_validation_budget = 0;
  g_irq_bridge_validation_active = false;
  g_irq_bridge_seen_avail = false;
  g_irq_bridge_seen_irq = false;
  g_irq_bridge_seen_cmp = false;
  g_irq_bridge_seen_main_read = false;
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

static int count_consume_pcs(const char *json) {
  uint32_t pcs[64] = {0};
  return parse_consume_pcs(json, pcs, 64);
}

static void json_preserve_array_field(const char *json, const char *key,
                                      char *dst, size_t dst_size) {
  if (!json || !key || !dst || dst_size == 0) {
    return;
  }

  char pattern[64];
  snprintf(pattern, sizeof(pattern), "\"%s\"", key);

  const char *p = strstr(json, pattern);
  if (!p) {
    snprintf(dst, dst_size, "[]");
    return;
  }

  const char *start = strchr(p, '[');
  if (!start) {
    snprintf(dst, dst_size, "[]");
    return;
  }

  int depth = 0;
  bool in_string = false;
  bool escaped = false;
  const char *end = start;
  while (*end) {
    char c = *end;
    if (in_string) {
      if (escaped) {
        escaped = false;
      } else if (c == '\\') {
        escaped = true;
      } else if (c == '"') {
        in_string = false;
      }
    } else {
      if (c == '"') {
        in_string = true;
      } else if (c == '[') {
        depth++;
      } else if (c == ']') {
        depth--;
        if (depth == 0) {
          end++;
          break;
        }
      }
    }
    end++;
  }

  if (depth != 0) {
    snprintf(dst, dst_size, "[]");
    return;
  }

  size_t len = (size_t)(end - start);
  if (len >= dst_size) {
    len = dst_size - 1;
  }
  memcpy(dst, start, len);
  dst[len] = 0;
}

static bool dr_has_complete_irq_dt(uint32_t dr) {
  for (int i = 0; i < irq_dt_array_index; i++) {
    DataTracker *dt = &irq_dt_array[i];
    if (dt->dr == dr &&
        dt->buffer_addr != 0 &&
        dt->read_pc != 0 &&
        dt->irq_pc != 0 &&
        irq_num_is_valid(dt->irq_num) &&
        dt->avail_pc != 0 &&
        dt->consume_pcs[0] != 0) {
      return true;
    }
  }
  return false;
}

static void parse_pseudo_channels(const char *json) {
  g_num_pseudo_channels = 0;
  memset(g_pseudo_channels, 0, sizeof(g_pseudo_channels));

  if (!json) {
    return;
  }

  const char *section = strstr(json, "\"pseudo_channels\":");
  if (!section) {
    dt_learning_log("[PSEUDO] LOAD count=0 reason=missing");
    return;
  }

  const char *p = strstr(section, "[");
  if (!p) {
    dt_learning_log("[PSEUDO] LOAD count=0 reason=no_array");
    return;
  }

  p++;
  while (*p && g_num_pseudo_channels < MAX_PSEUDO_CHANNELS) {
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == ',') p++;
    if (*p == ']') break;

    const char *obj_start = strstr(p, "{");
    if (!obj_start) break;
    const char *obj_end = strstr(obj_start, "}");
    if (!obj_end) break;

    uint32_t callread_pc = json_extract_int(obj_start, "callread_pc") & ~1u;
    uint32_t dr = json_extract_int(obj_start, "dr");
    uint32_t read_pc = json_extract_int(obj_start, "read_pc") & ~1u;
    uint32_t irq_pc = json_extract_int(obj_start, "irq_pc") & ~1u;
    uint32_t buffer_addr = json_extract_int(obj_start, "buffer_addr");
    uint32_t escape_block = json_extract_int(obj_start, "escape_block") & ~1u;
    uint32_t retry_count = json_extract_int(obj_start, "retry_count");

    if (callread_pc != 0 && dr != 0) {
      if (dr_has_complete_irq_dt(dr)) {
        dt_learning_log("[PSEUDO] LOAD_SKIP_RESOLVED dr=0x%x callread=0x%x",
                        dr, callread_pc);
      } else {
        PseudoChannel *ch = &g_pseudo_channels[g_num_pseudo_channels++];
        ch->callread_pc = callread_pc;
        ch->dr = dr;
        ch->read_pc = read_pc;
        ch->irq_pc = irq_pc;
        ch->buffer_addr = buffer_addr;
        ch->escape_block = escape_block;
        ch->retry_count = retry_count;
      }
    }

    p = obj_end + 1;
    const char *next_brace = strstr(p, "{");
    const char *next_bracket = strstr(p, "]");
    if (!next_brace || (next_bracket && next_bracket < next_brace)) break;
  }

  dt_learning_log("[PSEUDO] LOAD count=%d", g_num_pseudo_channels);
}


static bool json_extract_bool(const char *json_obj, const char *key,
                              bool default_value) {
  char search[128];
  snprintf(search, sizeof(search), "\"%s\":", key);
  const char *pos = strstr(json_obj, search);
  if (!pos) return default_value;
  pos += strlen(search);
  while (*pos == ' ' || *pos == '\t') pos++;
  if (strncmp(pos, "true", 4) == 0) return true;
  if (strncmp(pos, "false", 5) == 0) return false;
  return json_extract_int(json_obj, key) != 0;
}

static bool irq_bridge_same_key(const IrqBridge *a, const IrqBridge *b) {
  return a && b &&
         a->dr == b->dr &&
         a->main_read_pc == b->main_read_pc &&
         a->main_callread_pc == b->main_callread_pc;
}

static bool irq_bridge_confirmed_exists(const IrqBridge *candidate) {
  for (int i = 0; i < irq_bridge_array_index; i++) {
    if (irq_bridge_same_key(&irq_bridge_array[i], candidate)) {
      return true;
    }
  }
  return false;
}

static bool irq_bridge_candidate_is_sane(const IrqBridge *candidate) {
  if (!candidate) return false;
  if (!candidate->avail_pc || !candidate->irq_pc || !candidate->main_read_pc ||
      !candidate->main_callread_pc || !irq_num_is_valid(candidate->irq_num)) {
    return false;
  }
  if ((candidate->avail_pc & ~1u) == (candidate->main_callread_pc & ~1u) ||
      (candidate->avail_pc & ~1u) == (candidate->main_read_pc & ~1u)) {
    return false;
  }
  return true;
}

static bool irq_bridge_candidate_exists_before(const IrqBridge *candidate,
                                               int limit) {
  for (int i = 0; i < limit && i < irq_bridge_candidate_array_index; i++) {
    if (irq_bridge_same_key(&irq_bridge_candidate_array[i], candidate)) {
      return true;
    }
  }
  return false;
}

static void parse_irq_bridge_array(const char *json, const char *section_key,
                                   IrqBridge *array, short *array_index,
                                   bool confirmed_only) {
  if (!json || !section_key || !array || !array_index) return;

  *array_index = 0;
  const char *section = strstr(json, section_key);
  if (!section) {
    dt_learning_log("[IRQ_BRIDGE] LOAD key=%s count=0 reason=missing",
                    section_key);
    return;
  }

  const char *cur = strstr(section, "[");
  if (!cur) {
    dt_learning_log("[IRQ_BRIDGE] LOAD key=%s count=0 reason=no_array",
                    section_key);
    return;
  }

  cur++;
  while (*cur && *array_index < MAX_IRQ_BRIDGES) {
    while (*cur == ' ' || *cur == '\t' || *cur == '\n' || *cur == '\r' || *cur == ',') cur++;
    if (*cur == ']') break;

    const char *obj_start = strstr(cur, "{");
    if (!obj_start) break;
    const char *obj_end = strstr(obj_start, "}");
    if (!obj_end) break;

    IrqBridge bridge;
    memset(&bridge, 0, sizeof(bridge));
    bridge.dr = json_extract_int(obj_start, "dr");
    bridge.main_callread_pc = json_extract_int(obj_start, "main_callread_pc") & ~1u;
    bridge.main_read_pc = json_extract_int(obj_start, "main_read_pc") & ~1u;
    bridge.irq_pc = json_extract_int(obj_start, "irq_pc") & ~1u;
    bridge.avail_pc = json_extract_int(obj_start, "avail_pc") & ~1u;
    bridge.cmp_pc = json_extract_int(obj_start, "cmp_pc") & ~1u;
    bridge.irq_num = (short)json_extract_int(obj_start, "irq_num");
    bridge.enabled = json_extract_bool(obj_start, "enabled", true);

    if (bridge.dr != 0 && bridge.main_read_pc != 0 &&
        bridge.main_callread_pc != 0 && bridge.irq_pc != 0 &&
        bridge.avail_pc != 0 && irq_num_is_valid(bridge.irq_num) &&
        (!confirmed_only || bridge.enabled)) {
      array[*array_index] = bridge;
      (*array_index)++;
    }

    cur = obj_end + 1;
    const char *next_brace = strstr(cur, "{");
    const char *next_bracket = strstr(cur, "]");
    if (!next_brace || (next_bracket && next_bracket < next_brace)) break;
  }

  dt_learning_log("[IRQ_BRIDGE] LOAD key=%s count=%d", section_key,
                  *array_index);
}

static void irq_bridge_remove_candidate(int idx, const char *reason) {
  if (idx < 0 || idx >= irq_bridge_candidate_array_index) return;
  IrqBridge *bridge = &irq_bridge_candidate_array[idx];
  dt_learning_log("[IRQ_BRIDGE] CANDIDATE_REMOVE reason=%s dr=0x%x irq=%d avail=0x%x cmp=0x%x main_read=0x%x",
                  reason ? reason : "unknown", bridge->dr, bridge->irq_num,
                  bridge->avail_pc, bridge->cmp_pc, bridge->main_read_pc);
  for (int i = idx; i < irq_bridge_candidate_array_index - 1; i++) {
    irq_bridge_candidate_array[i] = irq_bridge_candidate_array[i + 1];
  }
  irq_bridge_candidate_array_index--;
  if (irq_bridge_candidate_array_index >= 0) {
    memset(&irq_bridge_candidate_array[irq_bridge_candidate_array_index], 0,
           sizeof(IrqBridge));
  }
}

static bool irq_bridge_promote_candidate(int idx) {
  if (idx < 0 || idx >= irq_bridge_candidate_array_index) return false;
  if (irq_bridge_array_index >= MAX_IRQ_BRIDGES) return false;

  IrqBridge bridge = irq_bridge_candidate_array[idx];
  bridge.enabled = true;
  if (!irq_bridge_confirmed_exists(&bridge)) {
    irq_bridge_array[irq_bridge_array_index++] = bridge;
    dt_learning_log("[IRQ_BRIDGE] PROMOTE dr=0x%x irq=%d irq_pc=0x%x avail=0x%x cmp=0x%x main_read=0x%x callread=0x%x",
                    bridge.dr, bridge.irq_num, bridge.irq_pc, bridge.avail_pc,
                    bridge.cmp_pc, bridge.main_read_pc,
                    bridge.main_callread_pc);
  }
  irq_bridge_remove_candidate(idx, "confirmed");
  return true;
}

static void irq_bridge_reset_validation(void) {
  g_irq_bridge_validation_idx = -1;
  g_irq_bridge_validation_budget = 0;
  g_irq_bridge_validation_active = false;
  g_irq_bridge_seen_avail = false;
  g_irq_bridge_seen_irq = false;
  g_irq_bridge_seen_cmp = false;
  g_irq_bridge_seen_main_read = false;
}

static bool start_irq_bridge_validation_if_needed(uc_engine *uc) {
  (void)uc;
  if (g_irq_bridge_validation_active) return true;

  bool changed = false;
  for (int i = 0; i < irq_bridge_candidate_array_index; i++) {
    IrqBridge *candidate = &irq_bridge_candidate_array[i];
    if (!irq_bridge_candidate_is_sane(candidate)) {
      irq_bridge_remove_candidate(i, "invalid_candidate");
      changed = true;
      i--;
      continue;
    }
    if (irq_bridge_confirmed_exists(candidate)) {
      irq_bridge_remove_candidate(i, "already_confirmed");
      changed = true;
      i--;
      continue;
    }
    if (irq_bridge_candidate_exists_before(candidate, i)) {
      irq_bridge_remove_candidate(i, "duplicate_candidate");
      changed = true;
      i--;
      continue;
    }
    if (changed) {
      write_full_json();
      g_discovery_occurred = true;
    }
    g_irq_bridge_validation_idx = i;
    // Do not start the validation budget until the firmware actually reaches
    // the bridge wake point. A valid candidate may be loaded in a round that
    // does not execute the main scheduler loop before reload.
    g_irq_bridge_validation_budget = 0;
    g_irq_bridge_validation_active = true;
    g_irq_bridge_seen_avail = false;
    g_irq_bridge_seen_irq = false;
    g_irq_bridge_seen_cmp = false;
    g_irq_bridge_seen_main_read = false;
    dt_learning_log("[IRQ_BRIDGE] WAIT_AVAIL idx=%d dr=0x%x irq=%d irq_pc=0x%x avail=0x%x cmp=0x%x main_read=0x%x",
                    i, candidate->dr, candidate->irq_num, candidate->irq_pc,
                    candidate->avail_pc, candidate->cmp_pc,
                    candidate->main_read_pc);
    return true;
  }
  if (changed) {
    write_full_json();
    g_discovery_occurred = true;
  }
  return false;
}

static void dispatch_irq_bridge_validation(uc_engine *uc, uint32_t pc) {
  if (!g_irq_bridge_validation_active) return;
  if (g_irq_bridge_validation_idx < 0 ||
      g_irq_bridge_validation_idx >= irq_bridge_candidate_array_index) {
    irq_bridge_reset_validation();
    return;
  }

  IrqBridge *bridge = &irq_bridge_candidate_array[g_irq_bridge_validation_idx];
  if (pc == bridge->avail_pc && !g_irq_bridge_seen_avail) {
    g_irq_bridge_seen_avail = true;
    g_irq_bridge_validation_budget = IRQ_BRIDGE_VALIDATION_BUDGET;
    nvic_set_pending(uc, bridge->irq_num, false);
    dt_learning_log("[IRQ_BRIDGE] VALIDATE_PEND dr=0x%x irq=%d pc=0x%x budget=%u",
                    bridge->dr, bridge->irq_num, pc,
                    g_irq_bridge_validation_budget);
  }

  if (!g_irq_bridge_seen_avail) {
    return;
  }

  if (pc == bridge->irq_pc) {
    g_irq_bridge_seen_irq = true;
  }
  if (bridge->cmp_pc != 0 && pc == bridge->cmp_pc) {
    g_irq_bridge_seen_cmp = true;
  }
  if (pc == bridge->main_read_pc || pc == bridge->main_callread_pc) {
    uint32_t ipsr = 0;
    uc_reg_read(uc, UC_ARM_REG_IPSR, &ipsr);
    if (ipsr == 0) {
      g_irq_bridge_seen_main_read = true;
    }
  }

  if (g_irq_bridge_seen_avail && g_irq_bridge_seen_irq &&
      (bridge->cmp_pc == 0 || g_irq_bridge_seen_cmp) &&
      g_irq_bridge_seen_main_read) {
    irq_bridge_promote_candidate(g_irq_bridge_validation_idx);
    irq_bridge_reset_validation();
    write_full_json();
    g_discovery_occurred = true;
    do_exit(uc, UC_ERR_OK);
    return;
  }

  if (g_irq_bridge_validation_budget > 0) {
    g_irq_bridge_validation_budget--;
  }
  if (g_irq_bridge_seen_avail && g_irq_bridge_validation_budget == 0) {
    dt_learning_log("[IRQ_BRIDGE] VALIDATE_FAIL reason=post_avail_budget dr=0x%x irq=%d seen_avail=%d seen_irq=%d seen_cmp=%d seen_main_read=%d",
                    bridge->dr, bridge->irq_num,
                    g_irq_bridge_seen_avail ? 1 : 0,
                    g_irq_bridge_seen_irq ? 1 : 0,
                    g_irq_bridge_seen_cmp ? 1 : 0,
                    g_irq_bridge_seen_main_read ? 1 : 0);
    irq_bridge_remove_candidate(g_irq_bridge_validation_idx, "validation_failed");
    irq_bridge_reset_validation();
    write_full_json();
    g_discovery_occurred = true;
    do_exit(uc, UC_ERR_OK);
  }
}

static void irq_bridge_init_runtime_state(void) {
  memset(g_irq_bridge_rt, 0, sizeof(g_irq_bridge_rt));
  for (int i = 0; i < irq_bridge_array_index && i < MAX_IRQ_BRIDGES; i++) {
    if (!irq_bridge_array[i].enabled) continue;
    g_irq_bridge_rt[i].armed = true;
    g_irq_bridge_rt[i].waiting_read = false;
    g_irq_bridge_rt[i].wait_budget = 0;
  }
}

static bool irq_bridge_should_log_runtime(uint64_t *counter) {
  (*counter)++;
  return *counter <= 16 || ((*counter & 0x3ffu) == 0);
}

static void dispatch_irq_bridge_hook(uc_engine *uc, uint32_t pc) {
  for (int i = 0; i < irq_bridge_array_index && i < MAX_IRQ_BRIDGES; i++) {
    IrqBridge *bridge = &irq_bridge_array[i];
    IrqBridgeRuntimeState *rt = &g_irq_bridge_rt[i];
    if (!bridge->enabled) continue;

    if (rt->waiting_read) {
      if (pc == bridge->main_read_pc || pc == bridge->main_callread_pc) {
        uint32_t ipsr = 0;
        uc_reg_read(uc, UC_ARM_REG_IPSR, &ipsr);
        if (ipsr == 0) {
          rt->armed = true;
          rt->waiting_read = false;
          rt->wait_budget = 0;
          if (irq_bridge_should_log_runtime(&rt->rearm_log_count)) {
            dt_learning_log("[IRQ_BRIDGE] REARM dr=0x%x irq=%d pc=0x%x count=%llu",
                            bridge->dr, bridge->irq_num, pc,
                            (unsigned long long)rt->rearm_log_count);
          }
        }
      } else if (rt->wait_budget > 0) {
        rt->wait_budget--;
        if (rt->wait_budget == 0) {
          rt->armed = true;
          rt->waiting_read = false;
          dt_learning_log("[IRQ_BRIDGE] REARM_TIMEOUT dr=0x%x irq=%d avail=0x%x",
                          bridge->dr, bridge->irq_num, bridge->avail_pc);
        }
      }
    }

    if (bridge->avail_pc != pc || !rt->armed) continue;

    nvic_set_pending(uc, bridge->irq_num, false);
    rt->armed = false;
    rt->waiting_read = true;
    rt->wait_budget = IRQ_BRIDGE_REARM_BUDGET;
    if (irq_bridge_should_log_runtime(&rt->pend_log_count)) {
      dt_learning_log("[IRQ_BRIDGE] PEND dr=0x%x irq=%d avail=0x%x wait_read=0x%x count=%llu",
                      bridge->dr, bridge->irq_num, pc, bridge->main_read_pc,
                      (unsigned long long)rt->pend_log_count);
    }
  }
}

static void parse_main_dt_failures(const char *json) {
  g_num_main_dt_failures = 0;
  memset(g_main_dt_failures, 0, sizeof(g_main_dt_failures));

  if (!json) {
    return;
  }

  const char *section = strstr(json, "\"main_dt_failures\":");
  if (!section) {
    dt_learning_log("[MAIN_DT_FAILURE] LOAD count=0 reason=missing");
    return;
  }

  const char *p = strstr(section, "[");
  if (!p) {
    dt_learning_log("[MAIN_DT_FAILURE] LOAD count=0 reason=no_array");
    return;
  }

  p++;
  while (*p && g_num_main_dt_failures < MAX_MAIN_DT_FAILURES) {
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == ',') p++;
    if (*p == ']') break;

    const char *obj_start = strstr(p, "{");
    if (!obj_start) break;
    const char *obj_end = strstr(obj_start, "}");
    if (!obj_end) break;

    uint32_t dr = json_extract_int(obj_start, "dr");
    uint32_t read_pc = json_extract_int(obj_start, "read_pc") & ~1u;
    uint32_t callread_pc = json_extract_int(obj_start, "callread_pc") & ~1u;
    uint32_t retry_count = json_extract_int(obj_start, "retry_count");

    if (dr != 0 && read_pc != 0 && callread_pc != 0) {
      MainDtFailure *failure = &g_main_dt_failures[g_num_main_dt_failures++];
      failure->dr = dr;
      failure->read_pc = read_pc;
      failure->callread_pc = callread_pc;
      failure->retry_count = retry_count;
    }

    p = obj_end + 1;
    const char *next_brace = strstr(p, "{");
    const char *next_bracket = strstr(p, "]");
    if (!next_brace || (next_bracket && next_bracket < next_brace)) break;
  }

  dt_learning_log("[MAIN_DT_FAILURE] LOAD count=%d", g_num_main_dt_failures);
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

  json_preserve_array_field(buf, "blacklist",
                            g_json_blacklist_raw,
                            sizeof(g_json_blacklist_raw));
  json_preserve_array_field(buf, "pseudo_channels",
                            g_json_pseudo_channels_raw,
                            sizeof(g_json_pseudo_channels_raw));
  json_preserve_array_field(buf, "main_dt_failures",
                            g_json_main_dt_failures_raw,
                            sizeof(g_json_main_dt_failures_raw));

  parse_irq_bridge_array(buf, "\"irq_bridge_set\":",
                         irq_bridge_array, &irq_bridge_array_index, true);
  parse_irq_bridge_array(buf, "\"irq_bridge_candidates\":",
                         irq_bridge_candidate_array,
                         &irq_bridge_candidate_array_index, false);
  irq_bridge_init_runtime_state();

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
        short irq_num        = (short)json_extract_int(obj_start, "irq_num");

        printf("[JSON_RELOAD] irq_dt: dr=0x%x irq_pc=0x%x irq_num=%d buf=0x%x avail=0x%x\n",
               dr, irq_pc, irq_num, buffer_addr, avail_pc);

        fill_data_tracker_irq_dt_array(dr, callread_pc, read_pc, buffer_addr,
                                       irq_pc, avail_pc, rx_head, rx_tail,
                                       buffer_len, buffer_min_len, consume_count,
                                       irq_num, vtor_num);
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

  parse_pseudo_channels(buf);
  parse_main_dt_failures(buf);

  free(buf);

  dt_learning_log("[JSON_RELOAD] irq_dt=%d main_dt=%d",
                  irq_dt_array_index, main_dt_array_index);
}

// Check if a DR address already has a valid learned DT.
static bool dr_has_valid_dt(uint32_t dr) {
  khint_t k = kh_get(dr_dt, hash_table, dr);
  if (k == kh_end(hash_table)) {
    return false;
  }

  DataTracker *dt = kh_value(hash_table, k);
  if (!dt || dt->dr != dr) {
    return false;
  }

  if (dt->read_pc == 0 || dt->callread_pc == 0) {
    return false;
  }

  if (dt->irq_pc == 0) {
    return true;
  }

  if (dt->buffer_addr != 0 && irq_num_is_valid(dt->irq_num)) {
    return true;
  }

  return false;
}

static bool has_unknown_discovery_dr(void) {
  for (int i = 0; i < g_num_dr_addrs; i++) {
    if (!dr_has_valid_dt(g_all_dr_addrs[i])) {
      return true;
    }
  }
  return false;
}


// Rebuild placeholder DTs and monitor hooks for unknown DRs
void rebuild_pending_drs(uc_engine *uc) {
  for (int i = 0; i < g_num_dr_addrs; i++) {
    uint32_t dr = g_all_dr_addrs[i];

    // Skip if already has a known DT (from JSON)
    if (dr_has_valid_dt(dr)) {
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

    // Fill FIFO with a discovery seed when provided; otherwise preserve the
    // old one-byte 0xaa fallback.
    seed_pending_discovery_fifo(dt, dr, true);

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
  if (g_dt_callstack_early_requested) {
    dt_callstack_set_early_active(has_unknown_discovery_dr(),
                                  "after_json_reload");
  }
  debug_log_target_irq_pc(uc, "per_round_reload");

  // 4. Add normal avail hooks for DTs that are already complete. Incomplete
  // irq_dt entries are intentionally skipped here and handled by bounds
  // learning below.
  ufuzz_adapter_add_avail_hook(uc);

  // 5. Validate IRQ->main-read bridge candidates before bounds learning.
  // Bounds can keep an incomplete irq_dt active for many rounds; bridge
  // validation is candidate-scoped and does not mutate main_dt/irq_dt data.
  if (start_irq_bridge_validation_if_needed(uc)) {
    printf("[PER_ROUND] IRQ bridge validation active: candidates=%d confirmed=%d\n",
           irq_bridge_candidate_array_index, irq_bridge_array_index);
    return 0;
  }

  // 6. Prefer post-static-analysis bounds learning for incomplete irq_dt
  // entries. Pending DR discovery remains disabled while bounds is active, but
  // complete DTs keep their normal avail hooks installed.
  if (start_bounds_learning_if_needed(uc)) {
    printf("[PER_ROUND] Bounds learning active: %d main_dt, %d irq_dt, %d pending\n",
           main_dt_array_index, irq_dt_array_index, pending_dt_array_index);
    return 0;
  }

  // 7. Create placeholder DTs for unknown DRs
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
    const char *consume_pcs = dt->consume_pcs[0] ? dt->consume_pcs : "[]";
    int consume_count = count_consume_pcs(consume_pcs);
    fprintf(fp, "    {\"dr\": \"0x%x\", \"callread_pc\": \"0x%x\", "
            "\"read_pc\": \"0x%x\", \"buffer_addr\": \"0x%x\", "
            "\"irq_pc\": \"0x%x\", \"irq_num\": %d, \"avail_pc\": \"0x%x\", "
            "\"rx_head\": %u, \"rx_tail\": %u, "
            "\"buffer_len\": %d, \"buffer_min_len\": %d, "
            "\"consume_count\": %d, "
            "\"consume_pc_set\": %s}%s\n",
            dt->dr, dt->callread_pc, dt->read_pc, dt->buffer_addr,
            dt->irq_pc, dt->irq_num, dt->avail_pc, dt->rx_head, dt->rx_tail,
            dt->buffer_len, dt->buffer_min_len, consume_count,
            consume_pcs,
            (i < irq_dt_array_index - 1) ? "," : "");
  }
  fprintf(fp, "  ],\n");

  // main_dt_set
  fprintf(fp, "  \"main_dt_set\": [\n");
  for (int i = 0; i < main_dt_array_index; i++) {
    DataTracker *dt = &main_dt_array[i];
    const char *consume_pcs = dt->consume_pcs[0] ? dt->consume_pcs : "[]";
    int consume_count = count_consume_pcs(consume_pcs);
    fprintf(fp, "    {\"dr\": \"0x%x\", \"callread_pc\": \"0x%x\", "
            "\"read_pc\": \"0x%x\", \"buffer_addr\": \"0x%x\", "
            "\"irq_pc\": \"0x%x\", \"irq_num\": %d, \"avail_pc\": \"0x%x\", "
            "\"rx_head\": %u, \"rx_tail\": %u, "
            "\"buffer_len\": %d, \"buffer_min_len\": %d, "
            "\"consume_count\": %d, "
            "\"consume_pc_set\": %s}%s\n",
            dt->dr, dt->callread_pc, dt->read_pc, dt->buffer_addr,
            dt->irq_pc, 0, dt->avail_pc, dt->rx_head, dt->rx_tail,
            dt->buffer_len, dt->buffer_min_len, consume_count,
            consume_pcs,
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

  fprintf(fp, "  \"irq_bridge_set\": [\n");
  for (int i = 0; i < irq_bridge_array_index; i++) {
    IrqBridge *bridge = &irq_bridge_array[i];
    fprintf(fp, "    {\"state\": \"confirmed\", \"enabled\": %s, "
            "\"dr\": \"0x%x\", \"main_callread_pc\": \"0x%x\", "
            "\"main_read_pc\": \"0x%x\", \"irq_pc\": \"0x%x\", "
            "\"irq_num\": %d, \"avail_pc\": \"0x%x\", "
            "\"cmp_pc\": \"0x%x\"}%s\n",
            bridge->enabled ? "true" : "false", bridge->dr,
            bridge->main_callread_pc, bridge->main_read_pc, bridge->irq_pc,
            bridge->irq_num, bridge->avail_pc, bridge->cmp_pc,
            (i < irq_bridge_array_index - 1) ? "," : "");
  }
  fprintf(fp, "  ],\n");

  fprintf(fp, "  \"irq_bridge_candidates\": [\n");
  for (int i = 0; i < irq_bridge_candidate_array_index; i++) {
    IrqBridge *bridge = &irq_bridge_candidate_array[i];
    fprintf(fp, "    {\"state\": \"candidate\", \"enabled\": %s, "
            "\"dr\": \"0x%x\", \"main_callread_pc\": \"0x%x\", "
            "\"main_read_pc\": \"0x%x\", \"irq_pc\": \"0x%x\", "
            "\"irq_num\": %d, \"avail_pc\": \"0x%x\", "
            "\"cmp_pc\": \"0x%x\"}%s\n",
            bridge->enabled ? "true" : "false", bridge->dr,
            bridge->main_callread_pc, bridge->main_read_pc, bridge->irq_pc,
            bridge->irq_num, bridge->avail_pc, bridge->cmp_pc,
            (i < irq_bridge_candidate_array_index - 1) ? "," : "");
  }
  fprintf(fp, "  ],\n");

  // Remaining fields (empty, for semu-fuzz compatibility)
  fprintf(fp, "  \"blacklist\": %s,\n", g_json_blacklist_raw);
  fprintf(fp, "  \"pseudo_channels\": %s,\n", g_json_pseudo_channels_raw);
  fprintf(fp, "  \"main_dt_failures\": %s,\n", g_json_main_dt_failures_raw);
  fprintf(fp, "  \"indirect_src_addrs\": [],\n");
  fprintf(fp, "  \"data_regs\": [],\n");
  fprintf(fp, "  \"avail_dt_dict\": {},\n");
  fprintf(fp, "  \"consume_dt_dict\": {},\n");
  fprintf(fp, "  \"global_vars\": []\n");
  fprintf(fp, "}\n");

  fclose(fp);
  dt_learning_log("[JSON_WRITE] irq_dt=%d main_dt=%d bridge=%d candidates=%d path=%s",
                  irq_dt_array_index, main_dt_array_index,
                  irq_bridge_array_index, irq_bridge_candidate_array_index,
                  g_json_file_path);
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

void set_function_entries(uint32_t *entries, int num_entries) {
  g_num_function_entries = 0;
  memset(g_function_entries, 0, sizeof(g_function_entries));

  if (!entries || num_entries <= 0) {
    dt_learning_log("[PSEUDO] FUNC_ENTRIES count=0");
    return;
  }

  if (num_entries > MAX_FUNCTION_ENTRIES) {
    num_entries = MAX_FUNCTION_ENTRIES;
  }

  for (int i = 0; i < num_entries; i++) {
    uint32_t pc = entries[i] & ~1u;
    if (pc == 0) {
      continue;
    }
    g_function_entries[g_num_function_entries++] = pc;
  }

  qsort(g_function_entries, g_num_function_entries,
        sizeof(g_function_entries[0]), compare_u32_value);

  int out = 0;
  for (int i = 0; i < g_num_function_entries; i++) {
    if (out == 0 || g_function_entries[i] != g_function_entries[out - 1]) {
      g_function_entries[out++] = g_function_entries[i];
    }
  }
  g_num_function_entries = out;

  dt_learning_log("[PSEUDO] FUNC_ENTRIES count=%d", g_num_function_entries);
}

void set_indirect_map_path(const char *path) {
  if (!path) {
    g_indirect_map_path[0] = 0;
    return;
  }

  snprintf(g_indirect_map_path, sizeof(g_indirect_map_path), "%s", path);
  dt_learning_log("[INDIRECT] MAP_PATH %s", g_indirect_map_path);
}

void set_indirect_enabled(int enabled) {
  g_indirect_enabled = enabled ? true : false;
  if (!g_indirect_enabled) {
    g_num_indirect_sites = 0;
  }
  dt_learning_log("[INDIRECT] ENABLED %d", g_indirect_enabled ? 1 : 0);
}

void set_indirect_call_sites(uint32_t *sites, int num_sites) {
  g_num_indirect_sites = 0;
  memset(g_indirect_sites, 0, sizeof(g_indirect_sites));

  if (!g_indirect_enabled) {
    dt_learning_log("[INDIRECT] SITES skipped reason=disabled");
    return;
  }

  if (!sites || num_sites <= 0) {
    dt_learning_log("[INDIRECT] SITES empty");
    return;
  }

  if (num_sites > MAX_INDIRECT_CALL_SITES) {
    num_sites = MAX_INDIRECT_CALL_SITES;
  }

  for (int i = 0; i < num_sites; i++) {
    g_indirect_sites[g_num_indirect_sites].src_pc = sites[i] & ~1u;
    g_num_indirect_sites++;
  }

  qsort(g_indirect_sites, g_num_indirect_sites,
        sizeof(g_indirect_sites[0]), compare_indirect_site);
  dt_learning_log("[INDIRECT] SITES count=%d", g_num_indirect_sites);
}

void set_ghidra_callback(void *cb) {
  g_ghidra_callback = cb;
}

static bool discovery_multi_candidate_enabled(void) {
  const char *v = getenv("UFUZZ_DISCOVERY_MULTI_CANDIDATE");
  return v && v[0] == '1';
}

static bool discovery_seed_enabled(void) {
  const char *v = getenv("UFUZZ_DISCOVERY_ENABLE_SEED");
  return v && v[0] == '1';
}

static void discovery_reset_candidates(void) {
  memset(g_discovery_read_tokens, 0, sizeof(g_discovery_read_tokens));
  g_num_discovery_read_tokens = 0;
  memset(g_discovery_candidates, 0, sizeof(g_discovery_candidates));
  g_num_discovery_candidates = 0;
  g_discovery_order = 0;
}

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static size_t parse_hex_seed(const char *text, uint8_t *out, size_t cap) {
  if (!text || !out || cap == 0) return 0;

  size_t len = 0;
  int high = -1;
  for (const char *p = text; *p && len < cap; p++) {
    if (*p == '0' && (p[1] == 'x' || p[1] == 'X') && high < 0) {
      p++;
      continue;
    }
    if (isspace((unsigned char)*p) || *p == ':' || *p == ',' ||
        *p == '_' || *p == '-') {
      continue;
    }

    int n = hex_nibble(*p);
    if (n < 0) {
      dt_learning_log("[DISCOVERY] SEED_PARSE_SKIP char=0x%x", (unsigned)*p);
      continue;
    }

    if (high < 0) {
      high = n;
    } else {
      out[len++] = (uint8_t)((high << 4) | n);
      high = -1;
    }
  }

  if (high >= 0) {
    dt_learning_log("[DISCOVERY] SEED_PARSE_ODD_NIBBLE ignored=0x%x", high);
  }
  return len;
}

static size_t load_discovery_seed_for_dr(uint32_t dr, uint8_t *out,
                                         size_t cap, const char **source) {
  char env_name[64];
  snprintf(env_name, sizeof(env_name), "UFUZZ_DISCOVERY_SEED_%08X", dr);
  const char *text = getenv(env_name);
  if (text && text[0]) {
    size_t len = parse_hex_seed(text, out, cap);
    if (len > 0) {
      if (source) *source = env_name;
      return len;
    }
  }

  text = getenv("UFUZZ_DISCOVERY_SEED");
  if (text && text[0]) {
    size_t len = parse_hex_seed(text, out, cap);
    if (len > 0) {
      if (source) *source = "UFUZZ_DISCOVERY_SEED";
      return len;
    }
  }

  const char *use_fuzz = getenv("UFUZZ_DISCOVERY_USE_FUZZ_SEED");
  if (use_fuzz && use_fuzz[0] == '1' && fuzz && fuzz_size > 0) {
    size_t len = (size_t)fuzz_size;
    if (len > cap) len = cap;
    memcpy(out, fuzz, len);
    if (source) *source = "fuzz";
    return len;
  }

  if (source) *source = "fallback_0xaa";
  return 0;
}

static void seed_pending_discovery_fifo(DataTracker *dt, uint32_t dr,
                                        bool should_log) {
  if (!dt) return;

  const char *source = "fallback_0xaa";
  size_t len = 0;

  if (discovery_multi_candidate_enabled() && discovery_seed_enabled()) {
    len = load_discovery_seed_for_dr(dr, dt->fifo, sizeof(dt->fifo),
                                     &source);
  }

  if (len == 0) {
    dt->fifo[0] = 0xaa;
    len = 1;
    source = "fallback_0xaa";
  }

  dt->fifo_tail = 0;
  dt->fifo_head = (short)len;
  if (should_log) {
    dt_learning_log("[DISCOVERY] SEED_FIFO dr=0x%x source=%s len=%zu first=0x%x",
                    dr, source ? source : "unknown", len, dt->fifo[0]);
  }
}

static void discovery_ensure_candidate_read_hook(uc_engine *uc) {
  if (!discovery_multi_candidate_enabled()) return;
  if (g_discovery_candidate_read_hook != 0) return;

  uc_err err = uc_hook_add(uc, &g_discovery_candidate_read_hook,
                           UC_HOOK_MEM_READ_AFTER,
                           hook_discovery_candidate_read, NULL,
                           0, 0xFFFFFFFF);
  if (err == UC_ERR_OK) {
    dt_learning_log("[DISCOVERY] CAND_READ_HOOK installed");
  } else {
    dt_learning_log("[DISCOVERY] CAND_READ_HOOK_FAIL err=%d", err);
  }
}

static DiscoveryReadToken *discovery_recent_unmatched_token(uint32_t ipsr,
                                                            uint32_t value) {
  uint32_t byte = value & 0xffu;
  int count = g_num_discovery_read_tokens;
  int max = count < DISCOVERY_READ_TOKEN_MAX ? count : DISCOVERY_READ_TOKEN_MAX;

  for (int i = 0; i < max; i++) {
    int idx = (g_num_discovery_read_tokens - 1 - i) %
              DISCOVERY_READ_TOKEN_MAX;
    DiscoveryReadToken *tok = &g_discovery_read_tokens[idx];
    if (tok->matched || tok->ipsr != ipsr || tok->value != byte) {
      continue;
    }
    if (g_discovery_order >= tok->order &&
        g_discovery_order - tok->order > DISCOVERY_TOKEN_MAX_AGE) {
      continue;
    }
    return tok;
  }

  return NULL;
}

static bool discovery_candidate_touches(DiscoveryCandidate *cand,
                                        uint32_t addr, uint32_t size) {
  uint32_t end = addr + (size ? (uint32_t)size - 1u : 0u);
  return !(end + DISCOVERY_ADDR_MERGE_GAP < cand->start ||
           addr > cand->end + DISCOVERY_ADDR_MERGE_GAP);
}

static DiscoveryCandidate *discovery_candidate_for_write(uint32_t addr,
                                                         uint32_t size) {
  for (int i = 0; i < g_num_discovery_candidates; i++) {
    if (discovery_candidate_touches(&g_discovery_candidates[i], addr, size)) {
      return &g_discovery_candidates[i];
    }
  }

  if (g_num_discovery_candidates >= MAX_DISCOVERY_CANDIDATES) {
    dt_learning_log("[DISCOVERY] CAND_DROP addr=0x%x reason=max_candidates", addr);
    return NULL;
  }

  DiscoveryCandidate *cand =
      &g_discovery_candidates[g_num_discovery_candidates++];
  memset(cand, 0, sizeof(*cand));
  cand->start = addr;
  cand->end = addr + (size ? (uint32_t)size - 1u : 0u);
  return cand;
}

static void discovery_note_candidate_write(uc_engine *uc, uint32_t addr,
                                           int size,
                                           DiscoveryReadToken *tok) {
  if (!tok) return;

  uint32_t pc = 0;
  uc_reg_read(uc, UC_ARM_REG_PC, &pc);
  pc &= ~1u;

  uint32_t write_size = size > 0 ? (uint32_t)size : 1u;
  DiscoveryCandidate *cand = discovery_candidate_for_write(addr, write_size);
  if (!cand) return;

  uint32_t end = addr + write_size - 1u;
  if (addr < cand->start) cand->start = addr;
  if (end > cand->end) cand->end = end;

  if (cand->write_count == 0) {
    cand->first_order = tok->order;
  }
  cand->last_order = tok->order;
  cand->source_read_pc = tok->read_pc;
  cand->source_callread_pc = tok->callread_pc;
  cand->source_ipsr = tok->ipsr;
  cand->write_count++;

  if (g_discovery_addr_count < MAX_DISCOVERY_ADDRS) {
    g_discovery_addr_list[g_discovery_addr_count++] = addr;
  }

  ptrdiff_t idx = cand - g_discovery_candidates;
  dt_learning_log("[DISCOVERY] CAND_WRITE idx=%td range=0x%x-0x%x "
                  "addr=0x%x size=%d write_pc=0x%x src_read=0x%x "
                  "src_callread=0x%x writes=%u",
                  idx, cand->start, cand->end, addr, size, pc,
                  cand->source_read_pc, cand->source_callread_pc,
                  cand->write_count);

  discovery_ensure_candidate_read_hook(uc);
}

static void discovery_note_dr_read(uc_engine *uc, uint32_t dr, uint32_t pc,
                                   uint32_t ipsr, int size, int64_t value) {
  (void)dr;
  (void)size;

  uint32_t callread_pc =
      resolve_callread_pc_for_read(uc, pc, ipsr, "discovery_dr_read");

  DiscoveryReadToken *tok =
      &g_discovery_read_tokens[g_num_discovery_read_tokens %
                               DISCOVERY_READ_TOKEN_MAX];
  tok->value = (uint32_t)value & 0xffu;
  tok->read_pc = pc;
  tok->callread_pc = callread_pc;
  tok->ipsr = ipsr;
  tok->order = ++g_discovery_order;
  tok->matched = false;

  g_num_discovery_read_tokens++;

  dt_learning_log("[DISCOVERY] DR_TOKEN dr=0x%x pc=0x%x callread=0x%x "
                  "ipsr=0x%x val=0x%x order=%u",
                  g_discovery_dr, pc, callread_pc, ipsr, tok->value,
                  tok->order);
}

static DiscoveryCandidate *discovery_find_candidate_by_addr(uint32_t addr) {
  for (int i = 0; i < g_num_discovery_candidates; i++) {
    DiscoveryCandidate *cand = &g_discovery_candidates[i];
    if (addr >= cand->start && addr <= cand->end) {
      return cand;
    }
  }
  return NULL;
}

static void discovery_select_candidate(uc_engine *uc,
                                       DiscoveryCandidate *cand,
                                       const char *reason) {
  if (!cand || g_read_pc_done) return;

  g_discovery_buffer_addr = cand->start;
  g_discovery_read_pc = cand->main_read_pc;
  g_discovery_callread_pc = cand->main_callread_pc;
  g_read_pc_done = true;

  if (g_discovery_candidate_read_hook) {
    uc_hook_del(uc, g_discovery_candidate_read_hook);
    g_discovery_candidate_read_hook = 0;
  }

  dt_learning_log("[DISCOVERY] CAND_SELECT reason=%s buf=0x%x "
                  "range=0x%x-0x%x read_pc=0x%x callread=0x%x "
                  "src_callread=0x%x writes=%u irq_reads=%d",
                  reason ? reason : "unknown", cand->start, cand->start,
                  cand->end, cand->main_read_pc, cand->main_callread_pc,
                  cand->source_callread_pc, cand->write_count,
                  cand->seen_irq_read ? 1 : 0);
}

static void signal_ghidra_pending(const char *reason, uint32_t dr) {
  if (!g_ghidra_callback) return;
  int fd = open("/tmp/ghidra_pending", O_CREAT | O_WRONLY | O_TRUNC, 0600);
  if (fd >= 0) {
    write(fd, g_json_file_path, strlen(g_json_file_path));
    close(fd);
    dt_learning_log("[GHIDRA_PENDING] path=%s reason=%s dr=0x%x",
                    g_json_file_path, reason ? reason : "unknown", dr);
  }
}

// ====== Channel Discovery: Callbacks ======

// UC_HOOK_MEM_READ_AFTER callback for pending DRs
void hook_pending_dr_read_after(uc_engine *uc, uc_mem_type type,
    uint64_t address, int size, int64_t value, void *user_data) {

  uint32_t dr = (uint32_t)address;

  uint32_t ipsr = 0;
  uc_reg_read(uc, UC_ARM_REG_IPSR, &ipsr);
  uint32_t pc = 0;
  uc_reg_read(uc, UC_ARM_REG_PC, &pc);
  pc &= ~1u;

  if (g_pseudo_dr_read_diag_count < 512) {
    dt_learning_log("[DISCOVERY] DR_READ_AFTER_DIAG dr=0x%x pc=0x%x ipsr=0x%x size=%d value=0x%llx pseudo_active=%d pseudo_callread=0x%x in_discovery=%d",
                    dr, pc, ipsr, size, (unsigned long long)value,
                    g_pseudo_active ? 1 : 0,
                    g_pseudo_callread_pc,
                    g_in_discovery_mode ? 1 : 0);
    g_pseudo_dr_read_diag_count++;
  }
  if (g_in_discovery_mode) {
    if (discovery_multi_candidate_enabled() && dr == g_discovery_dr) {
      discovery_note_dr_read(uc, dr, pc, ipsr, size, value);
    }
    return;
  }

  if (ipsr != 0) {
    // === IRQ context → interrupt-read type ===
    dt_learning_log("[DISCOVERY] IRQ_DR_READ dr=0x%x ipsr=0x%x pc=0x%x",
                    dr, ipsr, pc);
    debug_log_target_irq_pc(uc, "irq_dr_read");

    g_discovery_dr = dr;
    g_discovery_taint = 0xAA;  // magic token byte, not full word

    uint32_t mem_vtor = 0;
    uint32_t resolved_vtor = 0;
    uint32_t resolved_irq_pc = 0;

    uc_mem_read(uc, SYSCTL_VTOR, &mem_vtor, sizeof(mem_vtor));

    if (resolve_irq_pc_from_vtor(uc, vtor_num, ipsr, &resolved_irq_pc)) {
      resolved_vtor = vtor_num;
    } else if (resolve_irq_pc_from_vtor(uc, mem_vtor, ipsr,
                                        &resolved_irq_pc)) {
      resolved_vtor = mem_vtor;
    } else if (resolve_irq_pc_from_vtor(uc, (uint32_t)g_code_hook_begin, ipsr,
                                        &resolved_irq_pc)) {
      resolved_vtor = (uint32_t)g_code_hook_begin;
    } else {
      dt_learning_log("[DISCOVERY] IRQ_PC_INVALID dr=0x%x ipsr=0x%x pc=0x%x mem_vtor=0x%x cached_vtor=0x%x",
                      dr, ipsr, pc, mem_vtor, vtor_num);
      return;
    }

    vtor_num = resolved_vtor;
    g_discovery_irq_pc = resolved_irq_pc;
    g_discovery_irq_ipsr = ipsr;
    g_discovery_cross_irq_skip_count = 0;
    g_discovery_irq_read_skip_count = 0;

    dt_learning_log("[DISCOVERY] IRQ_PC dr=0x%x irq_pc=0x%x vtor=0x%x ipsr=0x%x",
                    dr, g_discovery_irq_pc, resolved_vtor, ipsr);
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
    discovery_reset_candidates();
    if (discovery_multi_candidate_enabled()) {
      discovery_note_dr_read(uc, dr, pc, ipsr, size, value);
    }

  } else {
    // === Main loop context → firmware-read type (main_read) ===
    dt_learning_log("[DISCOVERY] MAIN_DR_READ dr=0x%x pc=0x%x", dr, pc);

    uint32_t callread_pc =
        resolve_callread_pc_for_read(uc, pc, ipsr, "main_dr_read");

    uint32_t matched_callread = 0;
    uint32_t main_retry_count = 0;
    if (is_known_main_dt_failure(dr, pc, callread_pc, &matched_callread,
                                  &main_retry_count)) {
      if (main_retry_count >= MAIN_DT_MAX_RETRY) {
        dt_learning_log("[DISCOVERY] SKIP_MAIN_DT_FAILURE dr=0x%x read_pc=0x%x callread=0x%x matched=0x%x retry=%u max=%u",
                        dr, pc, callread_pc, matched_callread,
                        main_retry_count, MAIN_DT_MAX_RETRY);
        return;
      }
      dt_learning_log("[DISCOVERY] RETRY_MAIN_DT_FAILURE dr=0x%x read_pc=0x%x callread=0x%x matched=0x%x retry=%u max=%u",
                      dr, pc, callread_pc, matched_callread,
                      main_retry_count, MAIN_DT_MAX_RETRY);
    }

    // Create main_dt with read_pc and callread_pc
    DataTracker *dt = &main_dt_array[main_dt_array_index];
    memset(dt, 0, sizeof(DataTracker));
    dt->dr = dr;
    dt->read_pc = pc;
    dt->callread_pc = callread_pc;
    dt->irq_pc = 0;
    dt->buffer_addr = 0;
    dt->irq_num = 0;
    dt->avail_pc = 0;  // deferred to static analysis

    // Insert into hash table
    int ret = 0;
    khint_t k = kh_put(dr_dt, hash_table, dr, &ret);
    if (ret != -1) {
      kh_value(hash_table, k) = dt;
    }
    main_dt_array_index++;

    dt_learning_log("[DISCOVERY] MAIN_DT dr=0x%x read_pc=0x%x callread_pc=0x%x",
                    dr, pc, callread_pc);
    // Write updated JSON before notifying the Ghidra daemon.
    write_full_json();
    signal_ghidra_pending("main_dt", dr);

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
    // ---- In IRQ context: connect recent DR reads to RAM writes ----
    if (g_discovery_irq_ipsr != 0 && ipsr != g_discovery_irq_ipsr) {
      if (g_discovery_cross_irq_skip_count < 16) {
        uint32_t pc = 0;
        uc_reg_read(uc, UC_ARM_REG_PC, &pc);
        dt_learning_log("[DISCOVERY] WRITE_SKIP_IRQ dr=0x%x expected_ipsr=0x%x actual_ipsr=0x%x pc=0x%x addr=0x%x val=0x%x",
                        g_discovery_dr, g_discovery_irq_ipsr, ipsr, pc,
                        (uint32_t)address, (uint32_t)value);
      }
      g_discovery_cross_irq_skip_count++;
      return;
    }

    if (discovery_multi_candidate_enabled()) {
      DiscoveryReadToken *tok =
          discovery_recent_unmatched_token(ipsr, (uint32_t)value);
      if (tok) {
        tok->matched = true;
        discovery_note_candidate_write(uc, (uint32_t)address, size, tok);
        return;
      }
    }

    // Compatibility fallback for older one-byte taint discovery.
    if (((uint32_t)value & 0xffu) == (g_discovery_taint & 0xffu) &&
        g_discovery_addr_count < MAX_DISCOVERY_ADDRS) {
      g_discovery_addr_list[g_discovery_addr_count++] = (uint32_t)address;
      dt_learning_log("[DISCOVERY] TAINT_WRITE #%d addr=0x%x val=0x%x",
                      g_discovery_addr_count, (uint32_t)address,
                      (uint32_t)value);
    }
  } else {
    // ---- In main loop context ----
    if (g_discovery_addr_count > 0 && g_discovery_buffer_addr == 0) {
      // buffer_addr just found; capture the main-loop read site next.
      uint32_t learned_addr =
          g_discovery_addr_list[g_discovery_addr_count - 1];
      PseudoChannel *hint = find_pseudo_buffer_hint(g_discovery_dr,
                                                   g_discovery_irq_pc);
      if (hint) {
        uint32_t diff = learned_addr > hint->buffer_addr
            ? learned_addr - hint->buffer_addr
            : hint->buffer_addr - learned_addr;
        g_discovery_buffer_addr = hint->buffer_addr;
        if (diff > 16) {
          dt_learning_log("[DISCOVERY] BUFFER_ADDR_REUSE_WARN dr=0x%x irq_pc=0x%x learned=0x%x reused=0x%x diff=%u callread=0x%x writes=%d",
                          g_discovery_dr, g_discovery_irq_pc, learned_addr,
                          g_discovery_buffer_addr, diff, hint->callread_pc,
                          g_discovery_addr_count);
        }
        dt_learning_log("[DISCOVERY] BUFFER_ADDR_REUSE_PSEUDO dr=0x%x irq_pc=0x%x learned=0x%x reused=0x%x callread=0x%x writes=%d",
                        g_discovery_dr, g_discovery_irq_pc, learned_addr,
                        g_discovery_buffer_addr, hint->callread_pc,
                        g_discovery_addr_count);
      } else {
        g_discovery_buffer_addr = learned_addr;
      }
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


void hook_discovery_candidate_read(uc_engine *uc, uc_mem_type type,
    uint64_t address, int size, int64_t value, void *user_data) {
  (void)type;
  (void)size;
  (void)value;
  (void)user_data;

  if (!discovery_multi_candidate_enabled()) return;
  if (!g_in_discovery_mode || g_read_pc_done) return;

  DiscoveryCandidate *cand =
      discovery_find_candidate_by_addr((uint32_t)address);
  if (!cand) return;

  uint32_t ipsr = 0;
  uint32_t pc = 0;
  uc_reg_read(uc, UC_ARM_REG_IPSR, &ipsr);
  uc_reg_read(uc, UC_ARM_REG_PC, &pc);
  pc &= ~1u;

  if (ipsr != 0) {
    cand->seen_irq_read = true;
    if (g_discovery_irq_read_skip_count < 16) {
      dt_learning_log("[DISCOVERY] CAND_IRQ_READ dr=0x%x range=0x%x-0x%x "
                      "pc=0x%x ipsr=0x%x addr=0x%x",
                      g_discovery_dr, cand->start, cand->end, pc, ipsr,
                      (uint32_t)address);
    }
    g_discovery_irq_read_skip_count++;
    return;
  }

  cand->seen_main_read = true;
  cand->main_read_pc = pc;
  cand->main_callread_pc =
      resolve_callread_pc_for_read(uc, pc, ipsr, "candidate_main_read");

  discovery_select_candidate(uc, cand, "main_read");
  try_finalize(uc);
}

// ====== Channel Discovery: Phase 1 buffer read callback ======

// Fires when the discovered buffer address is read.
// Captures read_pc (PC at buffer read) and callread_pc (direct caller callsite).
// Bounds are inferred later, after static analysis supplies avail/consume PCs.
void hook_phase1_buffer_read(uc_engine *uc, uc_mem_type type,
    uint64_t address, int size, int64_t value, void *user_data) {

  if (!g_in_discovery_mode) return;
  if (g_read_pc_done) return;

  uint32_t ipsr = 0;
  uc_reg_read(uc, UC_ARM_REG_IPSR, &ipsr);
  if (ipsr != 0) {
    if (g_discovery_irq_read_skip_count < 16) {
      uint32_t skip_pc = 0;
      uc_reg_read(uc, UC_ARM_REG_PC, &skip_pc);
      dt_learning_log("[DISCOVERY] BUFFER_READ_PC_SKIP_IRQ dr=0x%x pc=0x%x ipsr=0x%x buf=0x%x",
                      g_discovery_dr, skip_pc, ipsr,
                      g_discovery_buffer_addr);
    }
    g_discovery_irq_read_skip_count++;
    return;
  }

  uint32_t pc = 0;
  uc_reg_read(uc, UC_ARM_REG_PC, &pc);
  pc &= ~1u;

  g_discovery_read_pc = pc;
  g_discovery_callread_pc =
      resolve_callread_pc_for_read(uc, pc, ipsr, "buffer_read");
  g_read_pc_done = true;

  if (g_discovery_buffer_read_hook) {
    uc_hook_del(uc, g_discovery_buffer_read_hook);
    g_discovery_buffer_read_hook = 0;
  }

  dt_learning_log("[DISCOVERY] BUFFER_READ_PC dr=0x%x read_pc=0x%x callread_pc=0x%x ipsr=0x%x in_irq=%d",
                  g_discovery_dr, g_discovery_read_pc,
                  g_discovery_callread_pc, ipsr, ipsr != 0 ? 1 : 0);

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

  if (!irq_num_is_valid((short)g_bounds_irq)) {
    dt_learning_log("[BOUNDS] IRQ_UNRESOLVED dr=0x%x irq_pc=0x%x irq_num=%d",
                    dt->dr, dt->irq_pc, dt->irq_num);
    return;
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
    if (!irq_num_is_valid(dt->irq_num)) continue;
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
  g_bounds_irq = dt->irq_num;
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
  if (g_discovery_candidate_read_hook) {
    uc_hook_del(uc, g_discovery_candidate_read_hook);
    g_discovery_candidate_read_hook = 0;
  }
  g_in_discovery_mode = false;

  uint32_t matched_callread = 0;
  uint32_t pseudo_retry_count = 0;
  if (is_known_pseudo_callread(g_discovery_dr, g_discovery_callread_pc,
                               &matched_callread, &pseudo_retry_count)) {
    if (pseudo_retry_count >= PSEUDO_MAX_RETRY) {
      dt_learning_log("[DISCOVERY] SKIP_KNOWN_PSEUDO dr=0x%x callread=0x%x matched=0x%x retry=%u max=%u read_pc=0x%x buf=0x%x irq_pc=0x%x",
                      g_discovery_dr, g_discovery_callread_pc,
                      matched_callread, pseudo_retry_count,
                      PSEUDO_MAX_RETRY, g_discovery_read_pc,
                      g_discovery_buffer_addr, g_discovery_irq_pc);
      g_read_pc_done = false;
      g_discovery_dr = 0;
      g_discovery_irq_pc = 0;
      g_discovery_irq_ipsr = 0;
      g_discovery_cross_irq_skip_count = 0;
      g_discovery_irq_read_skip_count = 0;
      g_discovery_buffer_addr = 0;
      g_discovery_read_pc = 0;
      g_discovery_callread_pc = 0;
      g_discovery_addr_count = 0;
      discovery_reset_candidates();
      return;
    }

    dt_learning_log("[DISCOVERY] RETRY_KNOWN_PSEUDO dr=0x%x callread=0x%x matched=0x%x retry=%u max=%u read_pc=0x%x buf=0x%x irq_pc=0x%x",
                    g_discovery_dr, g_discovery_callread_pc,
                    matched_callread, pseudo_retry_count,
                    PSEUDO_MAX_RETRY, g_discovery_read_pc,
                    g_discovery_buffer_addr, g_discovery_irq_pc);
  }

  // 2. Create full irq_dt from discovery data
  uint32_t dr = g_discovery_dr;
  DataTracker *dt = &irq_dt_array[irq_dt_array_index];
  memset(dt, 0, sizeof(DataTracker));
  dt->dr = dr;
  dt->irq_pc = g_discovery_irq_pc;
  dt->irq_num = (short)g_discovery_irq_ipsr;
  dt->buffer_addr = g_discovery_buffer_addr;
  dt->read_pc = g_discovery_read_pc;
  dt->callread_pc = g_discovery_callread_pc;
  dt->avail_pc = 0;          // filled by Ghidra daemon later
  dt->buffer_len = 0;        // learned after avail_pc static analysis
  dt->buffer_min_len = 0;    // learned after avail_pc static analysis

  dt->rx_head = 0;
  dt->rx_tail = 0;

  dt_learning_log("[DISCOVERY] IRQ_DT_PENDING dr=0x%x irq_pc=0x%x irq_num=%d buf=0x%x read_pc=0x%x callread_pc=0x%x",
                  dt->dr, dt->irq_pc, dt->irq_num, dt->buffer_addr,
                  dt->read_pc, dt->callread_pc);

  // Update hash table (replace placeholder)
  int ret = 0;
  khint_t k = kh_put(dr_dt, hash_table, dr, &ret);
  if (ret != -1) {
    kh_value(hash_table, k) = dt;
  }
  irq_dt_array_index++;
  // 3. Write updated JSON before notifying the Ghidra daemon.
  write_full_json();
  signal_ghidra_pending("irq_dt", dr);

  // Clean up pending reference to this DR
  for (int i = 0; i < pending_dt_array_index; i++) {
    if (pending_dt_array[i].dr == dr) {
      memset(&pending_dt_array[i], 0, sizeof(DataTracker));
      break;
    }
  }

  g_discovery_occurred = true;

  dt_learning_log("[DISCOVERY] COMPLETE_PENDING dr=0x%x irq_pc=0x%x irq_num=%d buf=0x%x read_pc=0x%x callread_pc=0x%x",
                  dr, g_discovery_irq_pc, g_discovery_irq_ipsr, g_discovery_buffer_addr,
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
