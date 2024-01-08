OWN_DIR := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
PYTHON_INC=$(shell python3-config --includes)
PYTHON_LDFLAGS=$(shell python3-config --ldflags)
UC_DIRNAME := fuzzware-unicorn

LIBDIR = $(OWN_DIR)/../../../unicorn/$(UC_DIRNAME)/
INC=-I$(OWN_DIR)/../../../unicorn/$(UC_DIRNAME)/include $(PYTHON_INC)
BIN_EXT = .so

CC = clang
CXX := clang++ # Use clang++ for compiling C++ files
CFLAGS += -fpic -Wall -Werror $(INC) -g -O3
CXXFLAGS := $(CFLAGS) # Use the same flags for C++ by default, can be adjusted as needed
LDFLAGS += -shared -L$(LIBDIR) -lunicorn $(PYTHON_LDFLAGS)

.PHONY: all clean
# Separate the C and C++ sources
C_SOURCES := native_hooks.c timer.c interrupt_triggers.c util.c state_snapshotting.c native_tracing.c uc_snapshot.c
C_SOURCES += core_peripherals/cortexm_nvic.c core_peripherals/cortexm_systick.c
CPP_SOURCES := ufuzz_adapter/beginpoint_hook.cc 
# ufuzz_adapter/emulator_handler.cc ufuzz_adapter/global_var.cc ufuzz_adapter/headless_ghidra.cc

# Object files for C and C++
C_OBJS := $(C_SOURCES:.c=.o)
CPP_OBJS := $(CPP_SOURCES:.cc=.o)

# All object files
OBJS := $(C_OBJS) $(CPP_OBJS)

# Default rule for compiling C++ source files
%.o: %.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@

native_hooks.so: $(OBJS)
	$(CXX) $^ $(LDFLAGS) -o $@ 

all: native_hooks.so

clean:
	rm -rf *.o core_peripherals/*.o ufuzz_adapter/*.o $(BINS)
