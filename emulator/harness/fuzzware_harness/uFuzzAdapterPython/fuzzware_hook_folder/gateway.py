import json
# map
fucntion_times = {}
addr_times = {0x8001c82:0,0x8001bf0:0}
from unicorn import UC_HOOK_CODE,UC_HOOK_BLOCK
from ...globs import uc
# Create a reverse mapping of function addresses to function names
gateway_address_to_word = None

def add_bug(name):
    print(f"Heureka! {name}", flush=True)
def addr_times_handler(uc, address, size, user_data):
    addr_times[address] += 1
    print(json.dumps(addr_times))

def hook_gateway_addr(uc):
    for address in addr_times.keys():
        uc.hook_add(UC_HOOK_CODE, addr_times_handler, begin=address-1, end=address|1)

def hook_gateway_bug(uc, address, size, user_data):
    if uc.regs.pc == 0x80069f0:
        add_bug("gateway-80069f0")