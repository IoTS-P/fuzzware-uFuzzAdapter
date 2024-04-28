plc_words = [
    "getRxBuffer",
    "digitalWrite",
    "is_pin_configured",
    "get_GPIO_Port",
    "digital_io_write",
    "HAL_GPIO_WritePin",
    "validateRequest",
    "makeWord",
    "buildException",
    "sendTxBuffer",
    "calcCRC",
    "millis",
    "GetCurrentMilli",
    "HAL_GetTick",
    "process_FC1",
    "process_FC3",
    "process_FC5",
    "process_FC6",
    "process_FC15",
    "process_FC16"
]
# map
fucntion_times = {}
for word in plc_words:
    fucntion_times[word] = 0

from unicorn import UC_HOOK_CODE,UC_HOOK_BLOCK
from ...globs import uc
# Create a reverse mapping of function addresses to function names
plc_address_to_word = None

# Modify the function_times_handler to use the reverse mapping
def function_times_handler(uc, address, size, user_data):
    # Check if the current address is in the reverse mapping
    if address in plc_address_to_word:
        # Get the function name from the reverse mapping
        word = plc_address_to_word[address]
        # Increment the count of this function in the map
        fucntion_times[word] += 1
        print(fucntion_times)

def hook_plc_words(uc):
    global plc_address_to_word
    plc_address_to_word = {uc.symbols[word]: word for word in plc_words}
    for address in plc_address_to_word.keys():
        uc.hook_add(UC_HOOK_BLOCK, function_times_handler, begin=address, end=address+1)
