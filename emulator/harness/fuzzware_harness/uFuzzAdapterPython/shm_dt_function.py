import os,pickle,ctypes
my_debug_log = print
def read_from_shared_memory(config,c_lib):
    '''
    used to read data from shared memory
    '''
    emulation_handler_serialized_data = None
    
        # read from shared memory file
        # os.walk get include shared_memory.txt
    shm_file = None
    for root, dirs, files in os.walk(os.path.dirname(config["binary_file"])):
        for file in files:
            if file.endswith("shared_memory.txt"):
                shm_file = os.path.join(root, file)
                break
    with open(shm_file, "rb") as f:
        emulation_handler_serialized_data = f.read()
    
    # check if the shared memory is empty
    if emulation_handler_serialized_data == b"\x00" * len(
        emulation_handler_serialized_data
    ):
        my_debug_log("Shared memory is empty or uninitialized.")
        return
    
    # recover the data from shared memory
    data_tracker_dict = pickle.loads(emulation_handler_serialized_data)
    irq_dt_set = data_tracker_dict["irq_dt_set"]
    main_dt_set = data_tracker_dict["main_dt_set"]
    fill_global_datatracker_array(c_lib,main_dt_set,irq_dt_set)
    # call c function to save irq_dt_set and main_dt_set
    my_debug_log("Shared memory is read")
    my_debug_log("Recover dt hooks complete")

def convert_to_ctypes(dt_object):
    from .data_tracker import DataTracker
    return DataTracker(
        dr=0 if dt_object.dr is None else dt_object.dr,
        callread_pc=0 if dt_object.callread_pc is None else dt_object.callread_pc,
        read_pc=0 if dt_object.read_pc is None else dt_object.read_pc,
        buffer_addr=0,
        irq_pc=0,
        avail_pc=0 if dt_object.avail_pc is None else dt_object.avail_pc,
        rx_head=0,
        rx_tail=0,
        buffer_len=0,
        buffer_min_len=0,
        consume_count=0
    )

def fill_global_datatracker_array(c_lib,main_dt_set,irq_dt_set):
    from .data_tracker import StructDataTracker
        # 获取全局数组的引用
    ARRAY_SIZE = 100
    main_dt_array = (StructDataTracker * ARRAY_SIZE).from_address(
        ctypes.addressof(c_lib.main_dt_array)
    )
    irq_dt_array = (StructDataTracker * ARRAY_SIZE).from_address(
        ctypes.addressof(c_lib.irq_dt_array)
    )
    #short main_dt_array_index = 0;
    #short irq_dt_array_index = 0;
    main_dt_array_index = ctypes.c_short.from_address(
        ctypes.addressof(c_lib.irq_dt_array)
    )
    irq_dt_array_index = ctypes.c_short.from_address(
        ctypes.addressof(c_lib.irq_dt_array)
    )
    # fill main_dt_array
    for i, get_dt in enumerate(main_dt_set):
        dt = convert_to_ctypes(get_dt)
        main_dt_array[i].dr = dt.dr
        main_dt_array[i].callread_pc = dt.callread_pc
        main_dt_array[i].read_pc = dt.read_pc
        main_dt_array[i].buffer_addr = dt.buffer_addr
        main_dt_array[i].irq_pc = dt.irq_pc
        main_dt_array[i].avail_pc = dt.avail_pc
        main_dt_array[i].rx_head = dt.rx_head
        main_dt_array[i].rx_tail = dt.rx_tail
        main_dt_array[i].buffer_len = dt.buffer_len
        main_dt_array[i].buffer_min_len = dt.buffer_min_len
        main_dt_array[i].consume_count = dt.consume_count
        main_dt_array_index.value = i
    # fill irq_dt_array
    for i, get_dt in enumerate(irq_dt_set):
        dt = convert_to_ctypes(get_dt)
        irq_dt_array[i].dr = dt.dr
        irq_dt_array[i].callread_pc = dt.callread_pc
        irq_dt_array[i].read_pc = dt.read_pc
        irq_dt_array[i].buffer_addr = dt.buffer_addr
        irq_dt_array[i].irq_pc = dt.irq_pc
        irq_dt_array[i].avail_pc = dt.avail_pc
        irq_dt_array[i].rx_head = dt.rx_head
        irq_dt_array[i].rx_tail = dt.rx_tail
        irq_dt_array[i].buffer_len = dt.buffer_len
        irq_dt_array[i].buffer_min_len = dt.buffer_min_len
        irq_dt_array[i].consume_count = dt.consume_count
        irq_dt_array_index.value = i
    
    return
