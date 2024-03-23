# The file seems to have a structure where each line contains information about a unique crash.
# The structure is: <num_unique_crashes> pc lr <crash_path_1> <crash_path_2> ...
# We will read the file and process the data accordingly.
import os, json,random,subprocess
# 你提供的真实 crash 地址
real_crash_list = ["80008c2", "8000a5a","8000ae4","8000978"]
# 用于存储真实 crash 地址的字典
real_crash_addresses = {}
for real_crash in real_crash_list:
    real_crash_addresses[real_crash] = 0
# 提取 Basic Block 的 addr
def extract_basic_block_addresses(output):
    addresses = []
    for line in output.split('\n'):
        if line.startswith('Basic Block: addr='):
            addr = line.split(' ')[3]
            addresses.append(addr)
    return addresses

# 判断是否是真实的 crash
def is_real_crash(addresses):
    for addr in addresses:
        for real_crash_addr in real_crash_addresses.keys():
            if real_crash_addr in addr:
                real_crash_addresses[real_crash_addr] += 1
                print(f"real crash addr: {real_crash_addr}")
                return True
    return False

def get_control_flow_graph(original_file_path,crash_file_path):
    completed_crash_file_path = os.path.join(original_file_path,crash_file_path)
    config_file_path = os.path.join(original_file_path, "data")
    command = f'/home/n0vic3/.virtualenvs/fuzzware_ufuzzadapter/bin/fuzzware emu -M {completed_crash_file_path}'
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,cwd=config_file_path)
    output, _ = process.communicate()
    output = output.decode('utf-8')

    # 提取 Basic Block 的 addr
    addresses = extract_basic_block_addresses(output)

    # 判断是否是真实的 crash
    if is_real_crash(addresses):
        return True
    return False

def get_results(file_path):
    # Get the path to the file
    original_file_path = file_path
    file_path = os.path.join(file_path,"stats", 'crash_contexts.txt')
    # Initialize a dictionary to store the results
    crash_results = {}
    real_crash = []
    with open(file_path, 'r') as file:
        for line in file.readlines()[1:]:
            # Split the line into components
            components = line.strip().split()
            # Extract the pc, lr, and crash paths
            num_unique_crashes = int(components[0])
            pc = components[1]
            lr = components[2]
            crash_paths = components[3:]

            # Select samples based on num_unique_crashes
            # if num_unique_crashes >= 10:
            #     selected_paths = random.sample(crash_paths, 10)
            # else:
            #     selected_paths = crash_paths
            selected_paths = crash_paths
            TRUE_CRASH = False
            for one_selcet_path in selected_paths:
                if not get_control_flow_graph(original_file_path,one_selcet_path):
                    print(f"not real crash: {one_selcet_path}")
                    print(f"pc: {pc}, lr: {lr}")
                    break
                else:
                    TRUE_CRASH = True
                    print(f"real crash: {one_selcet_path}")
                    real_crash.append(one_selcet_path)
            # Store the results in the dictionary
                    # Update the dictionary with the information
            if TRUE_CRASH:
                if lr not in crash_results:
                    crash_results[lr] = {'total': 0, 'pcs': {}}
                
                for _ in crash_paths:
                    crash_results[lr]['total'] += 1
                    if pc not in crash_results[lr]['pcs']:
                        crash_results[lr]['pcs'][pc] = 0
                    crash_results[lr]['pcs'][pc] += 1
        

    wrtie_path = file_path.replace('crash_contexts.txt', 'true_crash.txt')
    with open(wrtie_path, 'w') as file:
        
        file.write(json.dumps(real_crash))
        file.write('\n')
        file.write(json.dumps(real_crash_addresses))
    print('Results written to:', wrtie_path)
    return crash_results

if __name__ == '__main__':
    
    time_list = ["0308", "0303", "0304", "0311"]
    sum_results = {}
    for time in time_list:
        new_file_path = f'/home/n0vic3/fuzzers/fuzzware-examples/P2IM/PLC/{time}_fuzz'
        results = get_results(new_file_path)
        print(results)
        sum_results[time] = results
    print("all results: ", sum_results)