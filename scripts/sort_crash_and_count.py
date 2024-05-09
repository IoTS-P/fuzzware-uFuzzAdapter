# The file seems to have a structure where each line contains information about a unique crash.
# The structure is: <num_unique_crashes> pc lr <crash_path_1> <crash_path_2> ...
# We will read the file and process the data accordingly.
import os, json,random,subprocess,re
from plot_bb_config import firmware_crashpc
from multiprocessing import Pool
# 你提供的真实 crash 地址
firmware_name = "PLC"
real_crash_list = firmware_crashpc[firmware_name]
#"0401","0402","0403","0404","0405","0406","0408","0409" "0328","0330","0411","0412","0413""0423","0425","0426","0427"
time_list = ["0301"]

ADAPTER = True
if ADAPTER:
    fuzzware_version = "/home/n0vic3/.virtualenvs/fuzzware_ufuzzadapter/bin/fuzzware"
    home_path = "/home/n0vic3/fuzzers/fuzzware-examples"
    firmware_name += ""
    group_name= "P2IM"
else:
    fuzzware_version = "/home/n0vic3/.virtualenvs/fuzzware/bin/fuzzware"
    home_path = "/home/n0vic3/fuzzers/fuzzware/examples"
    # _inter or _idle
    firmware_name += ""
    group_name= "uEmu"
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
            if firmware_name == "uEmu.GPSTracker":
                # 使用正则表达式提取lr数字部分
                match = re.search(r'0x(\w+)', line.split(' ')[-1])
                if match:
                    result = match.group(1)
                    addresses.append(result)
        elif 'pc' in line:
            # 查找包含 'pc' 的行，并从中提取 'pc' 后的地址
            pc_addr = re.search(r'\(pc (0x[0-9a-f]+)\)', line)
            if pc_addr:
                addresses.append(pc_addr.group(1))
        
    return addresses

# 判断是否是真实的 crash
def is_real_crash(addresses):
    for addr in addresses:
        for real_crash_addr in real_crash_addresses.keys():
            if real_crash_addr in addr:
                real_crash_addresses[real_crash_addr] += 1
                print(f"real crash addr: {real_crash_addr}")
                return True,real_crash_addr
    return False,None

def get_control_flow_graph(original_file_path,crash_file_path):
    print(f"current firmware:{firmware_name} current time:{time} current file:{crash_file_path}")
    completed_crash_file_path = os.path.join(original_file_path,crash_file_path)
    mainxxx = crash_file_path.split('/')[0]
    config_file_path = os.path.join(original_file_path, mainxxx)
    command = f'{fuzzware_version} emu -M -v -t {completed_crash_file_path}'
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,cwd=config_file_path)
    output, _ = process.communicate()
    output = output.decode('utf-8')

    # 提取 Basic Block 的 addr
    addresses = extract_basic_block_addresses(output)

    # 判断是否是真实的 crash
    return is_real_crash(addresses)

def get_results(file_path):
    # Get the path to the file
    original_file_path = file_path
    file_path = os.path.join(file_path, "stats", 'crash_creation_timings.txt')
    # Initialize a dictionary to store the results
    crash_results = {}
    real_crash = []
    false_crash = []
    crash_timing_worker_results = []
    if ADAPTER:
        json_put_cmd = "json_file=$(ls *.json | head -n 1) && for dir in *_fuzz/; do for subdir in \"$dir\"main00*/; do if [[ -d \"$subdir\" ]]; then cp \"$json_file\" \"$subdir\"; fi; done; done"
        subprocess.run(json_put_cmd, shell=True,cwd=os.path.dirname(os.path.dirname(os.path.dirname(file_path))),executable="/bin/bash")
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            lines = file.readlines()
    else:
        subprocess.run(f"{fuzzware_version} genstats", shell=True,cwd=os.path.dirname(os.path.dirname(file_path)))
        with open(file_path, 'r') as file:
            lines = file.readlines()
    tasks = []
    for line in lines:
        components = line.strip().split()
        crash_path = components[-1]  # 从每行中获取崩溃路径列表
        tasks.append((original_file_path,crash_path))

    
    # 使用进程池批量处理任务
    crash_timing_worker_results = []
    with Pool(processes=128) as pool:  # 根据CPU核心数量设置进程数
        crash_timing_worker_results = pool.starmap(get_control_flow_graph, tasks)
    for i, result in enumerate(crash_timing_worker_results):
        if result[0]:
            real_crash.append(tasks[i][1])
            real_crash_addresses[result[1]] += 1
        else:
            false_crash.append(tasks[i][1])
        

    wrtie_path = file_path.replace('crash_creation_timings.txt', 'sort_pc_true_crash.txt')
    with open(wrtie_path, 'w') as file:
        file.write(json.dumps(real_crash_addresses))
        file.write('\n')
        file.write(json.dumps(real_crash))
        
        
    for real_crash in real_crash_list:
        real_crash_addresses[real_crash] = 0
    print('Results written to:', wrtie_path)
    return crash_results

def post_exec_pushplus(title,content):
    import requests
    requests.get(f"http://www.pushplus.plus/send?token=784df1822b964c4a9dd13e1513ca37f3&title={title}&content={content}&template=html")
if __name__ == '__main__':
    
    
    sum_results = {}
    
    for time in time_list:
        new_file_path = f'{home_path}/{group_name}/{firmware_name}/{time}_fuzz'
        results = get_results(new_file_path)
        print(results)
        sum_results[time] = results
    print("all results: ", sum_results)
    post_exec_pushplus("sort_pc_true_crash",json.dumps(sum_results))