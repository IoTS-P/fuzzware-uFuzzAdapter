# ...existing code...
import os, json,random,subprocess,re
from plot_bb_config import firmware_crashpc
from multiprocessing import Pool
# 你提供的真实 crash 地址
firmware_name = "Bootstrap_SPI"
real_crash_list = firmware_crashpc[firmware_name]
time_list = ["1107"]

ADAPTER = False
if ADAPTER:
    fuzzware_version = "/home/n0vic3/.virtualenvs/fuzzware_ufuzzadapter/bin/fuzzware"
    home_path = "/home/n0vic3/fuzzers/fuzzware-examples"
    firmware_name += ""
    group_name= "Fuzzware_CVE"
else:
    fuzzware_version = "/home/n0vic3/.virtualenvs/fuzzware/bin/fuzzware"
    home_path = "/home/n0vic3/fuzzers/fuzzware-examples"
    firmware_name += ""
    group_name= "Fuzzware_CVE"

# 用于存储真实 crash 地址的字典（计数）
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
                match = re.search(r'0x(\w+)', line.split(' ')[-1])
                if match:
                    result = match.group(1)
                    addresses.append(result)
        elif 'pc' in line:
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

    addresses = extract_basic_block_addresses(output)
    return is_real_crash(addresses)

def get_results(file_path):
    original_file_path = file_path
    file_path = os.path.join(file_path, "stats", 'crash_creation_timings.txt')
    crash_results = {}
    # 为每一类真实 crash 维护独立的队列（list）
    real_crashes_by_category = {rc: [] for rc in real_crash_list}
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
        crash_path = components[-1]
        tasks.append((original_file_path,crash_path))

    # 并行处理
    with Pool(processes=128) as pool:
        crash_timing_worker_results = pool.starmap(get_control_flow_graph, tasks)
    
    total_crashes = len(tasks)
    real_crash_count = 0
    
    for i, result in enumerate(crash_timing_worker_results):
        if result[0]:
            category = result[1] or "UNKNOWN"
            # 将匹配到的 crash 加入对应分类的队列
            real_crashes_by_category.setdefault(category, []).append(tasks[i][1])
            real_crash_addresses[result[1]] += 1
            real_crash_count += 1
        else:
            false_crash.append(tasks[i][1])

    false_crash_count = total_crashes - real_crash_count

    print(f"崩溃总数: {total_crashes}")
    print(f"命中真实崩溃数: {real_crash_count}")
    # 打印每类命中数量
    for cat, lst in real_crashes_by_category.items():
        print(f"  类别 {cat} -> {len(lst)}")

    print(f"未命中崩溃数: {false_crash_count}")
        
    wrtie_path = file_path.replace('crash_creation_timings.txt', 'newsort_pc_true_crash.txt')
    with open(wrtie_path, 'w') as file:
        # 先写计数字典，再写每类的 crash 队列
        file.write(json.dumps(real_crash_addresses))
        file.write('\n')
        file.write(json.dumps(real_crashes_by_category))
        
    # 重置计数器以便下次运行
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
        new_file_path = f'{home_path}/{group_name}/{firmware_name}/{time}_baseline_1'
        results = get_results(new_file_path)
        print(results)
        sum_results[time] = results
    print("all results: ", sum_results)
    post_exec_pushplus("sort_pc_true_crash",json.dumps(sum_results))
# ...existing code...