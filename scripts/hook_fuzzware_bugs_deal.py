# The file seems to have a structure where each line contains information about a unique crash.
# The structure is: <num_unique_crashes> pc lr <crash_path_1> <crash_path_2> ...
# We will read the file and process the data accordingly.
import os, json,random,subprocess,re
import time
from plot_bb_config import firmware_crashpc
from multiprocessing import Pool
# 你提供的真实 crash 地址
firmware_name = "10064_0"
# real_crash_list = firmware_crashpc[firmware_name]
#"0401","0402","0403","0404","0405","0406","0408","0409" "0328","0330","0411","0412","0413","0420",
time_list = ["0423"]
#/home/n0vic3/fuzzers/fuzzware-examples/other_target/CVE-2021-3319/0415_fuzz
# _inter or _idle

ADAPTER = True
FORCE_GENSTATS = False
if ADAPTER:
    fuzzware_version = "/home/n0vic3/.virtualenvs/fuzzware_ufuzzadapter/bin/fuzzware"
    home_path = "/home/n0vic3/fuzzers/fuzzware-examples"
    firmware_name += ""
    group_name= "other_target_mmio_seedbin"
else:
    fuzzware_version = "/home/n0vic3/.virtualenvs/fuzzware/bin/fuzzware"
    home_path = "/home/n0vic3/fuzzers/fuzzware/examples"
    firmware_name += ""
    group_name= "other_target_mmio_seedbin"
# 用于存储真实 crash 地址的字典
# real_crash_addresses = {}
# for real_crash in real_crash_list:
#     real_crash_addresses[real_crash] = 0
# 提取 Basic Block 的 addr
# 判断是否是真实的 crash
def is_real_crash(output):
    cve_result = []
    # print(output)
    for line in output.split('\n'):
        if "Heureka" in line:
            cve_result.append(line.split(' ')[-1])
    if len(cve_result) > 0:
        return True, cve_result
    else:
        return False, None


def process_path(crash_file_path, original_file_path, fuzzware_version):
    completed_crash_file_path = os.path.join(original_file_path, crash_file_path)
    mainxxx = crash_file_path.split('/')[0]
    config_file_path = os.path.join(original_file_path, mainxxx)
    command = f'{fuzzware_version} emu {completed_crash_file_path}'
    print(f"completed_crash_file_path:{completed_crash_file_path}")
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=config_file_path)
    output, _ = process.communicate()
    output = output.decode('utf-8')

    return is_real_crash(output), crash_file_path

def get_results(file_path):
    original_file_path = file_path
    file_path = os.path.join(file_path, "stats", 'crash_creation_timings.txt')
    

    # Read and process file lines
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
        tasks.append((crash_path, original_file_path, fuzzware_version))

    # 使用进程池批量处理任务
    with Pool(processes=72) as pool:  # 根据CPU核心数量设置进程数
        crash_timing_worker_results = pool.starmap(process_path, tasks)

    # Collecting results
    real_crash = []
    false_crash = []
    crash_results = {}
    num_processed = 0
    for async_result, crash_path in crash_timing_worker_results:
        result, group = async_result[0],async_result[1]
        if result:
            print(f"real crash: {crash_path}")
            real_crash.append(crash_path)
            for g in group:
                crash_results[g] = crash_results.get(g, 0) + 1
        else:
            print(f"false crash: {crash_path}")
            false_crash.append(crash_path)


    # Write results to file
    write_path = file_path.replace('crash_creation_timings.txt', 'true_crash.txt')
    with open(write_path, 'w') as file:
        file.write(f"num of crashes:{len(real_crash)}\n")
        file.write(json.dumps(real_crash))
        file.write('\n')
        file.write(f"num of false crashes:{len(false_crash)}\n")
        file.write(json.dumps(false_crash))
        file.write('\n')
        file.write(json.dumps(crash_results))
    print(crash_results)
    print('Results written to:', write_path)

    

if __name__ == '__main__':
    
    
    sum_results = {}
    
    for one_time in time_list:
        new_file_path = f'{home_path}/{group_name}/{firmware_name}/{one_time}_fuzz'
        if not os.path.exists(os.path.join(new_file_path,"stats","true_crash.txt")) or FORCE_GENSTATS:
            results = get_results(new_file_path)
            print(results)
            sum_results[one_time] = results
        else:
            with open(os.path.join(new_file_path,"stats","true_crash.txt"), 'r') as file:
                lines = file.readlines()
            # for i,line in enumerate(lines):
            #     print(f"line {i}: {line}")
            print(f"new_file_path: {new_file_path}")
            print(lines[0].strip("\n"))
            print(lines[4])
            print("--------------------------------------------------------------------------------")
    print("all results: ", sum_results)