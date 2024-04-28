# The file seems to have a structure where each line contains information about a unique crash.
# The structure is: <num_unique_crashes> pc lr <crash_path_1> <crash_path_2> ...
# We will read the file and process the data accordingly.
import os, json,random,subprocess,re
import time
from plot_bb_config import firmware_crashpc
from multiprocessing import Pool
# 你提供的真实 crash 地址
firmware_name = "heat_press_3"
# real_crash_list = firmware_crashpc[firmware_name]
#"0401","0402","0403","0404","0405","0406","0408","0409" "0328","0330","0411","0412","0413","0420",
time_list = ["0426"]
#/home/n0vic3/fuzzers/fuzzware-examples/other_target/CVE-2021-3319/0415_fuzz
# _inter or _idle

ADAPTER = True
FORCE_GENSTATS = False
if ADAPTER:
    fuzzware_version = "/home/n0vic3/.virtualenvs/fuzzware_ufuzzadapter/bin/fuzzware"
    home_path = "/home/n0vic3/fuzzers/fuzzware-examples"
    firmware_name += ""
    group_name= "P2IM"
else:
    fuzzware_version = "/home/n0vic3/.virtualenvs/fuzzware/bin/fuzzware"
    home_path = "/home/n0vic3/fuzzers/fuzzware/examples"
    firmware_name += ""
    group_name= "other_target_mmio_seedbin"

def extracted_json_data(output):
    results = output.split('\n')[::-1]
    for line in results:
        try:
            data = json.loads(line)
            if type(data) == dict:
                return data
            else:
                continue
        except:
            pass
        

        

def process_path(input_file_path, original_file_path, fuzzware_version):
    completed_input_file_path = os.path.join(original_file_path, input_file_path)
    mainxxx = input_file_path.split('/')[0]
    config_file_path = os.path.join(original_file_path, mainxxx)
    command = f'{fuzzware_version} emu {completed_input_file_path}'
    print(f"completed_input_file_path:{completed_input_file_path}")
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=config_file_path)
    output, _ = process.communicate()
    output = output.decode('utf-8')

    return extracted_json_data(output),input_file_path

def get_results(file_path):
    original_file_path = file_path
    file_path = os.path.join(file_path, "stats", 'input_creation_timings.txt')
    
    # Initialize a dictionary to store function call counts
    function_call_counts = {}

    # Read and process file lines
    crash_timing_worker_results = []
    if ADAPTER:
        json_put_cmd = "json_file=$(ls *.json | head -n 1) && for dir in *_fuzz/; do for subdir in \"$dir\"main00*/; do if [[ -d \"$subdir\" ]]; then cp \"$json_file\" \"$subdir\"; fi; done; done"
        subprocess.run(json_put_cmd, shell=True, cwd=os.path.dirname(os.path.dirname(os.path.dirname(file_path))), executable="/bin/bash")
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            lines = file.readlines()
    else:
        subprocess.run(f"{fuzzware_version} genstats", shell=True, cwd=os.path.dirname(os.path.dirname(file_path)))
        with open(file_path, 'r') as file:
            lines = file.readlines()
    tasks = []
    for line in lines:
        components = line.strip().split()
        crash_path = components[-1]  # 从每行中获取崩溃路径列表
        tasks.append((crash_path, original_file_path, fuzzware_version))

    # 使用进程池批量处理任务
    with Pool(processes=156) as pool:
        crash_timing_worker_results = pool.starmap(process_path, tasks)

    # Collecting results
    for async_data,input_file_path in crash_timing_worker_results:
        if async_data == None:
            print(f"{input_file_path} is None")
            continue
        try:
            for func_name, count in async_data.items():
                if func_name not in function_call_counts:
                    function_call_counts[func_name] = 0
                function_call_counts[func_name] += count
        except:
            print(f"error:{async_data} input_file:{input_file_path}")

    # Write results to file
    results_path = os.path.join(original_file_path, 'function_call_counts.json')
    with open(results_path, 'w') as file:
        json.dump(function_call_counts, file, indent=4)
    print('Function call counts written to:', results_path)
    return function_call_counts

if __name__ == '__main__':
    sum_results = {}
    
    for one_time in time_list:
        new_file_path = f'{home_path}/{group_name}/{firmware_name}/{one_time}_fuzz'
        if not os.path.exists(os.path.join(new_file_path, "stats", "avail_times.txt")) or FORCE_GENSTATS:
            results = get_results(new_file_path)
            sum_results[one_time] = results
    print("All results: ", sum_results)