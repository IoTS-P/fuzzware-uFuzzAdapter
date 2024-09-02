# The file seems to have a structure where each line contains information about a unique crash.
# The structure is: <num_unique_crashes> pc lr <crash_path_1> <crash_path_2> ...
# We will read the file and process the data accordingly.
import os, json,subprocess
from multiprocessing import Pool,Value
import ctypes
from plot_bb_config import *
# 你提供的真实 crash 地址
firmware_name = "Gateway"
# real_crash_list = firmware_crashpc[firmware_name]
#"0401","0402","0403","0404","0405","0406","0408","0409" "0328","0330","0411","0412","0413","0420","0301","0302","0303","0304","0305","0307","0308","0309","0310",
#,"0218","0219","0220","0224","0301","0302","0303","0304","0305","0414","0416"
time_list =  [
    "0307",
    #"0830","0831"
]


#/home/n0vic3/fuzzers/fuzzware-examples/other_target/CVE-2021-3319/0415_fuzz
# _inter or _idle

ADAPTER = True
FORCE_GENSTATS = True
if ADAPTER:
    fuzzware_version = "/home/n0vic3/.virtualenvs/fuzzware_ufuzzadapter/bin/fuzzware"
    home_path = "/home/n0vic3/fuzzers/fuzzware-examples"
    firmware_name += ""
    group_name= "P2IM"
else:
    fuzzware_version = "/home/n0vic3/.virtualenvs/fuzzware/bin/fuzzware"
    home_path = "/home/n0vic3/fuzzers/fuzzware/examples"
    firmware_name += ""
    group_name= "P2IM"

def extracted_json_data(output):
    # print(output)
    results = output.split('\n')[::-1]
    for line in results:
        try:
            data = json.loads(line)
            if type(data) == dict:
                print(len(data))
                return data
            else:
                continue
        except:
            pass
        
        

def process_path(input_file_path, original_file_path, fuzzware_version,):

    completed_input_file_path = os.path.join(original_file_path, input_file_path)
    mainxxx = input_file_path.split('/')[0]
    config_file_path = os.path.join(original_file_path, mainxxx)
    command = f'{fuzzware_version} emu {completed_input_file_path}'
    
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=config_file_path)
    output, _ = process.communicate()
    output = output.decode('utf-8')
    print("current_input_file_path:",completed_input_file_path)
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
    tasks_nums = len(tasks)
    # 使用进程池批量处理任务
    with Pool(processes=88) as pool:
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
    tmp_dict = dict()
    with open(results_path, 'w') as file:
        for key, value in function_call_counts.items():
            # hex(int) to str
            tmp_dict[hex(int(key))] = value
        json.dump(tmp_dict, file, indent=4)
        all_avail_function_times = 0
    print('Function call counts written to:', results_path)

    return tmp_dict

def post_exec_pushplus(title,content):

    import requests
    
    content = len(content)
    res = requests.get(f"http://www.pushplus.plus/send?token=784df1822b964c4a9dd13e1513ca37f3&title={title}&content={content}&template=html")
    print(res.content)

if __name__ == '__main__':
    sum_results = {}
    for one_time in time_list:
        base_path_no_group = f'{home_path}/{group_name}/{firmware_name}/{one_time}_fuzz'
        if os.path.exists(base_path_no_group):
            results = get_results(base_path_no_group)
            sum_results[one_time] = results
        else:
            for group_index in range(5):  # Loop through group_0 to group_4
                base_path_with_group = f'{home_path}/{group_name}/{firmware_name}/group_{group_index}/{one_time}_fuzz'
                print(base_path_with_group)
                if os.path.exists(base_path_with_group):
                   results = get_results(base_path_with_group)
                   sum_results[one_time] = results
    print("All results: ", sum_results)
    post_exec_pushplus(f"Function call counts for {firmware_name}", sum_results)
