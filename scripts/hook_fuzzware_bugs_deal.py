# The file seems to have a structure where each line contains information about a unique crash.
# The structure is: <num_unique_crashes> pc lr <crash_path_1> <crash_path_2> ...
# We will read the file and process the data accordingly.
import os, json,random,subprocess,re
from plot_bb_config import firmware_crashpc
# 你提供的真实 crash 地址
firmware_name = "CVE-2021-3319"
real_crash_list = firmware_crashpc[firmware_name]
#"0404","0405","0406","0408","0409" "0328","0330","0411","0412","0413"
time_list = ["0405","0406","0409","0412"]
#/home/n0vic3/fuzzers/fuzzware-examples/other_target/CVE-2021-3319/0415_fuzz
# _inter or _idle
firmware_name += ""
group_name= "other_target"
ADAPTER = True
if ADAPTER:
    fuzzware_version = "/home/n0vic3/.virtualenvs/fuzzware_ufuzzadapter/bin/fuzzware"
    home_path = "/home/n0vic3/fuzzers/fuzzware-examples"
else:
    fuzzware_version = "/home/n0vic3/.virtualenvs/fuzzware/bin/fuzzware"
    home_path = "/home/n0vic3/fuzzers/fuzzware/examples"
# 用于存储真实 crash 地址的字典
real_crash_addresses = {}
for real_crash in real_crash_list:
    real_crash_addresses[real_crash] = 0
# 提取 Basic Block 的 addr

# 判断是否是真实的 crash
def is_real_crash(output):
    # return "Heureka" in output
    for line in output.split('\n'):
        if "Heureka" in line:
            return True, line.split(' ')[-1]
    return False, None

def get_control_flow_graph(original_file_path,crash_file_path):
    completed_crash_file_path = os.path.join(original_file_path,crash_file_path)
    mainxxx = crash_file_path.split('/')[0]
    config_file_path = os.path.join(original_file_path, mainxxx)
    command = f'{fuzzware_version} emu {completed_crash_file_path}'
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,cwd=config_file_path)
    output, _ = process.communicate()
    output = output.decode('utf-8')
    # print(output)
    # 判断是否是真实的 crash
    return is_real_crash(output)

def get_results(file_path):
    # Get the path to the file
    original_file_path = file_path
    file_path = os.path.join(file_path,"stats", 'crash_contexts.txt')
    # Initialize a dictionary to store the results
    crash_results = {}
    real_crash = []
    false_crash = []
    i = 0
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
                i += 1
                print(f"current firmware:{firmware_name} current time:{time} crash:{i}")
                result,group = get_control_flow_graph(original_file_path,one_selcet_path)
                if not result:
                    print(f"false crash: {one_selcet_path}")
                    false_crash.append(one_selcet_path)
                else:
                    TRUE_CRASH = True
                    print(f"real crash: {one_selcet_path}")
                    real_crash.append(one_selcet_path)
                    crash_results[group] = crash_results.get(group, 0) + 1
            # Store the results in the dictionary
                    # Update the dictionary with the information
            
        

    wrtie_path = file_path.replace('crash_contexts.txt', 'true_crash.txt')
    with open(wrtie_path, 'w') as file:
        file.write(f"num of crashes:{len(real_crash)}\n")
        file.write(json.dumps(real_crash))
        file.write('\n')
        file.write(f"num of false crashes:{len(false_crash)}\n")
        file.write(json.dumps(false_crash))
        file.write('\n')
        file.write(json.dumps(real_crash_addresses))
        file.write('\n')
        file.write(json.dumps(crash_results))
    for real_crash in real_crash_list:
        real_crash_addresses[real_crash] = 0
    print('Results written to:', wrtie_path)
    

if __name__ == '__main__':
    
    
    sum_results = {}
    
    for time in time_list:
        new_file_path = f'{home_path}/{group_name}/{firmware_name}/{time}_fuzz'
        results = get_results(new_file_path)
        print(results)
        sum_results[time] = results
    print("all results: ", sum_results)