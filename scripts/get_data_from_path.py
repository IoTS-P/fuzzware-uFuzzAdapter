import re,os,subprocess
firmware_name = "Steering_Control"
# real_crash_list = firmware_crashpc[firmware_name]
#"0401","0402","0403","0404","0405","0406","0408","0409" "0328","0330","0411","0412","0413","0420","0421","0422","0423"
#"0301","0302","0303","0304","0305","0307","0308","0309","0310","0311"
time_list = ["0216","0218","0219","0220","0224","0419","0420","0421","0422","0423"]
#/home/n0vic3/fuzzers/fuzzware-examples/other_target/CVE-2021-3319/0415_fuzz
# _inter or _idle

ADAPTER = False
GET_CRASH_TYPE = False

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
def extract_coverage_data(log_path):
    with open(log_path, 'r') as file:
        lines = file.readlines()
    last_coverage_line = [line for line in lines if "Basic block coverage" in line][-1]
    coverage_percentage = re.search(r"(\d+\.\d+)%", last_coverage_line).group(1)
    basic_blocks = re.search(r"\b\d+\b", last_coverage_line).group(0)

    return coverage_percentage,basic_blocks

def extract_crash_data(crash_path):
    if not os.path.exists(crash_path):
        subprocess.run(f"{fuzzware_version} genstats", shell=True,cwd=os.path.dirname(os.path.dirname(crash_path)),executable="/bin/bash")
    with open(crash_path, 'r') as file:
        lines = file.readlines()
        
    if len(lines) == 0:
        first_crash_time = 0
    else:
        first_crash_time = lines[0].split("\t")[0]
    
    unique_crashes = len(lines)
    return first_crash_time, unique_crashes

def get_crash_types(crash_context_path):
    if not os.path.exists(crash_context_path):
        if ADAPTER:
            json_put_cmd = "json_file=$(ls *.json | head -n 1) && for dir in *_fuzz/; do for subdir in \"$dir\"main00*/; do if [[ -d \"$subdir\" ]]; then cp \"$json_file\" \"$subdir\"; fi; done; done"
            subprocess.run(json_put_cmd, shell=True,cwd=os.path.dirname(os.path.dirname(os.path.dirname(crash_context_path))),executable="/bin/bash")
        activate_path = os.path.join(os.path.dirname(fuzzware_version),"activate")
        print(activate_path)
        # subprocess.run(f"source {activate_path}", shell=True,cwd=os.path.dirname(os.path.dirname(crash_context_path)),executable="/bin/bash")
        subprocess.run(f"source {activate_path} && fuzzware genstats crashcontexts", shell=True,cwd=os.path.dirname(os.path.dirname(crash_context_path)),executable="/bin/bash")
    with open(crash_context_path, 'r') as file:
        lines = file.readlines()[1:]
    crash_type = len(lines)
    for line in lines:
        components = line.strip().split(" ")
        if int(components[1],16) == -404:
            crash_type -= 1
    return crash_type
# Replace the paths with your actual file paths
if __name__ == "__main__":
    for one_time in time_list:
        base_path = f'{home_path}/{group_name}/{firmware_name}/{one_time}_fuzz'
        coverage_log_path = base_path+"/logs/pipeline.log"
        crash_log_path = base_path+"/stats/crash_creation_timings.txt"
        crash_context_path = base_path+"/stats/crash_contexts.txt"
        input_log_path = base_path+"/stats/input_creation_timings.txt"
        coverage_percentage,basic_blocks = extract_coverage_data(coverage_log_path)
        first_crash_time, unique_crashes = extract_crash_data(crash_log_path)
        if GET_CRASH_TYPE:
            crash_type = get_crash_types(crash_context_path)
            print(f"Crash type: {crash_type}")
        print(f"base_path: {base_path}")
        # print(f"Basic blocks: {basic_blocks}")
        # print(f"Coverage percentage: {coverage_percentage}%")
        # print(f"First crash time: {first_crash_time}")
        # print(f"Unique crashes: {unique_crashes}")1402
        input_log_lines = open(input_log_path).readlines()
        print(f"Total inputs: {len(input_log_lines)}")
        print("=====================================")
        