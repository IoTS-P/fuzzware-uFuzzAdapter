import re
import os
import subprocess

firmware_name = "CVE-2021-3322"
time_list = ["0404","0405","0406","0408","0409","0412","0415","0416","0419"]
ADAPTER = False
GET_CRASH_TYPE = False
DATA_PATH = True

if ADAPTER:
    fuzzware_version = "/home/n0vic3/.virtualenvs/fuzzware_ufuzzadapter/bin/fuzzware"
    if DATA_PATH:
        home_path = "/data/fuzzware_tmp_dir/adapter"
    else:
        home_path = "/home/n0vic3/fuzzers/fuzzware-examples"
    group_name = "other_target"
else:
    fuzzware_version = "/home/n0vic3/.virtualenvs/fuzzware/bin/fuzzware"
    if DATA_PATH:
        home_path = "/data/fuzzware_tmp_dir/original"
    else:
        home_path = "/home/n0vic3/fuzzers/fuzzware/examples"
    group_name = "other_target_mmio_seedbin"

def extract_coverage_data(log_path):
    with open(log_path, 'r') as file:
        lines = file.readlines()
    last_coverage_line = [line for line in lines if "Basic block coverage" in line][-1]
    coverage_percentage = re.search(r"(\d+\.\d+)%", last_coverage_line).group(1)
    basic_blocks = re.search(r"\b\d+\b", last_coverage_line).group(0)
    return coverage_percentage, basic_blocks

def extract_crash_data(crash_path):
    if not os.path.exists(crash_path):
        subprocess.run(f"{fuzzware_version} genstats", shell=True, cwd=os.path.dirname(os.path.dirname(crash_path)), executable="/bin/bash")
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
            subprocess.run(json_put_cmd, shell=True, cwd=os.path.dirname(os.path.dirname(os.path.dirname(crash_context_path))), executable="/bin/bash")
        activate_path = os.path.join(os.path.dirname(fuzzware_version), "activate")
        subprocess.run(f"source {activate_path} && fuzzware genstats crashcontexts", shell=True, cwd=os.path.dirname(os.path.dirname(crash_context_path)), executable="/bin/bash")
    with open(crash_context_path, 'r') as file:
        lines = file.readlines()[1:]
    crash_type = len(lines)
    for line in lines:
        components = line.strip().split(" ")
        if int(components[1], 16) == -404:
            crash_type -= 1
    return crash_type

def process_fuzzing_data(base_path):
    coverage_log_path = os.path.join(base_path, "logs/pipeline.log")
    crash_log_path = os.path.join(base_path, "stats/crash_creation_timings.txt")
    crash_context_path = os.path.join(base_path, "stats/crash_contexts.txt")
    input_log_path = os.path.join(base_path, "stats/input_creation_timings.txt")

    coverage_percentage, basic_blocks = extract_coverage_data(coverage_log_path)
    first_crash_time, unique_crashes = extract_crash_data(crash_log_path)
    if GET_CRASH_TYPE:
        crash_type = get_crash_types(crash_context_path)
        print(f"Crash type: {crash_type}")

    print(f"base_path: {base_path}")
    # print(f"Basic blocks: {basic_blocks}")
    # print(f"Coverage percentage: {coverage_percentage}%")
    # print(f"First crash time: {first_crash_time}")
    print(f"Unique crashes: {unique_crashes}")
    input_log_lines = open(input_log_path).readlines()
    # print(f"Total inputs: {len(input_log_lines)}")
    print("=====================================")

if __name__ == "__main__":
    for one_time in time_list:
        base_path_no_group = f'{home_path}/{group_name}/{firmware_name}/{one_time}_fuzz'
        print(base_path_no_group)
        if os.path.exists(base_path_no_group):
            process_fuzzing_data(base_path_no_group)
        else:
            for group_index in range(5):  # Loop through group_0 to group_4
                base_path_with_group = f'{home_path}/{group_name}/{firmware_name}/group_{group_index}/{one_time}_fuzz'
                if os.path.exists(base_path_with_group):
                    process_fuzzing_data(base_path_with_group)
