import os, json, subprocess, re
import time
from plot_bb_config import firmware_crashpc
from multiprocessing import Pool

# Provided real crash address
firmware_name = "CVE-2023-00000"
firmware_name += ""
time_list = ["0707"]
ADAPTER = True
FORCE_GENSTATS = True
DATA_PATH = False
PROCESSORS = 100

if ADAPTER:
    fuzzware_version = "/home/n0vic3/.virtualenvs/fuzzware_ufuzzadapter/bin/fuzzware"
    if DATA_PATH:
        home_path = "/data/fuzzware_tmp_dir/adapter"
    else:
        home_path = "/home/n0vic3/fuzzers/fuzzware-examples"
    group_name = "month6_adapter"
else:
    fuzzware_version = "/home/n0vic3/.virtualenvs/fuzzware/bin/fuzzware"
    if DATA_PATH:
        home_path = "/data/fuzzware_tmp_dir/original"
    else:
        home_path = "/home/n0vic3/fuzzers/fuzzware/examples"
    group_name = "month6_original"

def is_real_crash(output):
    cve_result = []
    seen_cves = set()
    # print(output)
    for line in output.split('\n'):
        if "Heureka" in line:
            cve = line.split(' ')[-1]
            if cve not in seen_cves:
                cve_result.append(cve)
                seen_cves.add(cve)
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
        json_put_cmd = "json_file=$(ls *.json | head -n 1) && for dir in *_fuzz/; do for subdir in \"$dir\"main0*/; do if [[ -d \"$subdir\" ]]; then cp \"$json_file\" \"$subdir\"; fi; done; done"
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
        crash_path = components[-1]  # Get the crash path from each line
        tasks.append((crash_path, original_file_path, fuzzware_version))

    # Use a process pool to process tasks in batches
    with Pool(processes=PROCESSORS) as pool:  # Set the number of processes based on CPU cores
        crash_timing_worker_results = pool.starmap(process_path, tasks)

    # Collecting results
    real_crash = []
    false_crash = []
    crash_results = {}
    cve_files = {}  # Dictionary to hold CVE type and corresponding files

    for async_result, crash_path in crash_timing_worker_results:
        result, group = async_result[0], async_result[1]
        if result:
            print(f"real crash: {crash_path}")
            real_crash.append(crash_path)
            for g in group:
                crash_results[g] = crash_results.get(g, 0) + 1
                if g not in cve_files:
                    cve_files[g] = []
                cve_files[g].append(crash_path)
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
    
    # Output a file corresponding to a specific CVE type
    cve_write_path = write_path.replace('true_crash.txt', f'{firmware_name}_crash_results.txt')
    with open(cve_write_path, 'w') as cve_file:
        cve_file.write(f"Firmware: {firmware_name}\n")
        cve_file.write(f"num of crashes:{len(real_crash)}\n")
        cve_file.write(json.dumps(real_crash))
        # cve_file.write('\n')
        # cve_file.write(f"num of false crashes:{len(false_crash)}\n")
        # cve_file.write(json.dumps(false_crash))
        cve_file.write('\n')
        cve_file.write(json.dumps(crash_results))
        cve_file.write('\n')
        for cve, files in cve_files.items():
            cve_file.write(f"{cve}: {len(files)} crashes\n")
            cve_file.write(json.dumps(files))
            cve_file.write('\n--------------------------------------------------------------------------------\n')
    print('CVE-specific results written to:', cve_write_path)

    # post_exec_pushplus(f"crash results: {firmware_name}", f"num of crashes:{len(real_crash)}\nnum of false crashes:{len(false_crash)}")

def post_exec_pushplus(title, content):
    import requests
    res = requests.get(f"http://www.pushplus.plus/send?token=784df1822b964c4a9dd13e1513ca37f3&title={title}&content={content}&template=html")
    print(res.content)

if __name__ == '__main__':
    sum_results = {}
    for one_time in time_list:
        base_path_no_group = f'{home_path}/{group_name}/{firmware_name}/{one_time}_fuzz'
        # print(base_path_no_group)
        if os.path.exists(base_path_no_group):
            results = get_results(base_path_no_group)
            print(results)
            sum_results[one_time] = results
        else:
            for group_index in range(5):  # Loop through group_0 to group_4
                base_path_with_group = f'{home_path}/{group_name}/{firmware_name}/group_{group_index}/{one_time}_fuzz'
                # print(base_path_with_group)
                if os.path.exists(base_path_with_group):
                    results = get_results(base_path_with_group)
                    print(results)
                    sum_results[one_time] = results
    # for group_index in range(5):  # Loop through group_0 to group_4
    #     for one_time in time_list:
    #         new_file_path = f'{home_path}/{group_name}/{firmware_name}/group_{group_index}/{one_time}_fuzz'
    #         if not os.path.exists(os.path.join(new_file_path, "stats", "true_crash.txt")) or FORCE_GENSTATS:
    #             results = get_results(new_file_path)
    #             print(results)
    #             sum_results[one_time] = results
    #         else:
    #             with open(os.path.join(new_file_path, "stats", "true_crash.txt"), 'r') as file:
    #                 lines = file.readlines()
    #             print(f"new_file_path: {new_file_path}")
    #             print(lines[0].strip("\n"))
    #             print(lines[4])
    #             print("--------------------------------------------------------------------------------")
    print("all results: ", sum_results)
    post_exec_pushplus("hook_fuzzware_bugs_deal.py", "all results: sum_results")
