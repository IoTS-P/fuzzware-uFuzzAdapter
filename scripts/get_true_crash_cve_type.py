import ast
import os
from collections import defaultdict

def parse_crash_file(file_path):
    crash_map = defaultdict(list)
    try:
        with open(file_path, 'r') as file:
            for line in file:
                parts = line.strip().split()
                if len(parts) < 4:
                    continue
                
                pc_lr = (parts[1], parts[2])
                crash_files = parts[3:]
                
                for crash_file in crash_files:
                    crash_map[pc_lr].append(crash_file)
                
        return crash_map
    except FileNotFoundError:
        return None

def parse_list_from_string(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
        
        if len(lines) < 2:
            raise ValueError("File does not contain enough lines.")
        
        # The second line is expected to be the string representation of the list
        second_line = lines[1].strip()
        
        # Convert the string representation to an actual list
        crash_list = ast.literal_eval(second_line)
        
        return crash_list

def save_results(crash_map, crash_list, output_path):
    grouped_map = defaultdict(list)
    
    for crash in crash_list:
        for pc_lr, files in crash_map.items():
            if crash in files:
                grouped_map[pc_lr].append(crash)
                break
    
    with open(output_path, 'w') as file:
        for pc_lr, crashes in grouped_map.items():
            pc_lr_str = f"{pc_lr[0]} {pc_lr[1]}"
            crashes_str = ' '.join(crashes)
            line = f"{pc_lr_str} {len(crashes)}: {crashes_str}\n"
            file.write(line)


time_list = ["0410"]
ADAPTER = True
which_fuzzware = "adapter" if ADAPTER else "original"
# Usage example
for group_index in range(5):  # Loop through group_0 to group_4
    for one_time in time_list:
        base_path = f"/home/n0vic3/fuzzers/fuzzware/examples/month6_original/CVE-2023-00000/group_{group_index}/{one_time}_fuzz/stats"
        crash_contexts_path = os.path.join(base_path, 'crash_contexts.txt')
        true_crash_file_path = os.path.join(base_path, "true_crash.txt")
        output_file_path = os.path.join(base_path, "crash_output.txt")

        # Parse the crash context file and the true crash file
        crash_map = parse_crash_file(crash_contexts_path)
        if crash_map is None:
            print(f"Error: Could not parse the crash context file at {crash_contexts_path}")
            continue
        elif len(crash_map) == 1:
            print(f"no crash {crash_contexts_path}")
            continue

        crash_list = parse_list_from_string(true_crash_file_path)

        # Save the results to the output file
        save_results(crash_map, crash_list, output_file_path)
        f = open(output_file_path, "r")
        print(len(f.readlines()))
        print(f"Results saved to {output_file_path}")
