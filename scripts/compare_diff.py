import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

def extract_info_from_log(log_file_path):
    with open(log_file_path, 'r') as file:
        lines = file.readlines()
    
    function_call_pattern = re.compile(r'Calling function: .+ from .+ \(PC=0x[0-9a-fA-F]+, LR=0x[0-9a-fA-F]+\)')
    
    function_call = None
    
    for line in lines:
        if function_call_pattern.search(line):
            function_call = line.strip()
    
    return function_call

def process_log_file(log_file_path):
    print(f"Processing {log_file_path}")
    file_name = os.path.basename(log_file_path)
    function_call = extract_info_from_log(log_file_path)
    if function_call:
        return (file_name, function_call)
    return None

def compare_entries(entry1, entry2):
    function_call1 = entry1[1]
    function_call2 = entry2[1]
    
    return function_call1 == function_call2

def process_all_logs(directory_path, output_file_path, max_workers=4):
    log_files = []
    for root, _, files in os.walk(directory_path):
        for file in files:
            if file.endswith('.log'):
                log_files.append(os.path.join(root, file))

    entries = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process_log_file, log_file): log_file for log_file in log_files}
        for future in as_completed(futures):
            result = future.result()
            if result:
                entries.append(result)
    
    unique_entries = []
    similarity_counts = []
    
    for entry in entries:
        is_unique = True
        for unique_entry in unique_entries:
            if compare_entries(entry, unique_entry):
                similarity_counts[unique_entries.index(unique_entry)] += 1
                is_unique = False
                break
        
        if is_unique:
            unique_entries.append(entry)
            similarity_counts.append(1)
    
    with open(output_file_path, 'w') as output_file:
        for i, (file_name, function_call) in enumerate(unique_entries):
            output_file.write(f"File: {file_name}\n{function_call}\n")
            output_file.write(f"Similar files count: {similarity_counts[i]}\n\n")
    
    print(f"Processed {len(unique_entries)} unique entries.")

# 使用指定的日志目录和输出文件路径调用函数
log_directory = '/home/n0vic3/fuzzers/fuzzware-examples/month6_adapter/CVE-2023-00000_1/0618_fuzz/main017/crash_info'  # 替换为日志文件所在的目录路径
output_file = os.path.join(os.path.dirname(log_directory),"unique_entries.txt")  

process_all_logs(log_directory, output_file)
print(output_file)
