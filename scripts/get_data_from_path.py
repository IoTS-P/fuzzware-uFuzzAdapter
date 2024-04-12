import re

def extract_coverage_data(log_path):
    with open(log_path, 'r') as file:
        lines = file.readlines()
    last_coverage_line = [line for line in lines if "Basic block coverage" in line][-1]
    coverage_percentage = re.search(r"(\d+\.\d+)%", last_coverage_line).group(1)
    basic_blocks = re.search(r"\b\d+\b", last_coverage_line).group(0)

    return coverage_percentage,basic_blocks

def extract_crash_data(crash_path):
    with open(crash_path, 'r') as file:
        lines = file.readlines()
    if len(lines) == 0:
        first_crash_time = 0
    else:
        first_crash_time = lines[0].split("\t")[0]
    
    unique_crashes = len(lines)
    return first_crash_time, unique_crashes

# Replace the paths with your actual file paths
base_path = "/home/n0vic3/fuzzers/fuzzware/examples/other_target_orig/3319-30/fuzzware-project"
coverage_log_path = base_path+"/logs/pipeline.log"
crash_log_path = base_path+"/stats/crash_creation_timings.txt"

coverage_percentage,basic_blocks = extract_coverage_data(coverage_log_path)
first_crash_time, unique_crashes = extract_crash_data(crash_log_path)
print(f"Basic blocks: {basic_blocks}")
print(f"Coverage percentage: {coverage_percentage}%")
print(f"First crash time: {first_crash_time}")
print(f"Unique crashes: {unique_crashes}")
