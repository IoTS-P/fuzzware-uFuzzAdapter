import re

def extract_coverage_data(log_path):
    with open(log_path, 'r') as file:
        lines = file.readlines()
    last_coverage_line = [line for line in lines if "Basic block coverage" in line][-1]
    coverage_percentage = re.search(r"(\d+\.\d+)%", last_coverage_line).group(1)
    return coverage_percentage

def extract_crash_data(crash_path):
    with open(crash_path, 'r') as file:
        lines = file.readlines()
    first_crash_time = lines[0].split("\t")[0]
    unique_crashes = len(lines)
    return first_crash_time, unique_crashes

# Replace the paths with your actual file paths
coverage_log_path = "/home/n0vic3/fuzzers/fuzzware/examples/P2IM/Gateway/0224_fuzz/logs/pipeline.log"
crash_log_path = "/home/n0vic3/fuzzers/fuzzware/examples/P2IM/Gateway/0224_fuzz/stats/crash_creation_timings.txt"

coverage_percentage = extract_coverage_data(coverage_log_path)
first_crash_time, unique_crashes = extract_crash_data(crash_log_path)

print(f"Coverage percentage: {coverage_percentage}%")
print(f"First crash time: {first_crash_time}")
print(f"Unique crashes: {unique_crashes}")
