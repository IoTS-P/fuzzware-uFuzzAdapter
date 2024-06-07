import os

def find_execs_per_sec(base_path):
    result = []
    
    for root, dirs, files in os.walk(base_path):
        if 'fuzzer_stats' in files:
            file_path = os.path.join(root, 'fuzzer_stats')
            with open(file_path, 'r') as f:
                for line in f:
                    if line.startswith('execs_per_sec'):
                        execs_per_sec = float(line.split(':')[1].strip())
                        result.append((root, execs_per_sec))
                        break
    return result

def calculate_average(values):
    filtered_values = [value for value in values if value <= 20000]
    if not filtered_values:
        return 0
    return sum(filtered_values) / len(filtered_values)

base_path = '/home/n0vic3/fuzzers/fuzzware/examples/uEmu/uEmu.GPSTracker'
execs_per_sec_values = find_execs_per_sec(base_path)

for folder, value in execs_per_sec_values:
    print(f'Folder: {folder}, execs_per_sec: {value}')

average_execs_per_sec = calculate_average([value for _, value in execs_per_sec_values])
print(f'Average execs_per_sec (excluding values > 20000): {average_execs_per_sec}')
print(f'sum execs: {average_execs_per_sec*86400}')