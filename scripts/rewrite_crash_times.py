import os
crash_file_path = '/home/n0vic3/fuzzers/fuzzware/examples/P2IM/PLC/fuzzware-project/stats/crash_creation_timings.txt'
output_dir="/home/n0vic3/fuzzers/fuzzware/examples/P2IM/PLC/POC/true_crash" # 输出目录，需要替换为实际路径
true_crash_file_path = '/home/n0vic3/fuzzers/fuzzware/examples/P2IM/PLC/fuzzware-project/stats/crash_creation_timings_tututututut.txt'

# 获取当前目录下所有文件
all_files = os.listdir(output_dir)
new_all_files = []
for file in all_files:
    new_all_files.append(file.strip("_output.txt"))
all_files = new_all_files
# 读取crash_creation_timings.txt文件并提取出所有的crash文件名
all_crash_files = set()
with open(true_crash_file_path, 'w') as ff:
    with open(crash_file_path, 'r') as f:
        for line in f:
            parts = line.split()
            if len(parts) > 1:
                # 提取文件名并添加到集合中
                crash_file_name = parts[1].split('/')[-1]
                if crash_file_name in all_files:
                    ff.write(line)
                else:
                    print(crash_file_name)
                    # print(all_files)

f.close()
print(true_crash_file_path)
# # 检查每个真正的crash文件是否存在于当前目录的文件列表中
# for crash_file in all_crash_files:
#     # print(crash_file)
#     if crash_file in all_files:
#         # 如果文件存在，则读取并保存其内容
#         with open(crash_file, 'r') as file:
#             content = file.read()
#         # 保存内容到新文件，这里假设你想要保存到以'_true_crash.txt'结尾的文件
#         with open(crash_file + '_true_crash.txt', 'w') as file:
#             file.write(content)
