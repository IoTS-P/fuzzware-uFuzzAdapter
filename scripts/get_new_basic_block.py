import re,os

# 输入和输出文件路径
input_file_path = '/home/n0vic3/fuzzers/fuzzware/examples/month6_original/CVE-2023-00000_1/0618_fuzz/logs/pipeline.log'
output_file_path = os.path.join(os.path.dirname(input_file_path), 'new_basic_blocks.log')

# 正则表达式来匹配 "New basic block" 行并提取数值部分
pattern = re.compile(r'\[.*\] pipeline\.py - New basic block: (0x[0-9a-fA-F]+)')

# 读取日志文件并提取匹配的行中的数值部分
with open(input_file_path, 'r') as file:
    lines = file.readlines()

new_basic_block_values = [pattern.search(line).group(1) + '\n' for line in lines if pattern.search(line)]

# 将提取的数值部分写入新的文件
with open(output_file_path, 'w') as file:
    file.writelines(new_basic_block_values)

print(f'提取完成，结果保存在 {output_file_path}')

