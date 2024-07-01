# 定义输入文件和输出文件的路径
file1_path = '/home/n0vic3/fuzzers/fuzzware/examples/month6_original/CVE-2023-00000_0/0618_fuzz/logs/new_basic_blocks.log'
file2_path = '/home/n0vic3/fuzzers/fuzzware-examples/month6_adapter/CVE-2023-00000_1/0618_fuzz/logs/new_basic_blocks.log'
output_path = '/tmp/missing_basic_blocks.txt'

# 读取文件中的基本块地址
with open(file1_path, 'r') as file:
    basic_blocks_file1 = set(file.read().splitlines())

with open(file2_path, 'r') as file:
    basic_blocks_file2 = set(file.read().splitlines())

# 找出 file1 中存在但 file2 中缺少的基本块
file1_missing_blocks = sorted(basic_blocks_file1 - basic_blocks_file2)

# 找出 file2 中存在但 file1 中缺少的基本块
file2_missing_blocks = sorted(basic_blocks_file2 - basic_blocks_file1)

# 将缺少的基本块写入输出文件
with open(output_path, 'w') as file:
    file.write('In file1 but not in file2:\n')
    for block in file1_missing_blocks:
        file.write(block + '\n')
    file.write('\n')
    
    file.write('In file2 but not in file1:\n')
    for block in file2_missing_blocks:
        file.write(block + '\n')

print(f'分析结果已写入 {output_path}')
