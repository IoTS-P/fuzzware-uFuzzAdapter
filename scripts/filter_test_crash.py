import os
import json
import subprocess
import re
import argparse
from multiprocessing import Pool

def parse_and_filter_crash_contexts(file_path, target_pc, target_lr):
    """
    解析 filtered_crash_contexts.txt，筛选指定 PC 和 LR 的路径。
    """
    tasks = []
    with open(file_path, 'r') as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) < 3:
                continue
            pc = parts[1]
            lr = parts[2]
            paths = parts[3:]
            if pc == target_pc and lr == target_lr:
                tasks.extend(paths)
    return tasks

def run_fuzzware_test(crash_path, config_dir, fuzzware_version='/home/n0vic3/.virtualenvs/fuzzware_ufuzzadapter/bin/fuzzware'):
    """
    对单个路径运行 fuzzware 命令，返回是否有效、路径和最后一行输出，并保存输出到文件。
    """
    print(f"正在执行: {crash_path}")  # 输出正在执行的任务名称
    command = f'{fuzzware_version} emu -M -v -d -t -c {config_dir} {crash_path}'
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=os.path.dirname(crash_path))
        output, error = process.communicate()
        full_output = output.decode('utf-8') + error.decode('utf-8')
        last_line = full_output.strip().split('\n')[-1] if full_output.strip() else "无输出"  # 提取最后一行
        
        # 保存输出到文件
        output_dir = os.path.join(os.path.dirname(crash_path), '..', '..', 'outputs')  # 假设在项目根目录的 outputs/
        os.makedirs(output_dir, exist_ok=True)
        basename = os.path.basename(crash_path).replace(':', '_').replace(',', '_')  # 替换特殊字符
        output_file = os.path.join(output_dir, f"output_{basename}.txt")
        with open(output_file, 'w') as f:
            f.write(full_output)
        print(f"输出保存到: {output_file}")
        
        if "Exited without crash" in full_output:
            return False, crash_path, last_line
        return True, crash_path, last_line
    except Exception as e:
        last_line = str(e)
        return False, crash_path, last_line

def get_valid_crashes(tasks, config_dir, fuzzware_version='/home/n0vic3/.virtualenvs/fuzzware_ufuzzadapter/bin/fuzzware'):
    """
    使用进程池并行测试路径，返回所有结果列表 (is_valid, path, last_line)。
    """
    with Pool(processes=128) as pool:  # 类似 sort_crash_and_count.py
        results = pool.starmap(run_fuzzware_test, [(task, config_dir, fuzzware_version) for task in tasks])
    return results

def main():
    parser = argparse.ArgumentParser(description="筛选并测试特定 PC LR 的崩溃用例，仿照 sort_crash_and_count.py")
    parser.add_argument('--folder', required=True, help="项目文件夹路径 (e.g., /home/n0vic3/fuzzers/fuzzware-examples/Fuzzware_CVE/Bootstrap_SPI/0420_adapter_1)")
    parser.add_argument('--pc', required=True, help="目标 PC 值 (e.g., 0x0800ab42)")
    parser.add_argument('--lr', required=True, help="目标 LR 值 (e.g., 0x08001cc7)")
    parser.add_argument('--output_file', default='valid_crashes.txt', help="输出文件路径")
    parser.add_argument('--fuzzware_version', default='/home/n0vic3/.virtualenvs/fuzzware_ufuzzadapter/bin/fuzzware', help="fuzzware 路径")
    args = parser.parse_args()
    
    # 自动构造文件路径
    input_file = os.path.join(args.folder, 'stats', 'filtered_crash_contexts.txt')
    config_file = os.path.join(args.folder, '..', 'config.yml')
    
    if not os.path.exists(input_file):
        print(f"错误: 输入文件不存在 {input_file}")
        return
    if not os.path.exists(config_file):
        print(f"错误: 配置文件不存在 {config_file}")
        return
    
    # 筛选任务
    tasks = parse_and_filter_crash_contexts(input_file, args.pc, args.lr)
    print(f"筛选出 {len(tasks)} 个测试用例")
    
    # 补全路径
    full_tasks = [os.path.join(args.folder, task) for task in tasks]
    
    # 并行测试
    results = get_valid_crashes(full_tasks, config_file, args.fuzzware_version)
    
    # 检测是否全部检测：检查结果数量与任务数量
    if len(results) != len(tasks):
        print(f"警告: 结果数量 ({len(results)}) 与任务数量 ({len(tasks)}) 不匹配，可能有任务未处理")
    else:
        print("所有测试用例均已检测")
    
    # 输出每个任务的结果
    valid_crashes = []
    for is_valid, path, last_line in results:
        status = "有效" if is_valid else "无效 (Exited without crash)"
        print(f"结果: {path} - {status} - 最后一行: {last_line}")
        if is_valid:
            valid_crashes.append(path)
    
    # 统计
    total = len(tasks)
    valid_count = len(valid_crashes)
    invalid_count = total - valid_count
    print(f"总测试用例: {total}")
    print(f"有效崩溃: {valid_count}")
    print(f"无效崩溃 (Exited without crash): {invalid_count}")
    
    # 写入文件
    output_path = os.path.join(args.folder, args.output_file)
    with open(output_path, 'w') as f:
        for path in valid_crashes:
            f.write(path + '\n')
    
    print(f"结果写入: {output_path}")

if __name__ == '__main__':
    main()