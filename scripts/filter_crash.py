import json
import os
import argparse  # 用于命令行参数（可选）

def process_folder(folder_path):
    """
    处理单个文件夹：从 stats/ 读取文件，筛掉 crash，保存结果。
    """
    stats_dir = os.path.join(folder_path, 'stats')
    sort_pc_file = os.path.join(stats_dir, 'sort_pc_true_crash.txt')
    crash_contexts_file = os.path.join(stats_dir, 'crash_contexts.txt')
    output_file = os.path.join(stats_dir, 'filtered_crash_contexts.txt')
    
    # 检查文件是否存在
    if not os.path.exists(sort_pc_file):
        print(f"警告: {sort_pc_file} 不存在，跳过 {folder_path}")
        return
    if not os.path.exists(crash_contexts_file):
        print(f"警告: {crash_contexts_file} 不存在，跳过 {folder_path}")
        return
    
    try:
        # 步骤1: 读取 sort_pc_true_crash.txt，提取 crash 路径列表（第二行）
        with open(sort_pc_file, 'r') as f:
            lines = f.readlines()
            if len(lines) < 2:
                print(f"警告: {sort_pc_file} 格式错误，跳过 {folder_path}")
                return
            crash_list = json.loads(lines[1].strip())
        
        # 将 crash 列表转为 set 以便快速查找
        crash_set = set(crash_list)
        
        # 步骤2: 读取 crash_contexts.txt，筛掉匹配的 crash
        filtered_lines = []
        with open(crash_contexts_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):  # 跳过空行和注释行
                    continue
                parts = line.split()
                if len(parts) < 4:  # 至少需要 num pc lr 和至少一个路径
                    continue
                pc = parts[1]
                lr = parts[2]
                crash_paths = parts[3:]  # 剩余的是 crash 路径
                
                # 筛掉在 crash_set 中的路径
                remaining_paths = [path for path in crash_paths if path not in crash_set]
                
                # 如果有剩余路径，重新构造行，更新 num 为 len(remaining_paths)
                if remaining_paths:
                    new_num = len(remaining_paths)
                    new_line = f"{new_num} {pc} {lr} {' '.join(remaining_paths)}\n"
                    filtered_lines.append(new_line)
        
        # 步骤3: 写入输出文件
        with open(output_file, 'w') as f:
            f.writelines(filtered_lines)
        
        print(f"完成: {folder_path} -> {output_file} (筛掉 {len(crash_set)} 个路径)")
    
    except Exception as e:
        print(f"错误: 处理 {folder_path} 时出错: {e}")

def main():
    # 示例文件夹路径列表（替换为您的实际路径）
    folder_paths = [
        '/home/n0vic3/fuzzers/fuzzware-examples/new_targets_2025/BLE-HCI/0420_adapter_1',
        '/home/n0vic3/fuzzers/fuzzware-examples/new_targets_2025/BLE-HCI/0420_adapter_2',
        '/home/n0vic3/fuzzers/fuzzware-examples/new_targets_2025/BLE-HCI/0420_adapter_3',
        '/home/n0vic3/fuzzers/fuzzware-examples/new_targets_2025/BLE-HCI/0420_baseline_1',
        '/home/n0vic3/fuzzers/fuzzware-examples/new_targets_2025/BLE-HCI/0420_baseline_2',
        '/home/n0vic3/fuzzers/fuzzware-examples/new_targets_2025/BLE-HCI/0420_baseline_3',
        # 添加更多文件夹...
    ]
    
    # 可选：使用 argparse 从命令行获取路径
    # parser = argparse.ArgumentParser(description="筛掉 crash 脚本")
    # parser.add_argument('--folders', nargs='+', required=True, help="文件夹路径列表")
    # args = parser.parse_args()
    # folder_paths = args.folders
    
    for folder in folder_paths:
        process_folder(folder)
    
    print("所有文件夹处理完成。")

if __name__ == '__main__':
    main()