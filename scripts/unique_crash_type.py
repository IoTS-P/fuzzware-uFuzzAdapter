import os
import argparse

def parse_file(file_path):
    """
    解析单个 filtered_crash_contexts.txt 文件，提取唯一的 (pc, lr) 对。
    """
    pc_lr_set = set()
    if not os.path.exists(file_path):
        print(f"警告: {file_path} 不存在，跳过")
        return pc_lr_set
    
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):  # 跳过空行和注释行
                    continue
                parts = line.split()
                if len(parts) >= 3:  # 至少有 num pc lr
                    pc = parts[1]
                    lr = parts[2]
                    pc_lr_set.add((pc, lr))  # 添加 (pc, lr) 对到集合
    except Exception as e:
        print(f"错误: 解析 {file_path} 时出错: {e}")
    
    return pc_lr_set

def main():
    parser = argparse.ArgumentParser(description="比较多个文件夹下的 filtered_crash_contexts.txt，统计不同的 pc lr 对数量")
    parser.add_argument('--folders', nargs='+', required=True, help="文件夹路径列表")
    args = parser.parse_args()
    
    all_pc_lr = set()  # 全局集合，存储所有唯一的 (pc, lr) 对
    
    for folder in args.folders:
        file_path = os.path.join(folder, 'stats', 'filtered_crash_contexts.txt')
        pc_lr_set = parse_file(file_path)
        all_pc_lr.update(pc_lr_set)  # 合并到全局集合
    
    print(f"总共不同的 crash 种类（pc lr 对）数量: {len(all_pc_lr)}")
    
    # 保存独特的种类到文件，第一行添加标题
    with open('unique_pc_lr.txt', 'w') as f:
        f.write("# pc lr\n")  # 添加标题行
        for pc, lr in sorted(all_pc_lr):
            f.write(f"{pc} {lr}\n")
    print("独特的 pc lr 对已保存到 unique_pc_lr.txt")

if __name__ == '__main__':
    main()