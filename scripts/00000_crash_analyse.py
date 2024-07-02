import os
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

ADPATER = False

def run_command(command):
    try:
        subprocess.run(command, shell=True, executable='/bin/zsh', check=True)
    except subprocess.CalledProcessError as e:
        print(f"Command failed with error: {e}")

def run_commands(file_path):
    # 读取文件内容
    base_directory = os.path.dirname(os.path.dirname(file_path))
    with open(file_path, 'r') as file:
        lines = file.readlines()

    commands = []

    for line in lines:
        parts = line.strip().split()
        main_folder = parts[1].split('/')[0]
        sub_folder = "/".join(parts[1].split('/')[1:])
        crash_info = sub_folder.split('/')[-1]
        
        # 提取crash文件的id
        crash_id = crash_info.split(',')[0].split(':')[1]
        
        # 构建输出文件路径
        output_file = os.path.join(base_directory, main_folder, "crash_info", f'{crash_id}.log')
        if not os.path.exists(output_file):
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
        # 构建zsh命令
        if ADPATER:
            command = f"cd {base_directory}/{main_folder} && source /usr/share/virtualenvwrapper/virtualenvwrapper.sh && workon fuzzware_ufuzzadapter && fuzzware emu -M -v -t {sub_folder} > {output_file}"
        else:
            command = f"cd {base_directory}/{main_folder} && source /usr/share/virtualenvwrapper/virtualenvwrapper.sh && workon fuzzware && fuzzware emu -M -v -t {sub_folder} > {output_file}"
        print(command)
        commands.append(command)
    
    # 使用ThreadPoolExecutor来并行执行命令
    with ThreadPoolExecutor() as executor:
        future_to_command = {executor.submit(run_command, cmd): cmd for cmd in commands}
        for future in as_completed(future_to_command):
            cmd = future_to_command[future]
            try:
                future.result()
            except Exception as exc:
                print(f"{cmd} generated an exception: {exc}")

# 使用文件路径来调用函数
file_path = '/home/n0vic3/fuzzers/fuzzware/examples/month6_original/riot-CVE-2023-24817_18_21_26-33974_5/group_3/0701_fuzz/stats/crash_creation_timings.txt'  # 将此处替换为你的文件路径
run_commands(file_path)
