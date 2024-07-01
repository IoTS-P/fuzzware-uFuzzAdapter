import os
import subprocess
ADPATER = True
def run_commands(file_path):
    # 读取文件内容
    base_directory = os.path.dirname(os.path.dirname(file_path))
    with open(file_path, 'r') as file:
        lines = file.readlines()

    for line in lines:
        parts = line.strip().split()
        main_folder = parts[1].split('/')[0]
        sub_folder = "/".join(parts[1].split('/')[1:])
        crash_info = sub_folder.split('/')[-1]
        
        # 提取crash文件的id
        crash_id = crash_info.split(',')[0].split(':')[1]
        
        # 构建输出文件路径
        output_file = os.path.join(base_directory, main_folder,"crash_info",f'{crash_id}.log')
        if not os.path.exists(output_file):
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
        # 构建zsh命令
        if ADPATER:
            command = f"cd {base_directory}/{main_folder} && source /usr/share/virtualenvwrapper/virtualenvwrapper.sh && workon fuzzware_ufuzzadapter && fuzzware emu -M -v -t {sub_folder} > {output_file}"
        else:
            command = f"cd {base_directory}/{main_folder} && source /usr/share/virtualenvwrapper/virtualenvwrapper.sh && workon fuzzware && fuzzware emu -M -v -t {sub_folder} > {output_file}"
        print(command)
        # 使用subprocess模块来执行命令
        subprocess.run(command, shell=True, executable='/bin/zsh', check=True)

# 使用文件路径来调用函数
file_path = '/home/n0vic3/fuzzers/fuzzware-examples/month6_adapter/CVE-2023-00000_1/0618_fuzz/stats/crash_creation_timings.txt'  # 将此处替换为你的文件路径
run_commands(file_path)
