import os, subprocess 

python_file = "/home/n0vic3/fuzzers/fuzzware-uFuzzAdapter/scripts/gather_bug_detection_timings.py"
basedir = "/home/n0vic3/fuzzers/fuzzware/examples/other_target_mmio_seedbin/CVE-2021-3329"
projdir_name_prefix = "0420_fuzz"
ADAPTER = False
if ADAPTER:
    fuzzware_version = "/home/n0vic3/.virtualenvs/fuzzware_ufuzzadapter/bin/activate"
    python_path = "/home/n0vic3/.virtualenvs/fuzzware_ufuzzadapter/bin/python"
else:
    fuzzware_version = "/home/n0vic3/.virtualenvs/fuzzware/bin/activate"
    python_path = "/home/n0vic3/.virtualenvs/fuzzware/bin/python"
outdir = os.path.join(basedir,projdir_name_prefix,"stats")
source_command = f"source {fuzzware_version} "
cmd = f" {python_path} {python_file} --basedir {basedir} --projdir_name_prefix {projdir_name_prefix} --outdir {outdir} -n 128"
# 使用 subprocess.run 执行命令
try:
    print("执行命令:", cmd)
    subprocess.run(source_command, shell=True, check=True,executable="/bin/bash")
    result = subprocess.run(cmd, shell=True, check=True, text=True, capture_output=True,executable="/bin/bash")
    print("输出:", result.stdout)
    print("错误:", result.stderr)
except subprocess.CalledProcessError as e:
    print("命令执行失败:", e)

print()