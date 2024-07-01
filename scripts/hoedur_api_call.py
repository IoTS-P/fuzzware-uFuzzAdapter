import os, subprocess 

python_file = "/home/n0vic3/fuzzers/fuzzware-uFuzzAdapter/scripts/gather_bug_detection_timings.py"
firmware_name = "CVE-2023-00000"
firmware_name += "_0"
basedir = ""
projdir_name_prefix = "0618_fuzz"
ADAPTER = False
if ADAPTER:
    basedir = os.path.join("/home/n0vic3/fuzzers/fuzzware-examples/month6_adapter/",firmware_name)
else:
    basedir = os.path.join("/home/n0vic3/fuzzers/fuzzware/examples/month6_original/",firmware_name)
    
def post_exec_pushplus(title,content):

    import requests
    
    content = len(content)
    res = requests.get(f"http://www.pushplus.plus/send?token=784df1822b964c4a9dd13e1513ca37f3&title={title}&content={content}&template=html")
    print(res.content)

if ADAPTER:
    fuzzware_version = "/home/n0vic3/.virtualenvs/fuzzware_ufuzzadapter/bin/activate"
    python_path = "/home/n0vic3/.virtualenvs/fuzzware_ufuzzadapter/bin/python"
    json_put_cmd = "json_file=$(ls *.json | head -n 1) && for dir in *_fuzz/; do for subdir in \"$dir\"main0*/; do if [[ -d \"$subdir\" ]]; then cp \"$json_file\" \"$subdir\"; fi; done; done"
    subprocess.run(json_put_cmd, shell=True,cwd=basedir,executable="/bin/bash")
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
    post_exec_pushplus("fuzzware",basedir)
    print("输出:", result.stdout)
    print("错误:", result.stderr)
except subprocess.CalledProcessError as e:
    print("命令执行失败:", e)

print()