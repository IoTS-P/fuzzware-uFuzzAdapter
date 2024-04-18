from subprocess import run
import os 
python_path = "/home/n0vic3/.virtualenvs/fuzzware/bin/python"
python_file = "/home/n0vic3/fuzzers/fuzzware-uFuzzAdapter/scripts/gather_bug_detection_timings.py"
basedir = "/home/n0vic3/fuzzers/fuzzware/examples/other_target_orig/CVE-2020-10064_inter"
projdir_name_prefix = "0409_fuzz"
outdir = os.path.join("/home/n0vic3/fuzzers/fuzzware/examples/other_target/CVE-2020-10064_inter",projdir_name_prefix,"stats")

cmd = f"{python_path} {python_file} --basedir {basedir} --projdir_name_prefix {projdir_name_prefix} --outdir {outdir} -n 32"
cmd = cmd.split()
print(cmd)
run(cmd)
