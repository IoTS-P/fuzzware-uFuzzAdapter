import os,subprocess,threading
full_path = os.path.expanduser("~")  # 获取用户的home目录
my_debug_log = print
def run_ghidra(binary, port):
    def run_command():
        # Create ghidra project
        file_name = os.path.basename(binary)
        project_path = os.path.join(full_path, 'ghidra_project')
        os.makedirs(project_path, exist_ok=True)        
        
        my_debug_log("Current port is: {}".format(port))
        
        # Check if another program is occupying the port
        pid = -1
        need_kill = True
        cmd1 = "netstat -tulnp | grep :{} | awk '{{print $7}}'".format(port)
        result1 = subprocess.run(cmd1, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if result1.returncode != 0:
            print(f"[-] Error when run_ghidra: {result1.stderr}")
            exit(-1)

        # Get PID and ProgramName, the stdout is like '228227/java\n'
        if result1.stdout != '':
            pid, program_name = result1.stdout.strip().split('/')
            my_debug_log("current pid = {}".format(pid))
            # Check if the program is java
            if program_name != 'java':
                print(f"[*] One program {program_name} occupies the port {port}, please check!")
                kill_program = input("Do you want to kill the program? (Y/n)")
                if kill_program == 'n':
                    print("[!] Please kill the program or change the port and try again!")
                    exit(0)
            # only if the program is java, don't kill it
            else:
                need_kill = True
        
        # Kill the program if necessary
        if pid != -1 and need_kill:
            print("current pid is ", pid)
            my_debug_log("current pid = {}".format(pid))
            cmd2 = "kill -9 {}".format(pid)
            result2 = subprocess.run(cmd2, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            my_debug_log(result2.stdout)
            my_debug_log(result2.stderr)
            if result2.returncode == 0:
                print("kill success")
                my_debug_log("kill success")
            else:
                print("kill failed")
                my_debug_log("kill failed")

        if need_kill == False:
            print("[+] Ghidra is already running, don't need to start it again.")
            return
        
        # Run Ghidra if necessary
        my_debug_log("run new ghidra server")
        delete_ghidra_project_lock_file()
        now_file_path = os.path.dirname(os.path.abspath(__file__))
        
        ghidra_script_path = os.path.join(now_file_path, 'run_ghidra.py')
        analyze_command = [
            os.path.join(full_path, 'ghidra', 'support', 'analyzeHeadless'),
            project_path,
            file_name[:-4],  # Assuming you want to strip the last 4 characters from the file name
            "-import",
            binary,
            "-overwrite",
            "-postScript",
            ghidra_script_path,
            port,
        ]
        
        cmd = " ".join(map(str, analyze_command))
        my_debug_log("ghidra cmd: %s" % cmd)
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8')

 
    command_thread = threading.Thread(target=run_command)
    command_thread.setDaemon(True) # set the thread as daemon thread
    command_thread.start()
    command_thread.join(15)


def delete_ghidra_project_lock_file():
    for root, dirs, files in os.walk(os.path.join(full_path, 'ghidra_project')):
        for file in files:
            if ".lock" in file:
                os.remove(os.path.join(root, file))