# usage: ghidra client, headless_ghidra.py is used to run ghidra headless

from .. import globs
import os,re,subprocess,threading

from time import time,sleep
from ..util import my_debug_log
import json

# my_debug_log = print
full_path = os.path.expanduser("~")  # 获取用户的home目录
import socket

def client_send_message(message,port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    count = 0
    server_address = ('localhost', port)
    while True:
        try:    
        # 连接服务器
            res = -1
            while True:
                try:
                    # client_socket.connect(server_address)
                    res = client_socket.connect_ex(server_address)
                    if res == 0:
                        my_debug_log("Connection successful!")
                        break
                    else:
                        my_debug_log("server may not ready yet,wait and try again")
                        sleep(1)
                        continue
                except socket.error as e:
                    my_debug_log("Connection error 1:{}".format(e))
                    pass
            if res == 0:
                break
            # client_socket.connect(server_address)
            # print("Connection successful,test if it is the target server:")
            # client_socket.sendall(shm_name.encode())
            # message = cleint_socket.recv(1024).decode()
            # if message == "fuzz server error!":
            #     client_socket.close()
            #     port += 1
            #     count += 1
            #     #if try after 200 times,still can't connect,then return None
            #     if count >= 200:
            #         my_debug_log("can't connect to the ghidra server more than 200 times!")
            #         return None                 
            # elif message == "authentication success!":
            #     my_debug_log("current port connected :{}".format(port))
            #     break

        except socket.error as e:
            my_debug_log("Connection error 2:{}".format(e))
            pass
            # my_debug_log("port %d is unconnected" % port)
            # port += 1
            # count += 1
            # #if try after 200 times,still can't connect,then return None
            # if count >= 200:
            #     my_debug_log("can't connect to the ghidra server more than 200 times!")
            #     return None
    try:
        client_socket.sendall(message.encode())
        
        response = client_socket.recv(8192)
        response = response.decode()
        print('get receive:', response)
        if response:
            return json.loads(response)
        else:
            return None
    except socket.error as e:
        print('Communicate Error:',e)
    finally:
        client_socket.close()


def run_ghidra(binary, port):
    def run_command():
        # Create ghidra project
        file_name = os.path.basename(binary)
        # get home_path like /home/user
        home_path = os.path.expanduser('~')
        project_path = os.path.join(home_path, 'ghidra_project')
        os.makedirs(project_path, exist_ok=True)        
        
        my_debug_log("Current port is: {}".format(port))
        
        # Check if another program is occupying the port
        pid = -1
        need_kill = False
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
                need_kill = False
        
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
        
        ghidra_script_path = os.path.join(os.path.dirname(__file__), 'run_ghidra.py')
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
  

def run_ghidra_script(port, ghidra_script_type, ghidra_script_args=[]):
    '''
    port: the port of ghidra server, e.g. 11111
    ghidra_script_type: the type of ghidra script, e.g. ["callind_collect"]
    ghidra_script_args: the args of ghidra script, e.g. [0x8002ee5,0x8008b6e]
    '''
    starttime = time()
    ghidra_script_type.extend(map(str, ghidra_script_args))
    message = json.dumps(ghidra_script_type)
    response = client_send_message(message,port) 
    print("ghidra output: %s" % response)
    if ghidra_script_type[0] == "global_static_data":
        if not isinstance(response,list):
            print("the response is not list!")
            return None
        
        if len(response) == 1:
            if not isinstance(response[0],list) and not isinstance(response[0],dict):
                print("met the effective read point, got the effective data input pc = {}".format(response[0]))
                return response[0],[]

        #The return value of a static script is an array containing a dictionary
        #he last element of the array is the global traversal value
        dt_dict_list = response[:-1]
        global_vars = response[-1]
        
        endtime = time()
        print("ghidra get read avail addr time: %f" % (endtime - starttime))
        print("ghidra get dt_dict_list: %s" % dt_dict_list)
        print("ghidra get global_vars: %s" % global_vars)
        return dt_dict_list,global_vars
    elif ghidra_script_type[0] == "callind_collect":
        return response
    elif ghidra_script_type[0] == "correct_lr":
        return int(response, 16)
    return response


def delete_ghidra_project_lock_file():
    for root, dirs, files in os.walk(os.path.join(full_path, 'ghidra_project')):
        for file in files:
            if ".lock" in file:
                os.remove(os.path.join(root, file))


if __name__ == '__main__':
    pass
    # run_ghidra_get_read_avail_addr("/home/liyuweiheng/fuzzers/SEmu/DataSet/fuzz_tests/sam3x/Heat_Press/Heat_Press.elf",0x815b0, 0x80f35, 0x802d0, 0x81448)
    # run_ghidra_get_consume_pc("/home/liyuweiheng/fuzzers/SEmu/DataSet/fuzz_tests/f103/Gateway/Gateway.elf",0x8002ee5,0x8008b6e)
    #5748 2461 8991 8948 /home/liyuweiheng/fuzzers/SEmu/DataSet/fuzz_tests/k64/Console/output/default/dynamic_hook_indirect_addr.txt
    # read_avail_pc_str,hex_list  = run_ghidra_get_read_avail_addr("/home/liyuweiheng/fuzzers/SEmu/DataSet/fuzz_tests/k64/Console/Console.elf",0x1638, 0x99d, 0x231e, 0x22f4)
    # run_ghidra_get_read_avail_addr("/home/liyuweiheng/fuzzers/SEmu/DataSet/fuzz_tests/f103/Gateway/Gateway.elf",0x8008818, 0x800365d, 0x8002ee5, 0x8008b80,"/home/liyuweiheng/fuzzers/SEmu/DataSet/fuzz_tests/f103/Gateway/output_1201/default/dynamic_hook_indirect_addr.txt")
    #type,irq_pc,entry_point,callread_addr,read_addr,buffer_addr,dynamic_hook_indirect_path,port
    # run_ghidra_get_read_avail_addr(["global_avail_pc"],0x1674,0x99d, 0x231f, 0x22f4, 0x1fff0578,"/home/liyuweiheng/fuzzers/SEmu/DataSet/fuzz_tests/k64/Console/base_inputs/dynamic_hook_indirect_addr.txt",11111)