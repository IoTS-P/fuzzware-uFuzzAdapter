import subprocess,json

def find_function_address(binary_path, function_name):
    # 加载二进制文件
    cmd_res = subprocess.getoutput(f'objdump -t {binary_path} | grep {function_name} | cut -c 1-8')
    return cmd_res


if __name__ == "__main__":
    file_path = "/home/n0vic3/fuzzers/fuzzware-examples/other_target/CVE-2021-3330/CVE-2021-3330.json"
    function_name = 'uart_stm32_isr'       # 你要查找的函数名
    # 原始JSON数据
    data = {
        "irq_dt_set": [
            {
                "dr": 0,
                "callread_pc": 0,
                "read_pc": 0,
                "buffer_addr": 0,
                "consume_pc_set": [
                    "0"
                ],
                "irq_pc": 28,
                "avail_pc": 0x402d40,
                "rx_head": 0,
                "rx_tail": 0,
                "buffer_len": 1,
                "buffer_min_len": 1,
                "consume_count": 0
            }
        ],
    }

    # 生成新的JSON数据，只包含irq_dt_set内容
    new_data = {
        "main_dt_set": [],
        "irq_dt_set": data["irq_dt_set"],
        "dt_created_dr": [],
        "blacklist": [],
        "indirect_src_addrs": {},
        "data_regs": [],
        "avail_dt_dict": {},
        "consume_dt_dict": {}
    }

    
    # 将新数据写入新的JSON文件
    with open(file_path, "w") as f:
        json.dump(new_data, f, indent=4)

    print("生成JSON文件成功！")
    print(f"file_path:{file_path}")
