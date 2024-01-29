#!/bin/bash

# 定义文件夹路径
crashes_dir="/home/n0vic3/fuzzers/fuzzware/examples/P2IM/PLC/fuzzware-project/main001/fuzzers/fuzzer1/crashes"
output_dir="/home/n0vic3/fuzzers/fuzzware/examples/P2IM/PLC/POC/true_crash" # 输出目录，需要替换为实际路径

# 检查输出目录是否存在，不存在则创建
if [ ! -d "$output_dir" ]; then
  mkdir -p "$output_dir"
fi

# 遍历文件夹中的文件
# source ~/.bashrc
# workon fuzzware
cd /home/n0vic3/fuzzers/fuzzware/examples/P2IM/PLC
for file in "$crashes_dir"/*; do
    # 获取文件的基本名（不包含路径）
    filename=$(basename -- "$file")
    
    # 设置输出文件名
    crash_output="$output_dir/${filename}_output.txt"

    # 执行命令并将输出重定向到文件
    /home/n0vic3/.virtualenvs/fuzzware/bin/fuzzware emu -t "$file" > "$crash_output"

    # 检查输出文件是否包含特定字符串（不区分大小写）
    if ! grep -iq "process_fc" "$crash_output"; then
        # 如果没有匹配到字符串，删除输出文件
        echo "Not a true crash: $filename"
        rm "$crash_output"
    else
        # 如果匹配到字符串，输出文件名
        echo "True crash: $filename"
    fi
done
