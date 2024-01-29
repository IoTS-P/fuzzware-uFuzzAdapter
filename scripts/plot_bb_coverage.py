import matplotlib.pyplot as plt
import pandas as pd
import os
from datetime import timedelta, datetime
import matplotlib.dates as mdates

# 替换为你的CSV文件路径
csv_file_path = '/home/n0vic3/fuzzers/fuzzware/examples/P2IM/PLC/fuzzware-project/stats/covered_bbs_by_second_into_experiment.csv'
crash_file_path = '/home/n0vic3/fuzzers/fuzzware/examples/P2IM/PLC/fuzzware-project/stats/crash_creation_timings_tututututut.txt'
# 读取CSV文件
data = pd.read_csv(csv_file_path, delimiter='\t')

# 将秒转换为timedelta，然后加上一个起始时间（例如1970年1月1日）
start_time = datetime(1970, 1, 1)
data['time'] = data['# seconds_into_experiment'].apply(lambda x: start_time + timedelta(seconds=x))

# 绘制基本块计数折线图
plt.figure(figsize=(10, 5))  # 设置图表大小
plt.plot(data['time'], data['num_bbs_total'], marker='o', label='Basic Blocks')

# 添加crash文件的路径


# 读取crash文件，并获取崩溃发生的时间点
with open(crash_file_path, 'r') as crash_data:
    crash_times = [start_time + timedelta(seconds=int(line.split('\t')[0])) for line in crash_data]

# 在图表上标记崩溃点
# 在图表上标记崩溃点
# 添加崩溃时间点的处理
crash_data = pd.read_csv(
    crash_file_path, 
    sep='\t', 
    header=None,
    names=['second_into_experiment', 'details']
)

# 提取时间戳并转换成datetime
crash_times = crash_data['second_into_experiment'].apply(lambda x: start_time + timedelta(seconds=int(x)))

# 在图表上标记崩溃点
for crash_time in crash_times:
    # 临时转换crash_time为matplotlib理解的格式
    temp_crash_time = mdates.date2num(crash_time)
    
    # 过滤出对应时间点的数据
    filtered_data = data[data['time'].map(mdates.date2num) == temp_crash_time]
    
    # 如果找到匹配的时间点，则进行绘制
    if not filtered_data.empty:
        plt.plot(
            crash_time, 
            filtered_data['num_bbs_total'].iloc[0], 
            'rX', # 使用大写X表示crash图标
            markersize=10,
            label='Crash'
        )

# 由于标记可能重复添加，我们需要处理图例中的重复项
handles, labels = plt.gca().get_legend_handles_labels()
by_label = dict(zip(labels, handles))
plt.legend(by_label.values(), by_label.keys())

# 设置图表标题和坐标轴标签
plt.title('Basic Block Count and Crashes Over Time')
plt.xlabel('Time (HH:MM)')
plt.ylabel('Number of Basic Blocks')

# 设置x轴的时间格式
plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
plt.gca().xaxis.set_major_locator(mdates.HourLocator())

# 旋转x轴的日期标签以便更容易阅读
plt.gcf().autofmt_xdate()

# 显示网格
plt.grid(True)

# 显示图例
plt.legend(['Basic Blocks', 'Crashes'])

# 获取CSV文件所在的目录
csv_directory = os.path.dirname(csv_file_path)

# 获取CSV文件的基本名称（不含扩展名）
csv_base_name = os.path.splitext(os.path.basename(csv_file_path))[0]

# 构建图表的保存路径，使用CSV文件的基本名称
plot_file_path = os.path.join(csv_directory, f'{csv_base_name}_plot.png')

# 保存图表到CSV文件所在的目录
plt.savefig(plot_file_path)

print(f'Plot saved to {plot_file_path}')
# 关闭图表窗口，因为我们已经保存了图表
plt.close()
