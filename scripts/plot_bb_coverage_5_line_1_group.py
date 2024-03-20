import matplotlib.pyplot as plt
import pandas as pd
import os
from datetime import timedelta, datetime
import matplotlib.dates as mdates

# 替换为你的CSV文件所在目录
Baseline_base_path = '/home/n0vic3/fuzzers/fuzzware/examples/uEmu/Thermostat'
Adapter_base_path = '/home/n0vic3/fuzzers/fuzzware-examples/uEmu/Thermostat'
graph_title = "fuzzware/Thermostat"
graph_save_directory = Adapter_base_path
Baseline_path_list = [os.path.join(Baseline_base_path,"0308_fuzz"),os.path.join(Baseline_base_path,"0318_fuzz"),os.path.join(Baseline_base_path,"0310_fuzz"),os.path.join(Baseline_base_path,"0309_fuzz"),os.path.join(Baseline_base_path,"0311_fuzz")]
Adapter_path_list = [os.path.join(Adapter_base_path,"0308_fuzz"),os.path.join(Adapter_base_path,"0309_fuzz"),os.path.join(Adapter_base_path,"0317_fuzz"),os.path.join(Adapter_base_path,"0311_fuzz"),os.path.join(Adapter_base_path,"0318_fuzz")]

def plot_data(csv_file_path, label, color):
    # 读取CSV文件
    data = pd.read_csv(csv_file_path, delimiter='\t')

    # 将秒转换为timedelta，然后加上一个起始时间（例如1970年1月1日）
    start_time = datetime(1970, 1, 1)
    data['time'] = data['# seconds_into_experiment'].apply(lambda x: start_time + timedelta(seconds=x))

    # 绘制图表
    plt.plot(data['time'], data['num_bbs_total'], marker='o', color=color, label=label,linewidth=2, markersize=1)

# 设置图表大小
plt.figure(figsize=(10, 5))


# 绘制Baseline组的数据
for i in range(1,len(Baseline_path_list)+1):
    csv_file_path = os.path.join(Baseline_path_list[i-1], 'stats', 'covered_bbs_by_second_into_experiment.csv')
    plot_data(csv_file_path, f'{i}-Baseline', 'blue')

# 绘制Adapter组的数据
for i in range(1,len(Adapter_path_list)+1):
    csv_file_path = os.path.join(Adapter_path_list[i-1], 'stats', 'covered_bbs_by_second_into_experiment.csv')
    plot_data(csv_file_path, f'{i}-Adapter', 'red')

# 设置图表标题和坐标轴标签
plt.title(graph_title)
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
plt.legend()

# 保存图表到CSV文件所在的目录
plot_file_path = os.path.join(graph_save_directory, 'comparison_plot.png')
plt.savefig(plot_file_path)
print(f'Plot saved to {plot_file_path}')

# 关闭图表窗口
plt.close()
