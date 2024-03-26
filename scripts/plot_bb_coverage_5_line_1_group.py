import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import os
from datetime import timedelta, datetime
import matplotlib.dates as mdates
from plot_bb_config import *
firmware_name = 'Heat_Press'
group_name = 'P2IM'
Baseline_base_path = f'/home/n0vic3/fuzzers/fuzzware/examples/{group_name}/{firmware_name}'
Adapter_base_path = f'/home/n0vic3/fuzzers/fuzzware-examples/{group_name}/{firmware_name}'
graph_title = f"fuzzware/{firmware_name}"
graph_save_directory = Adapter_base_path

# Define the paths to the directories containing your 'covered_bbs_by_second_into_experiment.csv' files
Baseline_path_list = [os.path.join(Baseline_base_path, path) for path in baseline_folder[firmware_name]]
Adapter_path_list = [os.path.join(Adapter_base_path, path) for path in adapter_folder[firmware_name]]


def collect_and_interpolate_data(paths):
    data_frames = []
    for path in paths:
        print(f'Collecting data from {path}')
        csv_file_path = os.path.join(path, 'stats', 'covered_bbs_by_second_into_experiment.csv')
        data = pd.read_csv(csv_file_path, delimiter='\t')
        start_time = datetime(1970, 1, 1)
        # 将秒转换为小时
        data['hours'] = data['# seconds_into_experiment'] / 3600.0
        data_frames.append(data.set_index('hours'))

    # Determine common time range across all experiments
    unified_start = max(df.index.min() for df in data_frames)
    unified_end = min(df.index.max() for df in data_frames)
    unified_hours = np.arange(unified_start, unified_end + 1/3600, 1/3600)  # 每秒一个数据点

    # Interpolate data for the unified time range
    interpolated_data_frames = []
    for df in data_frames:
        if df.index.duplicated().any():
            df = df[~df.index.duplicated(keep='first')]
        df = df.reindex(unified_hours, method='nearest', tolerance=1/3600).interpolate('index')  # 使用index插值
        interpolated_data_frames.append(df['num_bbs_total'])

    combined_data = pd.concat(interpolated_data_frames, axis=1)
    return combined_data

def plot_median_and_range(data, color, label_prefix):
    median_values = data.median(axis=1)
    min_values = data.min(axis=1)
    max_values = data.max(axis=1)
    plt.plot(data.index, median_values, label=f'{label_prefix} Median', color=color, linewidth=2)
    plt.fill_between(data.index, min_values, max_values, color=color, alpha=0.3)

# Replace with your actual directories

# 收集和插值数据（假设已经修改为使用小时索引）
baseline_data = collect_and_interpolate_data(Baseline_path_list)
adapter_data = collect_and_interpolate_data(Adapter_path_list)

# 设置图表
plt.figure(figsize=(10, 5))

# 找到所有数据集中的最小和最大小时数
min_hours = min(baseline_data.index.min(), adapter_data.index.min())
max_hours = max(baseline_data.index.max(), adapter_data.index.max())

# 设置x轴的限制，这里直接使用小时数
plt.xlim(min_hours, max_hours)

# 设置x轴的标签，确保它们以小时为单位显示
hours_range = np.arange(min_hours, max_hours + 1, step=4)  # 每小时一个标签
plt.xticks(hours_range, [f'{int(hour)}' for hour in hours_range])

# 绘制基线和适配器组的数据
plot_median_and_range(baseline_data, 'blue', 'Baseline')
plot_median_and_range(adapter_data, 'red', 'Adapter')

# 设置标题和轴标签
plt.title(graph_title)
plt.xlabel('Time (Hours)')
plt.ylabel('Number of Basic Blocks')

# 显示网格
plt.grid(True)

# 显示图例
plt.legend()

# 保存图表到指定目录
plot_file_path = os.path.join(graph_save_directory, 'comparison_plot.png')
plt.savefig(plot_file_path)
print(f'Plot saved to {plot_file_path}')

# 关闭图表窗口，防止在交互式会话中显示
plt.close()