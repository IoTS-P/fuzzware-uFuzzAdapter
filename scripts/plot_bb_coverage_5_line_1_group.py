import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import os
from datetime import timedelta, datetime
import matplotlib.dates as mdates
from plot_bb_config import *

firmware_name = 'Gateway'
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
        data['hours'] = data['# seconds_into_experiment'] / 3600.0
        data_frames.append(data.set_index('hours'))

    unified_start = max(df.index.min() for df in data_frames)
    unified_end = min(df.index.max() for df in data_frames)
    unified_hours = np.arange(unified_start, unified_end + 1/3600, 1/3600)

    interpolated_data_frames = []
    for df in data_frames:
        if df.index.duplicated().any():
            df = df[~df.index.duplicated(keep='first')]
        df = df.reindex(unified_hours, method='nearest', tolerance=1/3600).interpolate('index')
        interpolated_data_frames.append(df['num_bbs_total'])

    combined_data = pd.concat(interpolated_data_frames, axis=1)
    return combined_data

def plot_median_and_range(data, color, label_prefix, marker):
    median_values = data.median(axis=1)
    min_values = data.min(axis=1)
    max_values = data.max(axis=1)
    plt.plot(data.index, median_values, color=color, linewidth=2, marker=marker, markevery=7200)
    plt.fill_between(data.index, min_values, max_values, color=color, alpha=0.3, edgecolor='none')

baseline_data = collect_and_interpolate_data(Baseline_path_list)
adapter_data = collect_and_interpolate_data(Adapter_path_list)

plt.figure(figsize=(4, 4))

min_hours = min(baseline_data.index.min(), adapter_data.index.min())
max_hours = max(baseline_data.index.max(), adapter_data.index.max())

plt.xlim(min_hours, max_hours)

hours_range = np.arange(min_hours, max_hours + 1, step=4)
plt.xticks(hours_range, [f'{int(hour)}' for hour in hours_range])

plot_median_and_range(baseline_data, '#2078AA', 'Baseline', 'o')
plot_median_and_range(adapter_data, '#AE3347', 'Adapter', '^')

plt.title(graph_title)
# plt.xlabel('Time (Hours)')
plt.ylabel('Number of Basic Blocks')

plt.grid(True)
# plt.legend()  # 注释掉这一行去掉图例
plot_file_path = os.path.join(graph_save_directory, 'comparison_plot.png')
plt.savefig(plot_file_path, dpi=300)
print(f'Plot saved to {plot_file_path}')

plt.close()
