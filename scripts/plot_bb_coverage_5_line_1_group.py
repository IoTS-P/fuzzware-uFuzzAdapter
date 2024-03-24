import matplotlib.pyplot as plt
import pandas as pd
import os
from datetime import timedelta, datetime
import matplotlib.dates as mdates
firmware_name = 'PLC'
group_name = 'P2IM'
Baseline_base_path = f'/home/n0vic3/fuzzers/fuzzware/examples/{group_name}/{firmware_name}'
Adapter_base_path = f'/home/n0vic3/fuzzers/fuzzware-examples/{group_name}/{firmware_name}'
graph_title = f"fuzzware/{firmware_name}"
graph_save_directory = Adapter_base_path

# Define the paths to the directories containing your 'covered_bbs_by_second_into_experiment.csv' files
Baseline_path_list = [os.path.join(Baseline_base_path,"0216_fuzz"),os.path.join(Baseline_base_path,"0218_fuzz"),os.path.join(Baseline_base_path,"0219_fuzz"),os.path.join(Baseline_base_path,"0220_fuzz"),os.path.join(Baseline_base_path,"0224_fuzz")]
Adapter_path_list = [os.path.join(Adapter_base_path,"0303_fuzz"),os.path.join(Adapter_base_path,"0304_fuzz"),os.path.join(Adapter_base_path,"0307_fuzz"),os.path.join(Adapter_base_path,"0311_fuzz"),os.path.join(Adapter_base_path,"0308_fuzz")]


def collect_and_interpolate_data(paths):
    data_frames = []
    for path in paths:
        csv_file_path = os.path.join(path, 'stats', 'covered_bbs_by_second_into_experiment.csv')
        data = pd.read_csv(csv_file_path, delimiter='\t')
        start_time = datetime(1970, 1, 1)
        data['time'] = data['# seconds_into_experiment'].apply(lambda x: start_time + timedelta(seconds=x))
        data_frames.append(data.set_index('time'))

    # Determine common time range across all experiments
    unified_start = max(df.index.min() for df in data_frames)
    unified_end = min(df.index.max() for df in data_frames)
    unified_time = pd.date_range(start=unified_start, end=unified_end, freq='S')

    # Interpolate data for the unified time range
    interpolated_data_frames = []
    for df in data_frames:
        df = df.reindex(unified_time, method='nearest', tolerance='1s').interpolate('time')
        interpolated_data_frames.append(df['num_bbs_total'])

    # Combine all interpolated data frames
    combined_data = pd.concat(interpolated_data_frames, axis=1)
    return combined_data

def plot_median_and_range(data, color, label_prefix):
    median_values = data.median(axis=1)
    min_values = data.min(axis=1)
    max_values = data.max(axis=1)
    plt.plot(data.index, median_values, label=f'{label_prefix} Median', color=color, linewidth=2)
    plt.fill_between(data.index, min_values, max_values, color=color, alpha=0.3)

# Replace with your actual directories

# Collect and interpolate the data
baseline_data = collect_and_interpolate_data(Baseline_path_list)
adapter_data = collect_and_interpolate_data(Adapter_path_list)

# Set up the plot
plt.figure(figsize=(10, 5))
# Format the x-axis to show time in HH:MM format
plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
plt.gca().xaxis.set_major_locator(mdates.HourLocator(interval=1))  # Change interval if you want more or fewer labels

# Find the min and max times across your datasets
min_time = min(baseline_data.index.min(), adapter_data.index.min())
max_time = max(baseline_data.index.max(), adapter_data.index.max())

# Now adjust min_time and max_time to the nearest hour if you want or just set them to your desired start and end times
start_time = min_time.replace(hour=0, minute=0, second=0, microsecond=0)
end_time = max_time.replace(hour=23, minute=59, second=59, microsecond=999999)

# Set the x-axis limits
plt.gca().set_xlim(start_time, end_time)

# Rotate x-axis labels to make them easier to read
plt.gcf().autofmt_xdate()

# Plot the data for Baseline and Adapter groups
plot_median_and_range(baseline_data, 'blue', 'Baseline')
plot_median_and_range(adapter_data, 'red', 'Adapter')

# Set the title and axis labels
plt.title(graph_title)
plt.xlabel('Time (HH:MM)')
plt.ylabel('Number of Basic Blocks')

# Format the x-axis to show time in HH:MM format
plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
plt.gca().xaxis.set_major_locator(mdates.HourLocator())

# Rotate x-axis labels to make them easier to read
plt.gcf().autofmt_xdate()

# Display grid
plt.grid(True)

# Display legend
plt.legend()

# Save the plot to the same directory as the data files
plot_file_path = os.path.join(graph_save_directory, 'comparison_plot.png')
plt.savefig(plot_file_path)
print(f'Plot saved to {plot_file_path}')

# Close the plot window to prevent it from displaying in an interactive session
plt.close()
