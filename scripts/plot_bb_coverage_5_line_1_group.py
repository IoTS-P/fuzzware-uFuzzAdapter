import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import os
from matplotlib.legend_handler import HandlerBase
from plot_bb_config import *

# Define your group names and corresponding firmware names
groups_and_firmwares = {
    'P2IM': ['PLC', 'Gateway', 'Heat_Press', "Console", "Steering_Control"],
    'uEmu': ['GPSTracker', '3Dprinter'],
    # Add more groups and firmware names as needed
}

base_path = '/home/n0vic3/fuzzers/fuzzware-examples'
graph_save_directory = base_path

def collect_and_interpolate_data(paths):
    data_frames = []
    for path in paths:
        print(f'Collecting data from {path}')
        csv_file_path = os.path.join(path, 'stats', 'covered_bbs_by_second_into_experiment.csv')
        data = pd.read_csv(csv_file_path, delimiter='\t')
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

def plot_median_and_range(ax, data, color, label, marker):
    median_values = data.median(axis=1)
    min_values = data.min(axis=1)
    max_values = data.max(axis=1)
    ax.plot(data.index, median_values, color=color, linewidth=2, marker=marker, markevery=7200, label=label)
    ax.fill_between(data.index, min_values, max_values, color=color, alpha=0.3, edgecolor='none')

# Create a figure with a sub-plot for each firmware name in each group
num_plots = sum(len(firmwares) for firmwares in groups_and_firmwares.values())
fig, axs = plt.subplots(1, num_plots, figsize=(4 * num_plots, 4))
plt.tight_layout(rect=[0, 0, 1, 0.85])

plot_index = 0
for group_name, firmware_names in groups_and_firmwares.items():
    for firmware_name in firmware_names:
        print(f'group_name: {group_name}, firmware_name: {firmware_name}')
        Baseline_base_path = f'/home/n0vic3/fuzzers/fuzzware/examples/{group_name}/{firmware_name}'
        Adapter_base_path = f'/home/n0vic3/fuzzers/fuzzware-examples/{group_name}/{firmware_name}'
        graph_title = f"{firmware_name}"

        # Define the paths to the directories containing your 'covered_bbs_by_second_into_experiment.csv' files
        Baseline_path_list = [os.path.join(Baseline_base_path, path) for path in baseline_folder[firmware_name]]
        Adapter_path_list = [os.path.join(Adapter_base_path, path) for path in adapter_folder[firmware_name]]

        baseline_data = collect_and_interpolate_data(Baseline_path_list)
        adapter_data = collect_and_interpolate_data(Adapter_path_list)

        min_hours = min(baseline_data.index.min(), adapter_data.index.min())
        max_hours = max(baseline_data.index.max(), adapter_data.index.max())

        axs[plot_index].set_xlim(min_hours, max_hours)
        plot_median_and_range(axs[plot_index], baseline_data, '#2078AA', 'Fuzzware', 'o')
        plot_median_and_range(axs[plot_index], adapter_data, '#AE3347', 'Fuzzware+F²IDE', '^')

        axs[plot_index].set_title(graph_title, fontsize=16)
        axs[plot_index].grid(True)
        axs[plot_index].spines['top'].set_visible(False)
        axs[plot_index].spines['right'].set_visible(False)
        plot_index += 1

# Collect all handles and labels from all subplots
handles, labels = [], []
for ax in axs:
    for handle, label in zip(*ax.get_legend_handles_labels()):
        if label not in labels:
            handles.append(handle)
            labels.append(label)

# Create custom legend handles with boxes
class LegendObject(object):
    def __init__(self, color, marker):
        self.color = color
        self.marker = marker

class HandlerLegendObject(HandlerBase):
    def create_artists(self, legend, orig_handle, xdescent, ydescent, width, height, fontsize, trans):
        import matplotlib.patches as patches
        from matplotlib.lines import Line2D
        legline = Line2D([width / 2], [height / 2], marker=orig_handle.marker,
                         color=orig_handle.color, markersize=10, linestyle='')

        legbox = patches.FancyBboxPatch((xdescent, ydescent), width, height,
                                        boxstyle="round,pad=0.3", edgecolor=orig_handle.color,
                                        facecolor=orig_handle.color, alpha=0.3, transform=trans)

        return [legbox, legline]

legend_handles = [LegendObject('#2078AA', 'o'), LegendObject('#AE3347', '^')]
legend_labels = ['Fuzzware', 'Fuzzware+F²IDE']

# Customize the legend
legend = fig.legend(handles=legend_handles, labels=legend_labels, loc='upper center', ncol=2, bbox_to_anchor=(0.5, 1.02), fontsize=16, shadow=False, frameon=True, fancybox=True, draggable=True, handler_map={LegendObject: HandlerLegendObject()})
for text in legend.get_texts():
    if 'F²IDE' in text.get_text():
        text.set_fontstyle('italic')
        text.set_weight('bold')
plot_file_path = os.path.join(graph_save_directory, 'comparison_plot_combined.png')
plt.savefig(plot_file_path, format='png', dpi=300)
print(f'Combined plot saved to {plot_file_path}')

plt.close()
