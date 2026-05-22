import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import os
import matplotlib.patches as patches
from matplotlib.legend_handler import HandlerBase
from matplotlib.lines import Line2D
from matplotlib.ticker import MaxNLocator, MultipleLocator, FuncFormatter
import matplotlib.ticker as ticker

# ... (Previous imports and config logic remains the same up to base_path definition)
# Assuming plot_bb_config.py contains baseline_folder and adapter_folder dictionaries
try:
    from plot_bb_config import baseline_folder, adapter_folder, fuzzed_folder
except ImportError:
    print("Error: Could not import baseline_folder, adapter_folder, and fuzzed_folder from plot_bb_config.py")
    # ... (dummy dict logic)
    baseline_folder = {}
    adapter_folder = {}
    fuzzed_folder = {}

# Define your group names and corresponding firmware names
groups_and_firmwares = {
    'P2IM': ["Console","Steering_Control",'Gateway','Heat_Press','PLC',"Soldering_Iron",],
    'uEmu': ['GPSTracker','LiteOS_IoT','3Dprinter','Zephyr_SocketCan','utasker_USB',],
    'new_targets_2025':['BLE-HCI'],
    'Fuzzware_CVE':['Bootstrap_UART','Bootstrap_SPI','Echo_Server','L2cap_Processor','Snmp_Server'],
    'MultiFuzz':['CCN-Lite-Relay','Gnrc_Networking'],
}

# ... (Missing entries fill logic) ...
all_firmware_names_flat = [fw for sublist in groups_and_firmwares.values() for fw in sublist]
for fw_name in all_firmware_names_flat:
    if fw_name not in baseline_folder: baseline_folder[fw_name] = []
    if fw_name not in adapter_folder: adapter_folder[fw_name] = []
    if fw_name not in fuzzed_folder: fuzzed_folder[fw_name] = []

base_path = '/home/n0vic3/fuzzers/fuzzware-examples/fuzzed_test'
graph_save_directory = base_path

# ... (collect_and_interpolate_data function remains the same) ...
def collect_and_interpolate_data(paths):
    data_frames = []
    for path in paths:
        csv_file_path = os.path.join(path, 'stats', 'covered_bbs_by_second_into_experiment.csv')
        if not os.path.exists(csv_file_path):
            continue
        try:
            data = pd.read_csv(csv_file_path, delimiter='\t')
            if '# seconds_into_experiment' not in data.columns or 'num_bbs_total' not in data.columns:
                continue
            if data.empty:
                 continue
            data['hours'] = data['# seconds_into_experiment'] / 3600.0
            data_frames.append(data.set_index('hours'))
        except Exception as e:
             print(f"Error reading {csv_file_path}: {e}")

    if not data_frames:
        return pd.DataFrame(index=pd.Index([], name='hours'), columns=[])

    try:
        unified_start = max(df.index.min() for df in data_frames)
        unified_end = min(df.index.max() for df in data_frames)
        if unified_start >= unified_end:
             if data_frames:
                 first_df = data_frames[0]
                 if not first_df.empty:
                     unified_start = first_df.index.min()
                     unified_end = first_df.index.max()
                     if unified_start >= unified_end:
                          unified_end = unified_start + 1/3600
                 else:
                      return pd.DataFrame(index=pd.Index([], name='hours'), columns=[])
             else:
                 return pd.DataFrame(index=pd.Index([], name='hours'), columns=[])
        unified_hours = np.arange(unified_start, unified_end + 1e-9, 1/3600)
    except ValueError:
        return pd.DataFrame(index=pd.Index([], name='hours'), columns=[])

    interpolated_data_frames = []
    for df in data_frames:
        if df.empty: continue
        if df.index.duplicated().any():
            df = df[~df.index.duplicated(keep='first')]
        df = df.reindex(unified_hours, method='nearest', tolerance=1/3600).interpolate('index')
        if 'num_bbs_total' in df.columns:
            interpolated_data_frames.append(df['num_bbs_total'])

    if not interpolated_data_frames:
         return pd.DataFrame(index=pd.Index([], name='hours'), columns=[])

    combined_data = pd.concat(interpolated_data_frames, axis=1)
    return combined_data

# [MODIFIED] plot_median_and_range according to your provided snippet
def plot_median_and_range(ax, data, color, label, marker):
    if data.empty or data.shape[1] == 0:
         return
    median_values = data.median(axis=1)
    min_values = data.min(axis=1)
    max_values = data.max(axis=1)
    
    # 1. Plot line
    ax.plot(data.index, median_values, color=color, linewidth=2, label=label)
    # 2. Fill range
    ax.fill_between(data.index, min_values, max_values, color=color, alpha=0.3, edgecolor='none')

    # 3. [NEW] Custom Marker logic: Every 2 hours
    mark_times = np.arange(0, 24.1, 2)
    # Interpolate values at these specific times
    mark_values = np.interp(mark_times, data.index, median_values)
    
    # 4. [NEW] Plot markers separately
    ax.plot(mark_times, mark_values, color=color, marker=marker, 
            markersize=4, linestyle='None')


# --- Main Plotting Logic ---
nrows = 3
ncols = 7
total_cells = nrows * ncols

all_firmwares = [(group, fw) for group, fws in groups_and_firmwares.items() for fw in fws]
num_plots = len(all_firmwares)

if num_plots == 0:
    exit()

fig, axs = plt.subplots(nrows, ncols, figsize=(20, 8))
plt.subplots_adjust(
    left=0.07,    
    right=0.96,   
    bottom=0.15,
    top=0.85,
    wspace=0.45,
    hspace=0.7)

fig.text(0.02, 0.5, '#BBs Covered', va='center', rotation='vertical', fontsize=20, fontweight='bold')
fig.text(0.5, 0.04, 'Duration(h)', ha='center', fontsize=20, fontweight='bold')

plot_index = 0
for group_name, firmware_names in groups_and_firmwares.items():
    for firmware_name in firmware_names:
        if plot_index >= total_cells: break

        print(f'Processing: {firmware_name}')

        Baseline_base_path = f'/home/n0vic3/fuzzers/fuzzware/examples/{group_name}/{firmware_name}'
        Adapter_base_path = f'/home/n0vic3/fuzzers/fuzzware-examples/{group_name}/{firmware_name}'
        Fuzzed_base_path = f'/home/n0vic3/fuzzers/fuzzware-examples/fuzzed_test/{group_name}/{firmware_name}'

        graph_title = f"{firmware_name}"
        if group_name =='new_targets_2025' or group_name == 'MultiFuzz' or group_name == 'Fuzzware_CVE' or firmware_name =='utasker_USB' or firmware_name =='Zephyr_SocketCan':
            Baseline_base_path = Adapter_base_path

        Baseline_path_list = [os.path.join(Baseline_base_path, path) for path in baseline_folder.get(firmware_name, [])]
        Adapter_path_list = [os.path.join(Adapter_base_path, path) for path in adapter_folder.get(firmware_name, [])]
        Fuzzed_path_list = [os.path.join(Fuzzed_base_path, path) for path in fuzzed_folder.get(firmware_name, [])]

        row_idx = plot_index // ncols
        col_idx = plot_index % ncols
        current_ax = axs[row_idx, col_idx]

        if not Baseline_path_list and not Adapter_path_list and not Fuzzed_path_list:
            current_ax.set_title(f"{graph_title}\n(No data)", fontsize=10)
            current_ax.axis('off')
            plot_index += 1
            continue

        baseline_data = collect_and_interpolate_data(Baseline_path_list)
        adapter_data = collect_and_interpolate_data(Adapter_path_list)
        fuzzed_group3_data = collect_and_interpolate_data(Fuzzed_path_list)

        # Plotting [UPDATED COLORS to match provided snippet logic if implied, keeping your previous colors but using the new plot function]
        # Your snippet used: ('#2078AA', 'o'), ('#8FBC8F', 's'), ('#AE3347', '^')
        plot_median_and_range(current_ax, baseline_data, '#2078AA', 'Fuzzware+RR', 'o')
        plot_median_and_range(current_ax, fuzzed_group3_data, '#8FBC8F', 'Fuzzware+Fuzz', 's')
        plot_median_and_range(current_ax, adapter_data, '#AE3347', 'Fuzzware+FIDO', '^')

        # --- [MODIFIED] Styling based on your snippet ---
        current_ax.set_title(graph_title, fontsize=14, fontweight='bold') # [Modified] fontsize 17->14, added bold
        current_ax.grid(True, linestyle='--', alpha=0.7) # [Modified] Custom grid style
        current_ax.set_axisbelow(True) # [Modified]
        current_ax.spines['top'].set_visible(False)
        current_ax.spines['right'].set_visible(False)
        current_ax.tick_params(axis='both', labelsize=12) # Slightly smaller tick labels usually better with restricted space

        # X-Axis configuration
        current_ax.set_xlim(0, 24)
        current_ax.xaxis.set_major_locator(MultipleLocator(4))
        def format_x_axis(x, pos):
            if int(x) in [0, 8, 16, 24]:
                return f"{int(x)}"
            return ""
        current_ax.xaxis.set_major_formatter(FuncFormatter(format_x_axis))

        # Y-Axis configuration
        current_ax.set_ylim(bottom=0)
        current_ax.yaxis.set_major_locator(MaxNLocator(nbins=4, integer=True))
        current_ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda x, p: format(int(x), ','))) # [Modified] added comma formatting

        plot_index += 1

    if plot_index >= total_cells: break

for i in range(plot_index, total_cells):
    row_idx = i // ncols
    col_idx = i % ncols
    axs[row_idx, col_idx].axis('off')

# --- [MODIFIED] Create Shared Legend using HandlerLegendObject ---

class LegendObject(object):
    def __init__(self, color, marker):
        self.color = color
        self.marker = marker

class HandlerLegendObject(HandlerBase):
    def create_artists(self, legend, orig_handle, xdescent, ydescent, width, height, fontsize, trans):
        # Create the rounded box background
        legbox = patches.FancyBboxPatch((xdescent, ydescent), width, height,
                                        boxstyle="round,pad=0.2", 
                                        edgecolor=orig_handle.color,
                                        facecolor=orig_handle.color, 
                                        alpha=0.3, 
                                        transform=trans)
        
        # Create the line through the middle
        legline = Line2D([xdescent, xdescent + width], 
                       [ydescent + height / 2, ydescent + height / 2],
                       color=orig_handle.color, 
                       linewidth=2, 
                       linestyle='-', 
                       transform=trans)
        
        # Create the marker in the middle
        legmarker = Line2D([xdescent + width / 2], [ydescent + height / 2], 
                         marker=orig_handle.marker,
                         color=orig_handle.color, 
                         markersize=8,  # Legend marker size typically larger than plot marker size
                         linestyle='None', 
                         transform=trans)

        return [legbox, legline, legmarker]

# Only define for the 3 items
legend_handles = [
    LegendObject('#2078AA', 'o'),
    LegendObject('#8FBC8F', 's'),
    LegendObject('#AE3347', '^')
]
# Names unchanged
legend_labels = ['Fuzzware+RR', 'Fuzzware+Fuzz', 'Fuzzware+FIDO']

legend = fig.legend(handles=legend_handles, 
                   labels=legend_labels,
                   loc='upper center',
                   bbox_to_anchor=(0.5, 0.985),
                   ncol=3, # 3 columns
                   fontsize=14,
                   shadow=False, 
                   frameon=True,
                   fancybox=True,
                   handler_map={LegendObject: HandlerLegendObject()},
                   handletextpad=0.5, 
                   borderpad=0.6)

# Font styling
for text in legend.get_texts():
    if 'FIDO' in text.get_text():
        text.set_fontstyle('italic')
        text.set_weight('bold')

plot_file_path = os.path.join(graph_save_directory, 'comparison_plot_combined_grid_new.png')
plt.savefig(plot_file_path, format='png', dpi=300, bbox_inches='tight', pad_inches=0.05)
print(f'Combined grid plot saved to {plot_file_path}')

plt.close(fig)