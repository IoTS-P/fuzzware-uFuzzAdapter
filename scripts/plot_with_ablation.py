import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from matplotlib.legend_handler import HandlerBase
from matplotlib.ticker import MaxNLocator

# --- 1. Import Configuration ---
try:
    # 确保 plot_bb_config_ablation.py 在同一目录下
    from plot_bb_config_ablation import baseline_folder, S1_adapter_folder, adapter_folder, S1_S2_adapter_folder
except ImportError:
    print("Error: Could not import folders from plot_bb_config_ablation.py")
    exit(1)

# --- 2. Firmware Group Mapping ---
# 必须手动定义 Group 映射，以构建正确的路径
# 这些固件来自 S1_adapter_folder
# [Modify] Added new firmware mappings
firmware_groups = {
    "Gateway": "P2IM",
    "Heat_Press": "P2IM",
    "3Dprinter": "uEmu",
    "GPSTracker": "uEmu",
    "utasker_USB": "uEmu",          # Added
    "CCN-Lite-Relay": "MultiFuzz",
    "Gnrc_Networking": "MultiFuzz", # Added
    "Bootstrap_UART": "Fuzzware_CVE" # Added
}

# --- 3. Define Base Paths ---
# Baseline 通常在 fuzzers/fuzzware/examples
BASELINE_ROOT_DEFAULT = '/home/n0vic3/fuzzers/fuzzware/examples'

# Adapter/S1 通常在 fuzzers/fuzzware-examples
ADAPTER_ROOT_DEFAULT = '/home/n0vic3/fuzzers/fuzzware-examples'
GRAPH_SAVE_DIRECTORY = ADAPTER_ROOT_DEFAULT

# --- 4. Identify Targets ---
# 只针对 S1_adapter_folder 中存在的固件生成图表
target_firmwares = [fw for fw in S1_adapter_folder.keys() if fw in firmware_groups]
num_plots = len(target_firmwares)

if num_plots == 0:
    print("No valid targets found in S1_adapter_folder (check firmware_groups mapping). Exiting.")
    exit()

print(f"Targets ({num_plots}): {target_firmwares}")

# --- 5. Helper Functions ---
def collect_and_interpolate_data(paths):
    data_frames = []
    for path in paths:
        csv_file_path = os.path.join(path, 'stats', 'covered_bbs_by_second_into_experiment.csv')
        
        if not os.path.exists(csv_file_path):
            print(f"Warning: File not found: {csv_file_path}")
            continue
            
        try:
            data = pd.read_csv(csv_file_path, delimiter='\t')
            # 兼容列名
            if '# relative_time' in data.columns:
                data.rename(columns={'# relative_time': 'time'}, inplace=True)
            elif '# seconds_into_experiment' in data.columns:
                data.rename(columns={'# seconds_into_experiment': 'time'}, inplace=True)
                
            if 'covered_bbs' in data.columns:
                 data.rename(columns={'covered_bbs': 'num_bbs_total'}, inplace=True)
            
            if 'time' not in data.columns or 'num_bbs_total' not in data.columns:
                print(f"Skipping {csv_file_path}: Missing columns.")
                continue

            # Convert seconds to hours
            data['hours'] = data['time'] / 3600.0
            data.set_index('hours', inplace=True)
            
            # Select only coverage
            df = data[['num_bbs_total']]
            
            # Remove duplicate indices
            df = df[~df.index.duplicated(keep='last')]
            data_frames.append(df)
        except Exception as e:
            print(f"Error reading {csv_file_path}: {e}")

    if not data_frames:
        return pd.DataFrame(index=pd.Index([], name='hours'), columns=[])

    try:
        # Interpolation Logic
        unified_start = max(df.index.min() for df in data_frames)
        unified_end = min(df.index.max() for df in data_frames)
        
        if unified_start >= unified_end:
             # Fallback
             if data_frames:
                 unified_start = 0
                 unified_end = max(df.index.max() for df in data_frames)
             else:
                 return pd.DataFrame(index=pd.Index([], name='hours'), columns=[])

        unified_hours = np.arange(unified_start, unified_end + 1e-9, 1/3600)

    except ValueError: 
        return pd.DataFrame(index=pd.Index([], name='hours'), columns=[])

    interpolated_data_frames = []
    for df in data_frames:
        if df.empty: continue
        # Reindex and Interpolate
        df = df.reindex(unified_hours, method='nearest', tolerance=1/3600).interpolate('index')
        if 'num_bbs_total' in df.columns:
             interpolated_data_frames.append(df['num_bbs_total'])

    if not interpolated_data_frames:
         return pd.DataFrame(index=pd.Index([], name='hours'), columns=[])

    combined_data = pd.concat(interpolated_data_frames, axis=1)
    return combined_data

def plot_median_and_range(ax, data, color, label, marker):
    if data.empty or data.shape[1] == 0:
         # print(f"Skipping plot for '{label}': Data is empty.")
         return
    median_values = data.median(axis=1)
    min_values = data.min(axis=1)
    max_values = data.max(axis=1)
    
    # 采样绘制 Marker (每2小时一个点，假设数据是1秒1个点则7200，如果已经稀疏化需调整)
    ax.plot(data.index, median_values, color=color, linewidth=2, marker=marker, 
            markevery=7200, markersize=8, label=label) 
    ax.fill_between(data.index, min_values, max_values, color=color, alpha=0.3, edgecolor='none')

# --- 6. Main Plotting Logic ---

# [Modify] Layout Adjustment
# Changed from single row to 2 rows to accommodate 8 plots
ncols = 4  
nrows = (num_plots + ncols - 1) // ncols  # Dynamic calculation: ceil(8/4) = 2

# Figure Size: Adjusted for 2 rows
fig, axs = plt.subplots(nrows, ncols, figsize=(3.5 * ncols, 4 * nrows), squeeze=False)

plt.subplots_adjust(left=0.07, right=0.96, bottom=0.15, top=0.9, wspace=0.3, hspace=0.4)

# Global Labels (Positioned relative to figure)
fig.text(0.02, 0.5, '#BBs Covered', va='center', rotation='vertical', fontsize=14, fontweight='bold')
fig.text(0.5, 0.05, 'Duration(h)', ha='center', fontsize=14, fontweight='bold') # Adjusted bottom position

plot_index = 0
for firmware_name in target_firmwares:
    group_name = firmware_groups[firmware_name]
    print(f'[{plot_index+1}/{num_plots}] {group_name}/{firmware_name}...')

    row_idx = plot_index // ncols
    col_idx = plot_index % ncols
    current_ax = axs[row_idx, col_idx]

    # --- Path Construction Logic (Mimicking plot_with_duration.py) ---
    
    # 1. Base Paths
    base_bl = os.path.join(BASELINE_ROOT_DEFAULT, group_name, firmware_name)
    base_ad = os.path.join(ADAPTER_ROOT_DEFAULT, group_name, firmware_name)
    
    # Special Handling for Baseline Paths
    # MultiFuzz, new_targets_2025, Fuzzware_CVE use Adapter path for baseline data too
    if group_name in ['new_targets_2025', 'MultiFuzz', 'Fuzzware_CVE']:
        base_bl = base_ad
    
    # S1 uses the same base root as Adapter
    base_s1 = base_ad
    
    # 2. Full Paths List
    # Get run IDs from config
    runs_bl = baseline_folder.get(firmware_name, [])
    runs_s1 = S1_adapter_folder.get(firmware_name, [])
    runs_s1_s2 = S1_S2_adapter_folder.get(firmware_name, [])
    runs_ad = adapter_folder.get(firmware_name, [])
    
    paths_bl = [os.path.join(base_bl, run) for run in runs_bl]
    paths_s1 = [os.path.join(base_s1, run) for run in runs_s1]
    paths_s1_s2 = [os.path.join(base_ad, run) for run in runs_s1_s2]
    paths_ad = [os.path.join(base_ad, run) for run in runs_ad]

    # --- Collect Data ---
    df_bl = collect_and_interpolate_data(paths_bl)
    df_s1 = collect_and_interpolate_data(paths_s1)
    df_s1_s2 = collect_and_interpolate_data(paths_s1_s2)
    df_ad = collect_and_interpolate_data(paths_ad)

    # --- Plot ---
    # Baseline: Blue Circle
    plot_median_and_range(current_ax, df_bl, '#2078AA', 'Baseline', 'o')
    # S1 (Ablation): Green Square 
    plot_median_and_range(current_ax, df_s1, '#34A853', 'Ablation (S1)', 's')
    # S1+S2 (Ablation): Orange Diamond
    plot_median_and_range(current_ax, df_s1_s2, '#F4B400', 'Ablation (S1+S2)', 'D')
    # Adapter (Full): Red Triangle
    plot_median_and_range(current_ax, df_ad, '#AE3347', 'Adapter', '^')

    # --- Styling ---
    current_ax.set_xlim(0, 24)
    # y-axis locator
    current_ax.yaxis.set_major_locator(MaxNLocator(nbins=4, min_n_ticks=3, integer=True))
    # x-axis locator
    current_ax.xaxis.set_major_locator(MaxNLocator(nbins=5, min_n_ticks=5, integer=True))
    
    current_ax.set_title(firmware_name.replace('_', ' '), fontsize=10, fontweight='bold', pad=10) # Reduced font size slightly
    current_ax.grid(True, linestyle='--', alpha=0.7)
    current_ax.spines['top'].set_visible(False)
    current_ax.spines['right'].set_visible(False)
    
    plot_index += 1

# [Modify] Hide empty subplots if any
for i in range(plot_index, nrows * ncols):
    row_idx = i // ncols
    col_idx = i % ncols
    axs[row_idx, col_idx].axis('off')

# --- Legend ---
class LegendObject(object):
    def __init__(self, color, marker):
        self.color = color
        self.marker = marker

class HandlerLegendObject(HandlerBase):
    def create_artists(self, legend, orig_handle, xdescent, ydescent, width, height, fontsize, trans):
        from matplotlib.lines import Line2D
        legline = Line2D([width/2], [height/2], marker=orig_handle.marker, 
                         color=orig_handle.color, markersize=8, linestyle='')
        legbox = patches.FancyBboxPatch((xdescent, ydescent), width, height,
                                        boxstyle="round,pad=0.2", edgecolor=orig_handle.color,
                                        facecolor=orig_handle.color, alpha=0.3, transform=trans)
        return [legbox, legline]

legend_handles = [
    LegendObject('#2078AA', 'o'), 
    LegendObject('#34A853', 's'),
    LegendObject('#F4B400', 'D'), 
    LegendObject('#AE3347', '^')
]
legend_labels = ['Baseline', 'Ablation (S1)', 'Ablation (S1+S2)', 'Adapter']

fig.legend(handles=legend_handles, labels=legend_labels, 
           loc='upper center', ncol=4, 
           bbox_to_anchor=(0.5, 0.98), # Adjusted upper anchor due to taller figure
           fontsize=12, 
           handler_map={LegendObject: HandlerLegendObject()})

# --- Save ---
save_name = 'ablation_S1_S2_comparison.png'
save_path = os.path.join(GRAPH_SAVE_DIRECTORY, save_name)
plt.savefig(save_path, dpi=300, bbox_inches='tight')
print(f"Plot saved to: {save_path}")