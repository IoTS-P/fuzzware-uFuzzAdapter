import matplotlib.pyplot as plt
import pandas as pd
import os
from datetime import timedelta, datetime
import matplotlib.dates as mdates

# 替换为你的CSV文件路径
csv_file_path = '/home/n0vic3/fuzzers/fuzzware/examples/P2IM/Console/fuzzware-project/stats/covered_bbs_by_second_into_experiment.csv'

# 读取CSV文件
data = pd.read_csv(csv_file_path, delimiter='\t')

# 将秒转换为timedelta，然后加上一个起始时间（例如1970年1月1日）
# 这是必须的，因为matplotlib的日期格式化器需要一个日期时间对象
start_time = datetime(1970, 1, 1)
data['time'] = data['# seconds_into_experiment'].apply(lambda x: start_time + timedelta(seconds=x))

# 绘制图表
plt.figure(figsize=(10, 5))  # 设置图表大小
plt.plot(data['time'], data['num_bbs_total'], marker='o')  # 绘制折线图，使用圆圈标记每个点

# 设置图表标题和坐标轴标签
plt.title('Basic Block Count Over Time')
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
plt.legend(['Basic Blocks'])

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
