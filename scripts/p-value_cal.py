import numpy as np
from scipy.stats import mannwhitneyu

# 示例：覆盖率数据（单位可以是 % 或 basic block 数）
A = np.array([738, 737, 737, 738, 751])  # baseline
B = np.array([1318, 1344, 1344, 1318, 1333])  # new method

# Mann-Whitney U Test
stat, p_value = mannwhitneyu(A, B, alternative='two-sided')

print("U statistic:", stat)
print("P-value:", p_value)