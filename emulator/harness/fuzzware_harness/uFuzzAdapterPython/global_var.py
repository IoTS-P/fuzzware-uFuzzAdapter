# usage: GlobalVar class is used to track the global variable

from ...utils import (
    uc_mem_read_offset_one_byte
)
class GlobalVar:
    def __init__(self, uc, address):
        self.address = int(address, 16)
        self.value = uc_mem_read_offset_one_byte(uc, self.address)
        self.previous_value = self.value

    def value_changed(self, uc):
        self.value = uc_mem_read_offset_one_byte(uc, self.address)
        ret_val = False
        if self.value == self.previous_value:
            ret_val = False
        else:
            ret_val = True
        self.previous_value = self.value
        return ret_val

def find_longest_continuous_segment(data):
    def find_continuous_segments(keys):
        if not keys:
            return []

        # 将集合的元素按升序排序
        sorted_keys = sorted(keys)

        # 查找连续的地址段
        segments = []
        current_segment = [sorted_keys[0]]

        for i in range(1, len(sorted_keys)):
            if sorted_keys[i] == sorted_keys[i - 1] + 1:
                current_segment.append(sorted_keys[i])
            else:
                segments.append(current_segment)
                current_segment = [sorted_keys[i]]

        segments.append(current_segment)
        return segments

    # 提取集合的元素列表
    keys = list(data)

    # 查找连续的地址段
    continuous_segments = find_continuous_segments(keys)
    print(continuous_segments)
    # 找到最长的连续地址段
    longest_segment = max(continuous_segments, key=len, default=[])

    return longest_segment

if __name__ == '__main__':
    data = {1, 2, 3, 5, 6, 7, 8, 9, 10}
    print(find_longest_continuous_segment(data))