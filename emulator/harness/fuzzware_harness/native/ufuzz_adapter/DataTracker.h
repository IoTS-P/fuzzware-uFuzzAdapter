#include <string>
#include <sstream>
#include <unordered_set>

class DataTracker {
private:
    uintptr_t dr; // address of the data register
    uintptr_t callread_pc; // the pc called the read function
    uintptr_t read_pc; // call dr pc in the read function
    uintptr_t buffer_addr; // the address reflected by the dr
    std::unordered_set<uintptr_t> consume_pc_set; // the set of the pc that consume the dr data
    uintptr_t irq_pc; // the pc of the irq handler
    uintptr_t avail_pc; // the pc to check the avail of the rx buffer (calculated by the irq handler or read_pc)
    uintptr_t rx_head; // pointer to the rx buffer
    uintptr_t rx_tail; // pointer to the rx buffer
    size_t buffer_len;
    uintptr_t buffer_min_len;
    size_t input_offset;
    size_t consume_count;
    size_t read_times;

public:
    DataTracker() : dr(0), callread_pc(0), read_pc(0), buffer_addr(0), irq_pc(0), avail_pc(0),
                    rx_head(0), rx_tail(0), buffer_len(0), buffer_min_len(0), input_offset(0),
                    consume_count(0), read_times(0) {}

    bool operator==(const DataTracker& other) const {
        return dr == other.dr &&
               callread_pc == other.callread_pc &&
               read_pc == other.read_pc &&
               buffer_addr == other.buffer_addr &&
               irq_pc == other.irq_pc &&
               avail_pc == other.avail_pc &&
               rx_head == other.rx_head &&
               rx_tail == other.rx_tail &&
               buffer_len == other.buffer_len &&
               buffer_min_len == other.buffer_min_len &&
               input_offset == other.input_offset &&
               consume_count == other.consume_count &&
               read_times == other.read_times;
    }

    friend std::hash<DataTracker>;

    std::string ToString() const {
        std::stringstream ss;
        ss << "dr: " << std::hex << dr << std::endl;
        ss << "callread_pc: " << std::hex << callread_pc << std::endl;
        ss << "read_pc: " << std::hex << read_pc << std::endl;
        ss << "buffer_addr: " << std::hex << buffer_addr << std::endl;
        ss << "irq_pc: " << std::hex << irq_pc << std::endl;
        ss << "avail_pc: " << std::hex << avail_pc << std::endl;
        ss << "rx_head: " << std::hex << rx_head << std::endl;
        ss << "rx_tail: " << std::hex << rx_tail << std::endl;
        ss << "buffer_len: " << buffer_len << std::endl;
        ss << "buffer_min_len: " << std::hex << buffer_min_len << std::endl;
        ss << "input_offset: " << input_offset << std::endl;
        ss << "consume_count: " << consume_count << std::endl;
        ss << "read_times: " << read_times;
        return ss.str();
    }
};

namespace std {
    template <>
    struct hash<DataTracker> {
        size_t operator()(const DataTracker& dt) const {
            return ((hash<uintptr_t>()(dt.dr) ^
                    (hash<uintptr_t>()(dt.callread_pc) << 1)) >> 1) ^
                    (hash<uintptr_t>()(dt.read_pc) << 1) ^
                    (hash<uintptr_t>()(dt.buffer_addr) >> 1) ^
                    (hash<uintptr_t>()(dt.irq_pc) << 1) ^
                    (hash<uintptr_t>()(dt.avail_pc) >> 1) ^
                    (hash<uintptr_t>()(dt.rx_head) << 1) ^
                    (hash<uintptr_t>()(dt.rx_tail) >> 1) ^
                    (hash<size_t>()(dt.buffer_len) << 1) ^
                    (hash<uintptr_t>()(dt.buffer_min_len) >> 1) ^
                    (hash<size_t>()(dt.input_offset) << 1) ^
                    (hash<size_t>()(dt.consume_count) >> 1) ^
                    (hash<size_t>()(dt.read_times) << 1);
        }
    };
}
