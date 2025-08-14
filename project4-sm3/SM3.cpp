#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#include <vector>
#include <numeric>

//状态结构体
struct SmState {
    unsigned int v[8];
    unsigned int t0 = 2045582361U;
    unsigned int t1 = 2056262026U;
};

//辅助函数
inline unsigned int ff_func(unsigned int x, unsigned int y, unsigned int z, int j) {
    if (j < 16) return x ^ y ^ z;
    return (x & y) | (x & z) | (y & z);
}

inline unsigned int gg_func(unsigned int x, unsigned int y, unsigned int z, int j) {
    if (j < 16) return x ^ y ^ z;
    return (x & y) | ((~x) & z);
}

inline unsigned int left_rot(unsigned int x, int n) {
    return (x << n) | (x >> (32 - n));
}

inline unsigned int p0_transform(unsigned int x) {
    return x ^ left_rot(x, 9) ^ left_rot(x, 17);
}

inline unsigned int p1_transform(unsigned int x) {
    return x ^ left_rot(x, 15) ^ left_rot(x, 23);
}

//消息预处理
std::vector<unsigned char> preprocess_message(const std::string& message) {
    std::vector<unsigned char> result(message.begin(), message.end());
    uint64_t bitLength = message.size() * 8;
    result.push_back(0x80);

    while ((result.size() * 8 + 64) % 512 != 0) {
        result.push_back(0x00);
    }

    for (int i = 7; i >= 0; --i) {
        result.push_back(static_cast<unsigned char>((bitLength >> (i * 8)) & 0xFF));
    }

    return result;
}

//消息扩展
void expand_message(const unsigned char* block, std::vector<unsigned int>& w_out, std::vector<unsigned int>& w1_out) {
    for (int j = 0; j < 16; ++j) {
        w_out[j] = (static_cast<unsigned int>(block[j*4]) << 24) |
                   (static_cast<unsigned int>(block[j*4+1]) << 16) |
                   (static_cast<unsigned int>(block[j*4+2]) << 8)  |
                   (static_cast<unsigned int>(block[j*4+3]));
    }
    for (int j = 16; j < 68; ++j) {
        w_out[j] = p1_transform(w_out[j-16] ^ w_out[j-9] ^ left_rot(w_out[j-3], 15)) ^
                   left_rot(w_out[j-13], 7) ^ w_out[j-6];
    }
    for (int j = 0; j < 64; ++j) {
        w1_out[j] = w_out[j] ^ w_out[j+4];
    }
}

//压缩函数
void compress_block(SmState& state, const std::vector<unsigned int>& w, const std::vector<unsigned int>& w1) {
    unsigned int a = state.v[0], b = state.v[1], c = state.v[2], d = state.v[3];
    unsigned int e = state.v[4], f = state.v[5], g = state.v[6], h = state.v[7];

    for (int j = 0; j < 64; ++j) {
        unsigned int tj = (j < 16) ? state.t0 : state.t1;
        unsigned int ss1 = left_rot(left_rot(a, 12) + e + left_rot(tj, j), 7);
        unsigned int ss2 = ss1 ^ left_rot(a, 12);

        unsigned int tt1 = ff_func(a, b, c, j) + d + ss2 + w1[j];
        unsigned int tt2 = gg_func(e, f, g, j) + h + ss1 + w[j];

        d = c; c = left_rot(b, 9); b = a; a = tt1;
        h = g; g = left_rot(f, 19); f = e; e = p0_transform(tt2);
    }

    state.v[0] ^= a; state.v[1] ^= b; state.v[2] ^= c; state.v[3] ^= d;
    state.v[4] ^= e; state.v[5] ^= f; state.v[6] ^= g; state.v[7] ^= h;
}

//主哈希函数
std::string do_sm3_hashing(const std::string& input_string) {
    SmState context;
    context.v[0] = 1937748463U; context.v[1] = 1226093241U;
    context.v[2] = 389422807U;  context.v[3] = 3669145600U;
    context.v[4] = 2845899964U; context.v[5] = 375685450U;
    context.v[6] = 3822180045U; context.v[7] = 2968393358U;

    auto padded_msg = preprocess_message(input_string);

    for (size_t i = 0; i < padded_msg.size(); i += 64) {
        std::vector<unsigned int> w(68);
        std::vector<unsigned int> w1(64);
        expand_message(padded_msg.data() + i, w, w1);
        compress_block(context, w, w1);
    }

    std::ostringstream ss;
    for (int i = 0; i < 8; ++i) {
        ss << std::hex << std::setfill('0') << std::setw(8) << context.v[i];
    }
    return ss.str();
}

int main() {
    std::vector<std::string> test_strings = {
        "",
        "huuy",
        "huyunhelloworldhelloworldhelloworldhuuy"
    };

    std::cout << "------------------------------------------" << std::endl;
    std::cout << "        SM3 Hash Calculation Report       " << std::endl;
    std::cout << "------------------------------------------" << std::endl;

    for (size_t i = 0; i < test_strings.size(); ++i) {
        const auto& s = test_strings[i];
        std::string hash_value = do_sm3_hashing(s);

        std::cout << ">> Test Case #" << i + 1 << ":" << std::endl;
        std::cout << "   Input String: \"" << (s.empty() ? "EMPTY" : s) << "\"" << std::endl;
        std::cout << "   Output Hash (with separators):" << std::endl;

        std::cout << "   ";
        for (size_t j = 0; j < hash_value.length(); j += 8) {
            std::cout << hash_value.substr(j, 8) << (j + 8 < hash_value.length() ? "-" : "");
        }
        std::cout << std::endl;
        std::cout << "------------------------------------------" << std::endl;
    }

    std::cout << "           End of Report." << std::endl;

    return 0;
}
