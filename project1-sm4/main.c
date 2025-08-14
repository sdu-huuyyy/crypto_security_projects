#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "sm4.h"

#define TEST_GROUPS 100
#define TEST_ROUNDS 10000

//通用性能测试函数
void run_performance_test(const char* test_name,
                          sm4_block_func encrypt_func,
                          sm4_block_func decrypt_func,
                          uint8_t plaintexts[][16],
                          uint32_t enc_rk[32],
                          uint32_t dec_rk[32],
                          int num_blocks) {
    uint8_t ciphertexts[TEST_GROUPS][16];
    uint8_t decrypted[TEST_GROUPS][16];

    unsigned __int64 start, end;
    _ReadWriteBarrier();
    start = __rdtsc();
    for (int i = 0; i < TEST_ROUNDS; ++i) {
        for (int j = 0; j < num_blocks; ++j) {
            encrypt_func(plaintexts[j], ciphertexts[j], enc_rk);
        }
    }
    end = __rdtsc();
    _ReadWriteBarrier();
    uint64_t total_encrypt_cycles = end - start;

    _ReadWriteBarrier();
    start = __rdtsc();
    for (int i = 0; i < TEST_ROUNDS; ++i) {
        for (int j = 0; j < num_blocks; ++j) {
            decrypt_func(ciphertexts[j], decrypted[j], dec_rk);
        }
    }
    end = __rdtsc();
    _ReadWriteBarrier();
    uint64_t total_decrypt_cycles = end - start;

    //验证解密结果
    int error_count = 0;
    for (int j = 0; j < num_blocks; ++j) {
        if (memcmp(plaintexts[j], decrypted[j], 16) != 0) {
            error_count++;
        }
    }

    // 测试性能
    const double cpu_ghz = 2.5;
    printf(" [ %s ] - Performance Summary\n", test_name);
    printf(" ▷ Test Runs: %d ops (%d blocks x %d rounds)\n", num_blocks * TEST_ROUNDS, num_blocks, TEST_ROUNDS);
    printf(" ▷ Encryption: %.2f cycles/block, %.2f MB/s\n",
           (double)total_encrypt_cycles / (num_blocks * TEST_ROUNDS),
           (num_blocks * TEST_ROUNDS * 16.0) / (total_encrypt_cycles / (cpu_ghz * 1e9)) / (1024 * 1024));
    printf(" ▷ Decryption: %.2f cycles/block, %.2f MB/s\n",
           (double)total_decrypt_cycles / (num_blocks * TEST_ROUNDS),
           (num_blocks * TEST_ROUNDS * 16.0) / (total_decrypt_cycles / (cpu_ghz * 1e9)) / (1024 * 1024));
    printf(" ▷ Verification: %d/%d mismatches\n", error_count, num_blocks);

int main() {
    uint8_t key[16] = { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef };
    uint32_t enc_rk[32], dec_rk[32];
    uint8_t plaintexts[TEST_GROUPS][16];

    srand((unsigned int)time(NULL));
    for (int i = 0; i < TEST_GROUPS; ++i) {
        for (int j = 0; j < 16; ++j) {
            plaintexts[i][j] = rand() & 0xFF;
        }
    }

    sm4_key_expansion(key, enc_rk, 0);
    sm4_key_expansion(key, dec_rk, 1);

    //测试基础实现
    run_performance_test("SM4 基础实现", sm4_encrypt_basic, sm4_decrypt_basic, plaintexts, enc_rk, dec_rk, TEST_GROUPS);

    //测试T-table实现
    sm4_generate_t_table();
    run_performance_test("SM4 T-table实现", sm4_encrypt_ttable, sm4_decrypt_ttable, plaintexts, enc_rk, dec_rk, TEST_GROUPS);

    //测试AES-NI实现
    if (has_aesni()) {
        uint8_t plaintexts_4blocks[TEST_GROUPS][64];
        for (int i = 0; i < TEST_GROUPS; ++i) {
            for (int j = 0; j < 64; ++j) {
                plaintexts_4blocks[i][j] = rand() & 0xFF;
            }
        }

    } else {
        printf("CPU不支持AES-NI指令集，跳过测试\n");
    }

    return 0;
}
