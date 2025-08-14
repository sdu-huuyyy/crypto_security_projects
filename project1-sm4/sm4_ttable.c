#include "sm4.h"
#include <string.h>

#define T_TABLE_SIZE 256

//T-table，存储 L(τ(x)) 的结果
static uint32_t T_table[T_TABLE_SIZE];

void sm4_generate_t_table() {
    for (int i = 0; i < T_TABLE_SIZE; ++i) {
        uint32_t x = i;
        uint32_t t = tau(x);
        T_table[i] = L(t);
    }
}

void sm4_encrypt_ttable(const uint8_t input[16], uint8_t output[16], const uint32_t rk[32]) {
    uint32_t X[36];
    memcpy(X, input, 16);

    //重新组合T-table，降低内存访问
    for (int i = 0; i < 32; i++) {
        uint32_t temp = X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[i];
        X[i + 4] = X[i] ^
                   T_table[(temp >> 24) & 0xFF] ^
                   rotate_left(T_table[(temp >> 16) & 0xFF], 8) ^
                   rotate_left(T_table[(temp >> 8) & 0xFF], 16) ^
                   rotate_left(T_table[temp & 0xFF], 24);
    }

    uint32_t out[4] = { X[35], X[34], X[33], X[32] };
    memcpy(output, out, 16);
}

void sm4_decrypt_ttable(const uint8_t input[16], uint8_t output[16], const uint32_t rk[32]) {
    sm4_encrypt_ttable(input, output, rk);
}
