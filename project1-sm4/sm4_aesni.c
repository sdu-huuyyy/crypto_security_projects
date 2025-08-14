#include "sm4.h"
#include <string.h>

//矩阵乘法辅助函数
static inline __m128i MulMatrix(__m128i x, __m128i higherMask, __m128i lowerMask) {
    __m128i tmp1, tmp2;
    __m128i andMask = _mm_set1_epi32(0x0f0f0f0f);
    tmp2 = _mm_srli_epi16(x, 4);
    tmp1 = _mm_and_si128(x, andMask);
    tmp2 = _mm_and_si128(tmp2, andMask);
    tmp1 = _mm_shuffle_epi8(lowerMask, tmp1);
    tmp2 = _mm_shuffle_epi8(higherMask, tmp2);
    return _mm_xor_si128(tmp1, tmp2);
}

//宏定义
#define MM_PACK0_EPI32(a, b, c, d) \
    _mm_unpacklo_epi64(_mm_unpacklo_epi32(a, b), _mm_unpacklo_epi32(c, d))
#define MM_PACK1_EPI32(a, b, c, d) \
    _mm_unpackhi_epi64(_mm_unpacklo_epi32(a, b), _mm_unpacklo_epi32(c, d))
#define MM_PACK2_EPI32(a, b, c, d) \
    _mm_unpacklo_epi64(_mm_unpackhi_epi32(a, b), _mm_unpackhi_epi32(c, d))
#define MM_PACK3_EPI32(a, b, c, d) \
    _mm_unpackhi_epi64(_mm_unpackhi_epi32(a, b), _mm_unpackhi_epi32(c, d))

#define MM_XOR2(a, b) _mm_xor_si128(a, b)
#define MM_XOR3(a, b, c) MM_XOR2(a, MM_XOR2(b, c))
#define MM_XOR4(a, b, c, d) MM_XOR2(a, MM_XOR3(b, c, d))
#define MM_XOR5(a, b, c, d, e) MM_XOR2(a, MM_XOR4(b, c, d, e))
#define MM_XOR6(a, b, c, d, e, f) MM_XOR2(a, MM_XOR5(b, c, d, e, f))
#define MM_ROTL_EPI32(a, n) \
    MM_XOR2(_mm_slli_epi32(a, n), _mm_srli_epi32(a, 32 - n))

//S盒实现
static inline __m128i sm4_sbox_aesni(__m128i x) {
    __m128i MASK = _mm_set_epi8(0x03, 0x06, 0x09, 0x0c, 0x0f, 0x02, 0x05, 0x08,
                                0x0b, 0x0e, 0x01, 0x04, 0x07, 0x0a, 0x0d, 0x00);
    x = _mm_shuffle_epi8(x, MASK);
    __m128i higherMask = _mm_set_epi8(
        0x22, 0x58, 0x1a, 0x60, 0x02, 0x78, 0x3a, 0x40,
        0x62, 0x18, 0x5a, 0x20, 0x42, 0x38, 0x7a, 0x00
    );
    __m128i lowerMask = _mm_set_epi8(
        0xe2, 0x28, 0x95, 0x5f, 0x69, 0xa3, 0x1e, 0xd4,
        0x36, 0xfc, 0x41, 0x8b, 0xbd, 0x77, 0xca, 0x00
    );
    x = MulMatrix(x, higherMask, lowerMask);
    x = _mm_xor_si128(x, _mm_set1_epi8(0x63));
    x = _mm_aesenclast_si128(x, _mm_setzero_si128());
    higherMask = _mm_set_epi8(
        0x14, 0x07, 0xc6, 0xd5, 0x6c, 0x7f, 0xbe, 0xad,
        0xb9, 0xaa, 0x6b, 0x78, 0xc1, 0xd2, 0x13, 0x00
    );
    lowerMask = _mm_set_epi8(
        0xd8, 0xb8, 0xfa, 0x9a, 0xc5, 0xa5, 0xe7, 0x87,
        0x5f, 0x3f, 0x7d, 0x1d, 0x42, 0x22, 0x60, 0x00
    );
    x = MulMatrix(x, higherMask, lowerMask);
    return _mm_xor_si128(x, _mm_set1_epi8(0x3b));
}

//加密4个SM4分组(并行处理)
void sm4_encrypt_4blocks_aesni(const uint8_t input[64], uint8_t output[64], const uint32_t rk[32]) {
    __m128i X[4], Tmp[4];
    __m128i vindex = _mm_setr_epi8(3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12);

    // 加载和打包数据
    Tmp[0] = _mm_loadu_si128((const __m128i*)input + 0);
    Tmp[1] = _mm_loadu_si128((const __m128i*)input + 1);
    Tmp[2] = _mm_loadu_si128((const __m128i*)input + 2);
    Tmp[3] = _mm_loadu_si128((const __m128i*)input + 3);

    X[0] = MM_PACK0_EPI32(Tmp[0], Tmp[1], Tmp[2], Tmp[3]);
    X[1] = MM_PACK1_EPI32(Tmp[0], Tmp[1], Tmp[2], Tmp[3]);
    X[2] = MM_PACK2_EPI32(Tmp[0], Tmp[1], Tmp[2], Tmp[3]);
    X[3] = MM_PACK3_EPI32(Tmp[0], Tmp[1], Tmp[2], Tmp[3]);

    X[0] = _mm_shuffle_epi8(X[0], vindex);
    X[1] = _mm_shuffle_epi8(X[1], vindex);
    X[2] = _mm_shuffle_epi8(X[2], vindex);
    X[3] = _mm_shuffle_epi8(X[3], vindex);

    // 轮函数
    for (int i = 0; i < 32; i++) {
        __m128i k = _mm_set1_epi32(rk[i]);
        Tmp[0] = MM_XOR4(X[1], X[2], X[3], k);
        Tmp[0] = sm4_sbox_aesni(Tmp[0]);
        Tmp[0] = MM_XOR6(X[0], Tmp[0], MM_ROTL_EPI32(Tmp[0], 2),
                         MM_ROTL_EPI32(Tmp[0], 10), MM_ROTL_EPI32(Tmp[0], 18),
                         MM_ROTL_EPI32(Tmp[0], 24));
        X[0] = X[1];
        X[1] = X[2];
        X[2] = X[3];
        X[3] = Tmp[0];
    }

    // 存储和解包数据
    X[0] = _mm_shuffle_epi8(X[0], vindex);
    X[1] = _mm_shuffle_epi8(X[1], vindex);
    X[2] = _mm_shuffle_epi8(X[2], vindex);
    X[3] = _mm_shuffle_epi8(X[3], vindex);

    _mm_storeu_si128((__m128i*)output + 0, MM_PACK0_EPI32(X[3], X[2], X[1], X[0]));
    _mm_storeu_si128((__m128i*)output + 1, MM_PACK1_EPI32(X[3], X[2], X[1], X[0]));
    _mm_storeu_si128((__m128i*)output + 2, MM_PACK2_EPI32(X[3], X[2], X[1], X[0]));
    _mm_storeu_si128((__m128i*)output + 3, MM_PACK3_EPI32(X[3], X[2], X[1], X[0]));
}

// 解密4个SM4分组(并行处理)
void sm4_decrypt_4blocks_aesni(const uint8_t input[64], uint8_t output[64], const uint32_t rk[32]) {
    __m128i X[4], Tmp[4];
    __m128i vindex = _mm_setr_epi8(3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12);

    // 加载和打包数据...
    Tmp[0] = _mm_loadu_si128((const __m128i*)input + 0);
    Tmp[1] = _mm_loadu_si128((const __m128i*)input + 1);
    Tmp[2] = _mm_loadu_si128((const __m128i*)input + 2);
    Tmp[3] = _mm_loadu_si128((const __m128i*)input + 3);

    X[0] = MM_PACK0_EPI32(Tmp[0], Tmp[1], Tmp[2], Tmp[3]);
    X[1] = MM_PACK1_EPI32(Tmp[0], Tmp[1], Tmp[2], Tmp[3]);
    X[2] = MM_PACK2_EPI32(Tmp[0], Tmp[1], Tmp[2], Tmp[3]);
    X[3] = MM_PACK3_EPI32(Tmp[0], Tmp[1], Tmp[2], Tmp[3]);

    X[0] = _mm_shuffle_epi8(X[0], vindex);
    X[1] = _mm_shuffle_epi8(X[1], vindex);
    X[2] = _mm_shuffle_epi8(X[2], vindex);
    X[3] = _mm_shuffle_epi8(X[3], vindex);

    //轮函数(反向迭代)
    for (int i = 31; i >= 0; i--) {
        __m128i k = _mm_set1_epi32(rk[i]);
        Tmp[0] = MM_XOR4(X[1], X[2], X[3], k);
        Tmp[0] = sm4_sbox_aesni(Tmp[0]);
        Tmp[0] = MM_XOR6(X[0], Tmp[0], MM_ROTL_EPI32(Tmp[0], 2),
                         MM_ROTL_EPI32(Tmp[0], 10), MM_ROTL_EPI32(Tmp[0], 18),
                         MM_ROTL_EPI32(Tmp[0], 24));
        X[0] = X[1];
        X[1] = X[2];
        X[2] = X[3];
        X[3] = Tmp[0];
    }

    //存储和解包数据
    X[0] = _mm_shuffle_epi8(X[0], vindex);
    X[1] = _mm_shuffle_epi8(X[1], vindex);
    X[2] = _mm_shuffle_epi8(X[2], vindex);
    X[3] = _mm_shuffle_epi8(X[3], vindex);

    _mm_storeu_si128((__m128i*)output + 0, MM_PACK0_EPI32(X[3], X[2], X[1], X[0]));
    _mm_storeu_si128((__m128i*)output + 1, MM_PACK1_EPI32(X[3], X[2], X[1], X[0]));
    _mm_storeu_si128((__m128i*)output + 2, MM_PACK2_EPI32(X[3], X[2], X[1], X[0]));
    _mm_storeu_si128((__m128i*)output + 3, MM_PACK3_EPI32(X[3], X[2], X[1], X[0]));
}
