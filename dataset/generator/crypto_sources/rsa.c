#include <stdint.h>

void montgomery_multiply(uint32_t *r, const uint32_t *a, const uint32_t *b, const uint32_t *n, uint32_t n0_inv, int len) {
    uint32_t t[64] = {0};
    for (int i = 0; i < len; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < len; j++) {
            uint64_t prod = (uint64_t)a[i] * b[j] + t[i + j] + carry;
            t[i + j] = (uint32_t)prod;
            carry = prod >> 32;
        }
        t[i + len] += (uint32_t)carry;

        uint32_t m = t[i] * n0_inv;
        carry = 0;
        for (int j = 0; j < len; j++) {
            uint64_t prod = (uint64_t)m * n[j] + t[i + j] + carry;
            t[i + j] = (uint32_t)prod;
            carry = prod >> 32;
        }
        for (int j = len; carry; j++) {
            uint64_t sum = (uint64_t)t[i + j] + carry;
            t[i + j] = (uint32_t)sum;
            carry = sum >> 32;
        }
    }
    for (int i = 0; i < len; i++) {
        r[i] = t[len + i];
    }
}

void rsa_mod_exp_65537(uint32_t *res, const uint32_t *base, const uint32_t *mod, int len) {
    uint32_t e = 65537; // RSA standard public exponent 0x10001
    uint32_t cur[32];
    for (int i = 0; i < len; i++) {
        cur[i] = base[i];
        res[i] = (i == 0) ? 1 : 0;
    }
    while (e > 0) {
        if (e & 1) {
            montgomery_multiply(res, res, cur, mod, 1, len);
        }
        montgomery_multiply(cur, cur, cur, mod, 1, len);
        e >>= 1;
    }
}
