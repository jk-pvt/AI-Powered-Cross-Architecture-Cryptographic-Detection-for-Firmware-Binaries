#include <stdint.h>

#define F(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | ~(z)))
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define FF(a, b, c, d, x, s, ac) { (a) += F((b), (c), (d)) + (x) + (uint32_t)(ac); (a) = ROTL((a), (s)); (a) += (b); }
#define GG(a, b, c, d, x, s, ac) { (a) += G((b), (c), (d)) + (x) + (uint32_t)(ac); (a) = ROTL((a), (s)); (a) += (b); }
#define HH(a, b, c, d, x, s, ac) { (a) += H((b), (c), (d)) + (x) + (uint32_t)(ac); (a) = ROTL((a), (s)); (a) += (b); }
#define II(a, b, c, d, x, s, ac) { (a) += I((b), (c), (d)) + (x) + (uint32_t)(ac); (a) = ROTL((a), (s)); (a) += (b); }

void md5_transform(uint32_t state[4], const uint32_t block[16]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];

    FF(a, b, c, d, block[0], 7, 0xd76aa478);
    FF(d, a, b, c, block[1], 12, 0xe8c7b756);
    FF(c, d, a, b, block[2], 17, 0x242070db);
    FF(b, c, d, a, block[3], 22, 0xc1bdceee);
    FF(a, b, c, d, block[4], 7, 0xf57c0faf);
    FF(d, a, b, c, block[5], 12, 0x4787c62a);
    FF(c, d, a, b, block[6], 17, 0xa8304613);
    FF(b, c, d, a, block[7], 22, 0xfd469501);

    GG(a, b, c, d, block[1], 5, 0xf61e2562);
    GG(d, a, b, c, block[6], 9, 0xc040b340);
    GG(c, d, a, b, block[11], 14, 0x265e5a51);
    GG(b, c, d, a, block[0], 20, 0xe9b6c7aa);

    HH(a, b, c, d, block[5], 4, 0xfffa3942);
    HH(d, a, b, c, block[8], 11, 0x8771f681);
    HH(c, d, a, b, block[11], 16, 0x6d9d6122);
    HH(b, c, d, a, block[14], 23, 0xfde5380c);

    II(a, b, c, d, block[0], 6, 0xf4292244);
    II(d, a, b, c, block[7], 10, 0x432aff97);
    II(c, d, a, b, block[14], 15, 0xab9423a7);
    II(b, c, d, a, block[5], 21, 0xfc93a039);

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
}
