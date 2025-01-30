#ifndef __HASH__
#define __HASH__
#include <stdio.h>
#include <stdlib.h>
#define H0_256 0x6A09E667L
#define H1_256 0xBB67AE85L
#define H2_256 0x3C6EF372L
#define H3_256 0xA54FF53AL
#define H4_256 0x510E527FL
#define H5_256 0x9B05688CL
#define H6_256 0x1F83D9ABL
#define H7_256 0x5BE0CD19L
#include <stdint.h>
#include <stdbool.h>
#define byte uint8_t            /**< 8-bit unsigned integer */
#define sign8 int8_t            /**< 8-bit signed integer */
#define sign16 int16_t          /**< 16-bit signed integer */
#define sign32 int32_t          /**< 32-bit signed integer */
#define sign64 int64_t          /**< 64-bit signed integer */
#define unsign32 uint32_t       /**< 32-bit unsigned integer */
#define unsign64 uint64_t       /**< 64-bit unsigned integer */
static const unsign32 K_256[64] =
{
    0x428a2f98L, 0x71374491L, 0xb5c0fbcfL, 0xe9b5dba5L, 0x3956c25bL, 0x59f111f1L, 0x923f82a4L, 0xab1c5ed5L,
    0xd807aa98L, 0x12835b01L, 0x243185beL, 0x550c7dc3L, 0x72be5d74L, 0x80deb1feL, 0x9bdc06a7L, 0xc19bf174L,
    0xe49b69c1L, 0xefbe4786L, 0x0fc19dc6L, 0x240ca1ccL, 0x2de92c6fL, 0x4a7484aaL, 0x5cb0a9dcL, 0x76f988daL,
    0x983e5152L, 0xa831c66dL, 0xb00327c8L, 0xbf597fc7L, 0xc6e00bf3L, 0xd5a79147L, 0x06ca6351L, 0x14292967L,
    0x27b70a85L, 0x2e1b2138L, 0x4d2c6dfcL, 0x53380d13L, 0x650a7354L, 0x766a0abbL, 0x81c2c92eL, 0x92722c85L,
    0xa2bfe8a1L, 0xa81a664bL, 0xc24b8b70L, 0xc76c51a3L, 0xd192e819L, 0xd6990624L, 0xf40e3585L, 0x106aa070L,
    0x19a4c116L, 0x1e376c08L, 0x2748774cL, 0x34b0bcb5L, 0x391c0cb3L, 0x4ed8aa4aL, 0x5b9cca4fL, 0x682e6ff3L,
    0x748f82eeL, 0x78a5636fL, 0x84c87814L, 0x8cc70208L, 0x90befffaL, 0xa4506cebL, 0xbef9a3f7L, 0xc67178f2L
};

#define PAD  0x80
#define ZERO 0

/* functions */

#define S(m,n,x) (((x)>>n) | ((x)<<(m-n)))
#define R(n,x) ((x)>>n)

#define Ch(x,y,z)  ((x&y)^(~(x)&z))
#define Maj(x,y,z) ((x&y)^(x&z)^(y&z))
#define Sig0_256(x)    (S(32,2,x)^S(32,13,x)^S(32,22,x))
#define Sig1_256(x)    (S(32,6,x)^S(32,11,x)^S(32,25,x))
#define theta0_256(x)  (S(32,7,x)^S(32,18,x)^R(3,x))
#define theta1_256(x)  (S(32,17,x)^S(32,19,x)^R(10,x))

#define Sig0_512(x)    (S(64,28,x)^S(64,34,x)^S(64,39,x))
#define Sig1_512(x)    (S(64,14,x)^S(64,18,x)^S(64,41,x))
#define theta0_512(x)  (S(64,1,x)^S(64,8,x)^R(7,x))
#define theta1_512(x)  (S(64,19,x)^S(64,61,x)^R(6,x))

typedef struct
{
    unsign32 length[2]; /**< 64-bit input length */
    unsign32 h[8];      /**< Internal state */
    unsign32 w[64];	/**< Internal state */
    int hlen;		/**< Hash length in bytes */
} hash256;

/**
 * @brief SHA384-512 hash function instance */
typedef struct
{
    unsign64 length[2]; /**< 64-bit input length */
    unsign64 h[8];      /**< Internal state */
    unsign64 w[80];	/**< Internal state */
    int hlen;           /**< Hash length in bytes */
} hash512;

/**
 * @brief SHA384 hash function instance */
typedef hash512 hash384;

/**
 * @brief SHA3 hash function instance */
typedef struct
{
    int length;   /**< 64-bit input length */
    unsign64 S[25];  /**< Internal state */
    int rate;          /**< TODO */
    int len;           /**< Hash length in bytes */
} sha3;

#define MC_SHA3 3       /**< SHA3 family member */


#define SHA3_HASH224 28 /**< SHA3 224 bit hash */
#define SHA3_HASH256 32 /**< SHA3 256 bit hash */
#define SHA3_HASH384 48 /**< SHA3 384 bit hash */
#define SHA3_HASH512 64 /**< SHA3 512 bit hash */


#define H0_512 0x6a09e667f3bcc908
#define H1_512 0xbb67ae8584caa73b
#define H2_512 0x3c6ef372fe94f82b
#define H3_512 0xa54ff53a5f1d36f1
#define H4_512 0x510e527fade682d1
#define H5_512 0x9b05688c2b3e6c1f
#define H6_512 0x1f83d9abfb41bd6b
#define H7_512 0x5be0cd19137e2179

#define H8_512 0xcbbb9d5dc1059ed8
#define H9_512 0x629a292a367cd507
#define HA_512 0x9159015a3070dd17
#define HB_512 0x152fecd8f70e5939
#define HC_512 0x67332667ffc00b31
#define HD_512 0x8eb44a8768581511
#define HE_512 0xdb0c2e0d64f98fa7
#define HF_512 0x47b5481dbefa4fa4

/* */

static const unsign64 K_512[80] =
{
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};


/* SHA3 */

#define SHA3_ROUNDS 24
#define rotl(x,n) (((x)<<n) | ((x)>>(64-n)))

/* round constants */

static const unsign64 RC[24] =
{
    0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808AUL, 0x8000000080008000UL,
    0x000000000000808BUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
    0x000000000000008AUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000AUL,
    0x000000008000808BUL, 0x800000000000008BUL, 0x8000000000008089UL, 0x8000000000008003UL,
    0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800AUL, 0x800000008000000AUL,
    0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL
};
void SHA3_init(sha3 *sh, int olen);
void SHA3_process(sha3 *sh, int byt);
void SHA3_squeeze(sha3 *sh, char *buff, int len);
void SHA3_hash(sha3 *sh, char *hash);


#endif