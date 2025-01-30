#include "../include/hash.h"
/* permutation */

static void SHA3_transform(sha3 *sh)
{
    int k;
    unsign64 B00,B01,B02,B03,B04,B10,B11,B12,B13,B14,B20,B21,B22,B23,B24,B30,B31,B32,B33,B34,B40,B41,B42,B43,B44;
    unsign64 C0,C1,C2,C3,C4,D0,D1,D2,D3,D4;

    for (k = 0; k < SHA3_ROUNDS; k++)
    {

        C0=sh->S[0] ^ sh->S[5] ^ sh->S[10] ^ sh->S[15] ^ sh->S[20];
        C1=sh->S[1] ^ sh->S[6] ^ sh->S[11] ^ sh->S[16] ^ sh->S[21];
        C2=sh->S[2] ^ sh->S[7] ^ sh->S[12] ^ sh->S[17] ^ sh->S[22];
        C3=sh->S[3] ^ sh->S[8] ^ sh->S[13] ^ sh->S[18] ^ sh->S[23];
        C4=sh->S[4] ^ sh->S[9] ^ sh->S[14] ^ sh->S[19] ^ sh->S[24];

        D0 = C4 ^ rotl(C1, 1);
        D1 = C0 ^ rotl(C2, 1);
        D2 = C1 ^ rotl(C3, 1);
        D3 = C2 ^ rotl(C4, 1);
        D4 = C3 ^ rotl(C0, 1);

        B00 =      sh->S[0]^D0;
        B10 = rotl(sh->S[6]^D1, 44);
        B20 = rotl(sh->S[12]^D2, 43);
        B30 = rotl(sh->S[18]^D3, 21);
        B40 = rotl(sh->S[24]^D4, 14);    

        B01 = rotl(sh->S[3]^D3, 28);
        B11 = rotl(sh->S[9]^D4, 20);
        B21 = rotl(sh->S[10]^D0, 3);
        B31 = rotl(sh->S[16]^D1, 45);
        B41 = rotl(sh->S[22]^D2, 61);

        B02 = rotl(sh->S[1]^D1, 1);
        B12 = rotl(sh->S[7]^D2, 6);
        B22 = rotl(sh->S[13]^D3, 25);
        B32 = rotl(sh->S[19]^D4, 8);
        B42 = rotl(sh->S[20]^D0, 18);

        B03 = rotl(sh->S[4]^D4, 27);
        B13 = rotl(sh->S[5]^D0, 36);
        B23 = rotl(sh->S[11]^D1, 10);
        B33 = rotl(sh->S[17]^D2, 15);
        B43 = rotl(sh->S[23]^D3, 56);

        B04 = rotl(sh->S[2]^D2, 62);
        B14 = rotl(sh->S[8]^D3, 55);
        B24 = rotl(sh->S[14]^D4, 39);
        B34 = rotl(sh->S[15]^D0, 41);
        B44 = rotl(sh->S[21]^D1, 2);

        sh->S[0]=B00^(~B10&B20);
        sh->S[1]=B10^(~B20&B30);
        sh->S[2]=B20^(~B30&B40);
        sh->S[3]=B30^(~B40&B00);
        sh->S[4]=B40^(~B00&B10);

        sh->S[5]=B01^(~B11&B21);
        sh->S[6]=B11^(~B21&B31);
        sh->S[7]=B21^(~B31&B41);
        sh->S[8]=B31^(~B41&B01);
        sh->S[9]=B41^(~B01&B11);

        sh->S[10]=B02^(~B12&B22);
        sh->S[11]=B12^(~B22&B32);
        sh->S[12]=B22^(~B32&B42);
        sh->S[13]=B32^(~B42&B02);
        sh->S[14]=B42^(~B02&B12);

        sh->S[15]=B03^(~B13&B23);
        sh->S[16]=B13^(~B23&B33);
        sh->S[17]=B23^(~B33&B43);
        sh->S[18]=B33^(~B43&B03);
        sh->S[19]=B43^(~B03&B13);

        sh->S[20]=B04^(~B14&B24);
        sh->S[21]=B14^(~B24&B34);
        sh->S[22]=B24^(~B34&B44);
        sh->S[23]=B34^(~B44&B04);
        sh->S[24]=B44^(~B04&B14);

        sh->S[0] ^= RC[k];
    }
}

/* Re-Initialize. olen is output length in bytes -
   should be 28, 32, 48 or 64 (224, 256, 384, 512 bits resp.) */

void SHA3_init(sha3 *sh, int olen)
{
    int i;
    for (i = 0; i < 25; i++)
        sh->S[i] = 0;  /* 5x5x8 bytes = 200 bytes of state */
    sh->length = 0;
    sh->len = olen;
    sh->rate = 200 - 2 * olen; /* number of bytes consumed in one gulp. Note that some bytes in the
                            state ("capacity") are not touched. Gulps are smaller for larger digests.
                            Important that olen<rate */
}

/* process a single byte */
void SHA3_process(sha3 *sh, int byt)
{
    int cnt = (int)(sh->length);
    int b = cnt % 8;
    cnt /= 8;
    sh->S[cnt] ^= ((unsign64)(byt&0xff) << (8 * b));
    sh->length++;
    if (sh->length == sh->rate) {
        sh->length=0;
        SHA3_transform(sh);
    }
}

/* squeeze the sponge */
void SHA3_squeeze(sha3 *sh, char *buff, int len)
{
    int i, j, k, m = 0;
    unsign64 el;
    int nb=len/sh->rate;

    for (j=0;j<nb;j++ )
    {
        for (i=0;i<sh->rate/8;i++)
        {
            el=sh->S[i];
            for (k=0;k<8;k++)
            {
               buff[m++] = (el & 0xff);
               el >>= 8;
            }
        }
        SHA3_transform(sh);    
    }
   
    i=0;
    while (m<len)
    {
        el = sh->S[i++];
        for (k = 0; k < 8; k++)
        {
            buff[m++] = (el & 0xff);
            if (m >= len) break;
            el >>= 8;
        }    
    } 
}

void SHA3_hash(sha3 *sh, char *hash)
{
    /* generate a SHA3 hash of appropriate size */
    int q = sh->rate - sh->length;
    if (q == 1) SHA3_process(sh, 0x86);
    else
    {
        SHA3_process(sh, 0x06);  /* 0x06 for SHA-3 */
        while ((int)sh->length != sh->rate - 1) SHA3_process(sh, 0x00);
        SHA3_process(sh, 0x80); /* this will force a final transform */
    }
    SHA3_squeeze(sh, hash, sh->len);
}

/* return intermediate hash */
void SHA3_continuing_hash(sha3 *sh,char *digest)
{
    sha3 cp=*sh;
    SHA3_hash(&cp,digest);
}





