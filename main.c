#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include "monokex.h"
#include "monocypher.h"

typedef uint8_t u8;

void xk1_manual(void) {
    crypto_kex_ctx c, s;
    u8 c_seed[32] = {111};
    u8 s_seed[32] = {222};
    u8 cs[32] = {100};
    u8 ss[32] = {200};
    u8 cp[32]; crypto_x25519_public_key(cp, cs);
    u8 sp[32]; crypto_x25519_public_key(sp, ss);
    u8  d[64];
    u8  k[32];
    u8 ckey[32], cextra[32], skey[32], sextra[32];

    crypto_kex_xk1_client_init(&c, c_seed, cs, cp, sp);
    crypto_kex_xk1_server_init(&s, s_seed, ss, sp);

    crypto_kex_write(&c, d, 32);
    crypto_kex_read(&s, d, 32);

    crypto_kex_write(&s, d, 48);
    crypto_kex_read(&c, d, 48);

    crypto_kex_write(&c, d, 64);
    crypto_kex_read(&s, d, 64);
    crypto_kex_remote_key(&s, k);

    crypto_kex_final(&c, ckey, cextra);
    crypto_kex_final(&s, skey, sextra);
}

int main(void) {
    xk1_manual();
    return 0;
}
