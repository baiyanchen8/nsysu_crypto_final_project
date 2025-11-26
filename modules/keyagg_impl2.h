/* src/modules/musig2/keyagg2_impl.h */

#ifndef SECP256K1_MUSIG2_KEYAGG2_IMPL_H
#define SECP256K1_MUSIG2_KEYAGG2_IMPL_H

#include "keyagg2.h"

/* 
 * Domain separation tag for H_agg:
 * $ H_{\text{agg}}(L, X_i) = \text{SHA256}(\text{tag} \parallel \text{tag} \parallel \text{ser}(L) \parallel \text{ser}(X_i)) $
 */
static const unsigned char MUSIG2_TAG_AGG[] = "MuSig2/agg";
/* 預先計算好的 tagged hash 初始 state，用來避免重複計算 taghash */
static secp256k1_sha256 musig2_tagged_hash_agg_init_state;
static int musig2_tagged_hash_agg_state_inited = 0;

/* 初始化 H_agg 的 tagged hash 初始 state: 
 * taghash = SHA256("MuSig2/agg")
 * 初始 state = SHA256(taghash || taghash)
 */
static void musig2_init_agg_tagged_hash(void) {
    if (musig2_tagged_hash_agg_state_inited) {
        return;
    }
    secp256k1_sha256 sha;
    unsigned char taghash[32];

    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, MUSIG2_TAG_AGG, sizeof(MUSIG2_TAG_AGG) - 1);
    secp256k1_sha256_finalize(&sha, taghash);

    secp256k1_sha256_initialize(&musig2_tagged_hash_agg_init_state);
    secp256k1_sha256_write(&musig2_tagged_hash_agg_init_state, taghash, 32);
    secp256k1_sha256_write(&musig2_tagged_hash_agg_init_state, taghash, 32);

    musig2_tagged_hash_agg_state_inited = 1;
}

/*
 * 計算 $ H_{\text{agg}}(L, X_i) $ 並轉成 scalar：
 *
 *  - $L = \{ X_1, \dots, X_n \}$
 *  - ser(L)  = 依序串接每個 $X_k$ 的 32-byte x-only 座標
 *  - ser(X_i)= $X_i$ 的 32-byte x-only 座標
 *
 * out = scalar( SHA256(tag || tag || ser(L) || ser(X_i)) )
 */
static void musig2_hash_agg(
    secp256k1_scalar *out,
    const secp256k1_ge *pubkeys,
    size_t n_pubkeys,
    const secp256k1_ge *Xi
) {
    secp256k1_sha256 sha;
    unsigned char buf[32];
    size_t i;

    VERIFY_CHECK(out != NULL);
    VERIFY_CHECK(pubkeys != NULL);
    VERIFY_CHECK(Xi != NULL);
    VERIFY_CHECK(n_pubkeys > 0 && n_pubkeys <= MUSIG2_MAX_SIGNERS);

    musig2_init_agg_tagged_hash();
    /* 複製初始 tagged state */
    sha = musig2_tagged_hash_agg_init_state;

    /* ser(L): 把所有 pubkeys 的 x (x-only) 序列化進 hash */
    for (i = 0; i < n_pubkeys; i++) {
        secp256k1_fe fe_x = pubkeys[i].x;
        secp256k1_fe_normalize(&fe_x);
        secp256k1_fe_get_b32(buf, &fe_x);
        secp256k1_sha256_write(&sha, buf, 32);
    }

    /* ser(X_i): 把 Xi 的 x (x-only) 序列化進 hash */
    {
        secp256k1_fe fe_x = Xi->x;
        secp256k1_fe_normalize(&fe_x);
        secp256k1_fe_get_b32(buf, &fe_x);
        secp256k1_sha256_write(&sha, buf, 32);
    }

    /* 最終計算出 32-byte hash 並轉成 scalar 模 $n$ */
    secp256k1_sha256_finalize(&sha, buf);
    secp256k1_scalar_set_b32(out, buf, NULL);
}

/* 對外 API: 單一 a_i 計算 */
int musig2_keyagg_coef(
    const secp256k1_ge *pubkeys,
    size_t n_pubkeys,
    size_t index,
    secp256k1_scalar *a_i_out
) {
    if (pubkeys == NULL || a_i_out == NULL) {
        return 0;
    }
    if (n_pubkeys == 0 || n_pubkeys > MUSIG2_MAX_SIGNERS) {
        return 0;
    }
    if (index >= n_pubkeys) {
        return 0;
    }

    musig2_hash_agg(a_i_out, pubkeys, n_pubkeys, &pubkeys[index]);
    return 1;
}

/* 
 * musig2_keyagg:
 *
 *  - 對所有公鑰 $X_i$ 計算 $a_i = H_{\text{agg}}(L, X_i)$
 *  - 以 EC 群計算：
 *      $$ \tilde{X} = \sum_{i=1}^n a_i \cdot X_i $$
 *    （在橢圓曲線上是加法；與抽象群中 $\prod X_i^{a_i}$ 對應）
 *
 *  - 並將結果填入 cache。
 */
int musig2_keyagg(
    const secp256k1_ge *pubkeys,
    size_t n_pubkeys,
    musig2_keyagg_cache *cache,
    secp256k1_ge *X_tilde_out
) {
    secp256k1_gej Xj;
    size_t i;

    if (pubkeys == NULL || cache == NULL) {
        return 0;
    }
    if (n_pubkeys == 0 || n_pubkeys > MUSIG2_MAX_SIGNERS) {
        return 0;
    }

    memset(cache, 0, sizeof(*cache));
    cache->n_signers = n_pubkeys;

    secp256k1_gej_set_infinity(&Xj);

    for (i = 0; i < n_pubkeys; i++) {
        secp256k1_scalar ai;
        secp256k1_gej tmpj;

        /* a_i = H_agg(L, X_i) */
        musig2_hash_agg(&ai, pubkeys, n_pubkeys, &pubkeys[i]);
        cache->a[i] = ai;

        /* tmp = a_i * X_i */
        /* 這裡使用 ecmult_const：tmpj = a_i * pubkeys[i] */
        secp256k1_ecmult_const(&tmpj, &pubkeys[i], &ai);

        /* Xj += tmpj */
        secp256k1_gej_add_var(&Xj, &Xj, &tmpj, NULL);
    }

    /* X_tilde = affine(Xj) */
    secp256k1_ge_set_gej(&cache->X_tilde, &Xj);
    cache->is_initialized = 1;

    if (X_tilde_out != NULL) {
        *X_tilde_out = cache->X_tilde;
    }
    return 1;
}

#endif /* SECP256K1_MUSIG2_KEYAGG2_IMPL_H */
