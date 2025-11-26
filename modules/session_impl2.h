/* src/modules/musig2/session2_impl.h */

#ifndef SECP256K1_MUSIG2_SESSION2_IMPL_H
#define SECP256K1_MUSIG2_SESSION2_IMPL_H

#include "session2.h"
#include "../src/ecmult_const.h"
#include "../src/ecmult_const_impl.h"

/* --- Tag 定義 -------------------------------------------------- */
/* b = H_non(X̃, (R_1,R_2), m) */
static const unsigned char MUSIG2_TAG_NONCE[] = "MuSig2/noncecoef";
/* c = H_sig(X̃, R, m)，沿用 BIP340 challenge tag */
static const unsigned char MUSIG2_TAG_SIG[]   = "BIP0340/challenge";

static secp256k1_sha256 musig2_tagged_hash_nonce_init;
static secp256k1_sha256 musig2_tagged_hash_sig_init;
static int musig2_tagged_nonce_inited = 0;
static int musig2_tagged_sig_inited   = 0;

/* 通用 tagged hash 初始化 helper */
static void musig2_init_tagged_hash(
    secp256k1_sha256 *init_state,
    int *flag,
    const unsigned char *tag,
    size_t taglen
) {
    if (*flag) return;
    secp256k1_sha256 sha;
    unsigned char taghash[32];

    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, tag, taglen);
    secp256k1_sha256_finalize(&sha, taghash);

    secp256k1_sha256_initialize(init_state);
    secp256k1_sha256_write(init_state, taghash, 32);
    secp256k1_sha256_write(init_state, taghash, 32);

    *flag = 1;
}

/*  H_non 用的初始化  */
static void musig2_init_nonce_tagged_hash(void) {
    musig2_init_tagged_hash(
        &musig2_tagged_hash_nonce_init,
        &musig2_tagged_nonce_inited,
        MUSIG2_TAG_NONCE,
        sizeof(MUSIG2_TAG_NONCE) - 1
    );
}

/*  H_sig 用的初始化  */
static void musig2_init_sig_tagged_hash(void) {
    musig2_init_tagged_hash(
        &musig2_tagged_hash_sig_init,
        &musig2_tagged_sig_inited,
        MUSIG2_TAG_SIG,
        sizeof(MUSIG2_TAG_SIG) - 1
    );
}

/* --- Session 初始化 --------------------------------------------- */

int musig2_session_init(
    musig2_session *session,
    const musig2_keyagg_cache *keyagg,
    const unsigned char msg32[32],
    size_t signer_index
) {
    size_t i;

    if (session == NULL || keyagg == NULL || msg32 == NULL) {
        return 0;
    }
    if (!keyagg->is_initialized) {
        return 0;
    }
    if (signer_index >= keyagg->n_signers) {
        return 0;
    }

    memset(session, 0, sizeof(*session));
    session->keyagg = *keyagg;          /* shallow copy */
    session->X_tilde = keyagg->X_tilde; /* 聚合公鑰 */

    for (i = 0; i < 32; i++) {
        session->msg32[i] = msg32[i];
    }

    session->signer_index = signer_index;
    session->is_initialized = 1;
    session->has_b = 0;
    session->has_c = 0;
    return 1;
}

/* --- Nonce state 初始化 ----------------------------------------- */

int musig2_nonce_state_init(
    musig2_nonce_state *st,
    const secp256k1_scalar r[MUSIG2_NONCE_COUNT]
) {
    size_t j;
    if (st == NULL || r == NULL) return 0;

    for (j = 0; j < MUSIG2_NONCE_COUNT; j++) {
        st->r[j] = r[j];
    }
    st->has_secret = 1;
    return 1;
}

/* --- Nonce Aggregation: R_agg[j] = ∏_i R_{i,j} ----------------- */

int musig2_nonce_agg(
    const secp256k1_ge *pub_R_all,
    size_t n_signers,
    musig2_nonce_agg_state *agg_state
) {
    size_t i, j;

    if (pub_R_all == NULL || agg_state == NULL) {
        return 0;
    }
    if (n_signers == 0 || n_signers > MUSIG2_MAX_SIGNERS) {
        return 0;
    }

    memset(agg_state, 0, sizeof(*agg_state));

    /* 對每個 j（0,1）分別做群加法 */
    for (j = 0; j < MUSIG2_NONCE_COUNT; j++) {
        secp256k1_gej Rj;
        secp256k1_gej_set_infinity(&Rj);

        for (i = 0; i < n_signers; i++) {
            const secp256k1_ge *Rij =
                &pub_R_all[i * MUSIG2_NONCE_COUNT + j];

            if (secp256k1_ge_is_infinity(Rij)) {
                continue;
            }
            secp256k1_gej_add_ge_var(&Rj, &Rj, Rij, NULL);
        }

        secp256k1_ge_set_gej(&agg_state->R_agg[j], &Rj);
    }

    agg_state->has_agg = 1;
    agg_state->has_eff = 0;
    return 1;
}

/* --- 計算 b, R_eff, c ------------------------------------------- */

/*
 * b = H_non(X̃, (R_0, R_1), m)
 *
 * 串接順序：
 *   ser(X̃.x) || ser(R_0.x) || ser(R_1.x) || msg32
 */
static void musig2_compute_b(
    secp256k1_scalar *b_out,
    const musig2_session *session,
    const musig2_nonce_agg_state *agg
) {
    secp256k1_sha256 sha;
    unsigned char buf[32];
    secp256k1_fe x;
    size_t i;

    VERIFY_CHECK(b_out != NULL);
    VERIFY_CHECK(session != NULL);
    VERIFY_CHECK(agg != NULL);
    VERIFY_CHECK(agg->has_agg);

    musig2_init_nonce_tagged_hash();
    sha = musig2_tagged_hash_nonce_init;

    /* ser(X̃.x) */
    x = session->X_tilde.x;
    secp256k1_fe_normalize(&x);
    secp256k1_fe_get_b32(buf, &x);
    secp256k1_sha256_write(&sha, buf, 32);

    /* ser(R_0.x), ser(R_1.x) */
    for (i = 0; i < MUSIG2_NONCE_COUNT; i++) {
        x = agg->R_agg[i].x;
        secp256k1_fe_normalize(&x);
        secp256k1_fe_get_b32(buf, &x);
        secp256k1_sha256_write(&sha, buf, 32);
    }

    /* msg32 */
    secp256k1_sha256_write(&sha, session->msg32, 32);

    secp256k1_sha256_finalize(&sha, buf);
    secp256k1_scalar_set_b32(b_out, buf, NULL);
}

/*
 * c = H_sig(X̃, R_eff, m)
 *
 *   這裡遵循 BIP340 風格：
 *   ser(R_eff.x) || ser(X̃.x) || msg32
 */
static void musig2_compute_c(
    secp256k1_scalar *c_out,
    const musig2_session *session,
    const musig2_nonce_agg_state *agg
) {
    secp256k1_sha256 sha;
    unsigned char buf[32];
    secp256k1_fe x;

    VERIFY_CHECK(c_out != NULL);
    VERIFY_CHECK(session != NULL);
    VERIFY_CHECK(agg != NULL);
    VERIFY_CHECK(agg->has_eff);

    musig2_init_sig_tagged_hash();
    sha = musig2_tagged_hash_sig_init;

    /* ser(R_eff.x) */
    x = agg->R_eff.x;
    secp256k1_fe_normalize(&x);
    secp256k1_fe_get_b32(buf, &x);
    secp256k1_sha256_write(&sha, buf, 32);

    /* ser(X̃.x) */
    x = session->X_tilde.x;
    secp256k1_fe_normalize(&x);
    secp256k1_fe_get_b32(buf, &x);
    secp256k1_sha256_write(&sha, buf, 32);

    /* msg32 */
    secp256k1_sha256_write(&sha, session->msg32, 32);

    secp256k1_sha256_finalize(&sha, buf);
    secp256k1_scalar_set_b32(c_out, buf, NULL);
}

int musig2_session_compute_bR_and_c(
    musig2_session *session,
    musig2_nonce_agg_state *agg_state
) {
    secp256k1_gej Rj;
    secp256k1_gej tmp;
    secp256k1_scalar b;
    size_t j;

    if (session == NULL || agg_state == NULL) {
        return 0;
    }
    if (!session->is_initialized) {
        return 0;
    }
    if (!agg_state->has_agg) {
        return 0;
    }

    /* 1. 算出 b */
    musig2_compute_b(&b, session, agg_state);
    session->b = b;
    session->has_b = 1;

    /* 2. 算出 R_eff = R_0 * R_1^b  (ν = 2) */
    secp256k1_gej_set_infinity(&Rj);

    /* 加上 R_0 */
    secp256k1_gej_add_ge_var(&Rj, &Rj, &agg_state->R_agg[0], NULL);

    /* 加上 R_1^b */
    {
        secp256k1_gej R1b;
        secp256k1_ecmult_const(&R1b, &agg_state->R_agg[1], &b);
        secp256k1_gej_add_var(&Rj, &Rj, &R1b, NULL);
    }

    secp256k1_ge_set_gej(&agg_state->R_eff, &Rj);
    agg_state->has_eff = 1;

    /* 3. 算出 c */
    musig2_compute_c(&session->c, session, agg_state);
    session->has_c = 1;

    return 1;
}

/* --- Partial signature ------------------------------------------- */

/*
 * s_i = c * a_i * x_i + r_{i,0} + r_{i,1} * b   (mod n)
 */
int musig2_partial_sign(
    const musig2_session *session,
    const secp256k1_scalar *seckey,
    const musig2_nonce_state *nonce,
    secp256k1_scalar *s_i_out
) {
    secp256k1_scalar ai, tmp, si;

    if (session == NULL || seckey == NULL || nonce == NULL || s_i_out == NULL) {
        return 0;
    }
    if (!session->is_initialized || !session->has_b || !session->has_c) {
        return 0;
    }
    if (!nonce->has_secret) {
        return 0;
    }
    if (session->signer_index >= session->keyagg.n_signers) {
        return 0;
    }

    /* 取得本 signer 的 a_i */
    ai = session->keyagg.a[session->signer_index];

    /* tmp = c * a_i */
    secp256k1_scalar_mul(&tmp, &session->c, &ai);

    /* tmp = tmp * x_i = c * a_i * x_i */
    secp256k1_scalar_mul(&tmp, &tmp, seckey);

    /* si  = r_{i,1} * b */
    secp256k1_scalar_mul(&si, &nonce->r[1], &session->b);

    /* si += r_{i,0} */
    secp256k1_scalar_add(&si, &si, &nonce->r[0]);

    /* si += c * a_i * x_i */
    secp256k1_scalar_add(&si, &si, &tmp);

    *s_i_out = si;
    return 1;
}

/* --- Aggregation: s = Σ s_i mod n ------------------------------- */

int musig2_partial_sig_agg(
    const secp256k1_scalar *s_partials,
    size_t n_signers,
    secp256k1_scalar *s_out
) {
    size_t i;
    secp256k1_scalar s;

    if (s_partials == NULL || s_out == NULL) {
        return 0;
    }
    if (n_signers == 0 || n_signers > MUSIG2_MAX_SIGNERS) {
        return 0;
    }

    secp256k1_scalar_clear(&s);
    for (i = 0; i < n_signers; i++) {
        secp256k1_scalar_add(&s, &s, &s_partials[i]);
    }

    *s_out = s;
    return 1;
}

#endif /* SECP256K1_MUSIG2_SESSION2_IMPL_H */
