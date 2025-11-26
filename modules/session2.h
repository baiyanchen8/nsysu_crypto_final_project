/* src/modules/musig2/session2.h */

#ifndef SECP256K1_MUSIG2_SESSION2_H
#define SECP256K1_MUSIG2_SESSION2_H

#include <stddef.h>

#include "../src/group.h"
#include "../src/scalar.h"
#include "../src/hash.h"
#include "../src/util.h"
#include "keyagg2.h"

/* 固定 MuSig2 使用 2 個 nonces: ν = 2 */
#define MUSIG2_NONCE_COUNT 2

/* 單一 signer 本地 nonce 狀態：
 *   - r[j]: 秘密 nonce 標量 r_{i,j}
 *
 * 注意：為了簡化 demo，這裡不幫你做隨機生成，只負責保存。
 * 你可以在外面用自己的 RNG 產生 r_j 再呼叫 init。
 */
typedef struct {
    secp256k1_scalar r[MUSIG2_NONCE_COUNT]; /* r_{i,0}, r_{i,1} */
    int has_secret;
} musig2_nonce_state;

/* 聚合 nonces 狀態：
 *   - R_agg[j] : 聚合後的 R_j = ∏_i R_{i,j}
 *   - R_eff    : 有效 nonce R = R_1 * R_2^b  (對 ν=2 的情況)
 */
typedef struct {
    secp256k1_ge  R_agg[MUSIG2_NONCE_COUNT];
    secp256k1_ge  R_eff;
    int has_agg;
    int has_eff;
} musig2_nonce_agg_state;

/* 整個 MuSig2 session 狀態 */
typedef struct {
    musig2_keyagg_cache keyagg;   /* 內含 X̃ 與 a_i 陣列 */
    secp256k1_ge X_tilde;         /* 聚合公鑰 X̃ */
    unsigned char msg32[32];      /* 要簽的訊息哈希 */

    secp256k1_scalar b;           /* nonce coefficient b */
    secp256k1_scalar c;           /* Schnorr challenge c */

    size_t signer_index;          /* 本 signer 在 L 中的 index */
    int has_b;
    int has_c;
    int is_initialized;
} musig2_session;

/* === API 宣告，在 session2_impl.h 實作 ===================== */

/* 初始化 session
 *  - 帶入已經算好的 keyagg cache
 *  - 指定本 signer index
 *  - 設定 msg32
 */
int musig2_session_init(
    musig2_session *session,
    const musig2_keyagg_cache *keyagg,
    const unsigned char msg32[32],
    size_t signer_index
);

/* 初始化本地 nonce 狀態，把 r[0], r[1] 複製進來 */
int musig2_nonce_state_init(
    musig2_nonce_state *st,
    const secp256k1_scalar r[MUSIG2_NONCE_COUNT]
);

/* 聚合 nonces：
 *  - pub_R_all: 長度 = n_signers * MUSIG2_NONCE_COUNT
 *      格式：pub_R_all[i * MUSIG2_NONCE_COUNT + j] = R_{i,j}
 *
 *  - 輸出：
 *      R_agg[j] = ∏_i R_{i,j}
 */
int musig2_nonce_agg(
    const secp256k1_ge *pub_R_all,
    size_t n_signers,
    musig2_nonce_agg_state *agg_state
);

/* 計算：
 *   - b = H_non(X̃, (R_1,R_2), m)
 *   - R_eff = R_1 * R_2^b
 *   - c = H_sig(X̃, R_eff, m)
 */
int musig2_session_compute_bR_and_c(
    musig2_session *session,
    musig2_nonce_agg_state *agg_state
);

/* 計算本 signer 的 partial signature:
 *
 *  公式（ν=2）：
 *    s_i = c * a_i * x_i + r_{i,0} + r_{i,1} * b  (mod n)
 *
 *  - seckey : scalar x_i (私鑰)
 *  - nonce  : 本地 nonce_state（裡面有 r_{i,0}, r_{i,1}）
 */
int musig2_partial_sign(
    const musig2_session *session,
    const secp256k1_scalar *seckey,
    const musig2_nonce_state *nonce,
    secp256k1_scalar *s_i_out
);

/* 聚合所有 partial signatures：
 *   s = Σ s_i (mod n)
 */
int musig2_partial_sig_agg(
    const secp256k1_scalar *s_partials,
    size_t n_signers,
    secp256k1_scalar *s_out
);

#endif /* SECP256K1_MUSIG2_SESSION2_H */
