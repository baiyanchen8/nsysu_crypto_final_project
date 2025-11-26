/* src/modules/musig2/keyagg2.h */

#ifndef SECP256K1_MUSIG2_KEYAGG2_H
#define SECP256K1_MUSIG2_KEYAGG2_H

#include <stddef.h>

/* 這些是 secp256k1 的 internal headers */
#include "../src/group.h"
#include "../src/scalar.h"
#include "../src/hash.h"
#include "../src/util.h"
#include "../src/ecmult_const.h"

/* Demo 版：限制最大 signer 數量（可以依需求調整或改成動態配置） */
#define MUSIG2_MAX_SIGNERS 16

/* 
 * musig2_keyagg_cache
 *
 * 儲存：
 *  - $ \tilde{X} $：聚合公鑰
 *  - $ a_i $：每個 signer 的 key aggregation coefficient
 *  - $n$：signer 數量
 *
 * 公式：
 *  - $a_i = H_{\text{agg}}(L, X_i)$
 *  - $\tilde{X} = \prod_{i=1}^n X_i^{a_i}$
 */
typedef struct {
    secp256k1_ge    X_tilde;                   /* 聚合公鑰 $\tilde{X}$ */
    secp256k1_scalar a[MUSIG2_MAX_SIGNERS];    /* 每個 signer 的 $a_i$ */
    size_t          n_signers;
    int             is_initialized;
} musig2_keyagg_cache;

/* 
 * 計算單一 signer 的 $a_i = H_{\text{agg}}(L, X_i)$。
 *
 * 參數:
 *  - pubkeys   : EC 公鑰陣列，長度為 n_pubkeys（使用 secp256k1_ge）
 *  - n_pubkeys : signer 數量
 *  - index     : 要計算哪一個 signer 的 index（0-based）
 *  - a_i_out   : 輸出 scalar $a_i$
 *
 * 回傳:
 *  - 1 : 成功
 *  - 0 : 失敗（參數錯誤）
 */
int musig2_keyagg_coef(
    const secp256k1_ge *pubkeys,
    size_t n_pubkeys,
    size_t index,
    secp256k1_scalar *a_i_out
);

/*
 * 計算整體 key aggregation:
 *
 *  - 對所有 $i$ 算出 $a_i = H_{\text{agg}}(L, X_i)$
 *  - 計算 $\tilde{X} = \prod_{i=1}^n X_i^{a_i}$
 *  - 將 $a_i$ 與 $\tilde{X}$ 存進 cache
 *
 * 參數:
 *  - pubkeys      : EC 公鑰陣列（secp256k1_ge）
 *  - n_pubkeys    : signer 數量
 *  - cache        : 輸出 musig2_keyagg_cache
 *  - X_tilde_out  : 若非 NULL，輸出聚合公鑰（複製自 cache->X_tilde）
 *
 * 回傳:
 *  - 1 : 成功
 *  - 0 : 失敗
 */
int musig2_keyagg(
    const secp256k1_ge *pubkeys,
    size_t n_pubkeys,
    musig2_keyagg_cache *cache,
    secp256k1_ge *X_tilde_out
);

#endif /* SECP256K1_MUSIG2_KEYAGG2_H */
