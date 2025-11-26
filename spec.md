# 架構圖
```
musig2_project/
├── src/
│   ├── field.h
│   ├── field_impl.h
│   ├── field_5x52.h
│   ├── field_5x52_impl.h
│   ├── group.h
│   ├── group_impl.h
│   ├── scalar.h
│   ├── scalar_impl.h
│   ├── scalar_4x64.h
│   ├── scalar_4x64_impl.h
│   ├── ecmult.h
│   ├── ecmult_impl.h
│   ├── ecmult_gen.h
│   ├── ecmult_gen_impl.h
│   ├── eckey.h
│   ├── eckey_impl.h
│   ├── hash.h
│   ├── hash_impl.h
│   ├── util.h
│   └── （其他 secp256k1 的必要核心）
│
├── modules
│   ├── keyagg2.h
│   ├── keyagg2_impl.h
│   ├── session2.h
│   ├── session2_impl.h
│   ├── main2_impl.h
│   └── tests2_impl.h（選擇性）
└── main.c

```

# 需要實作的 MuSig2 module 檔案

## Module 架構（要實作的部分）

```
musig2_project/
├── modules/
│   ├── musig2/
│   ├── keyagg2.h
│   ├── keyagg2_impl.h
│   ├── session2.h
│   ├── session2_impl.h
│   ├── main2_impl.h
|   └── tests2_impl.h（use to verify）
```


---

### 1. keyagg2.h

📌 目的：定義 Musig2 公鑰聚合（Key Aggregation）API

你應該在這裡宣告外部可用的：

- `musig2_keyagg_coef()`
- `musig2_keyagg()`
- 一些必要的 struct（例如 keyagg cache）

####  要提供的 API 範例：

```c
int musig2_keyagg_coef(
    const secp256k1_pubkey *pubkeys,
    size_t n_keys,
    size_t index,
    secp256k1_scalar *a_i_out
);

int musig2_keyagg(
    const secp256k1_pubkey *pubkeys,
    size_t n_keys,
    secp256k1_ge *X_tilde_out
);
```

---

###  2. keyagg2_impl.h
目的：實作聚合公鑰建構公式
這裡要實作的 key-aggregation 公式：

---

#####  Key Aggregation Coefficient

給定公鑰集合：

$$  
L = { X_1, X_2, \dots, X_n }  
$$

對於第 $i$ 個 signer，你必須計算：

$$  
a_i = H_{\text{agg}}(L, X_i)  
$$

其中 $H_{\text{agg}}$ 是 domain-separated hash。

---

####  Aggregated Public Key

最後聚合公鑰為：

$$  
\tilde{X} = \prod_{i=1}^{n} X_i^{, a_i}  
$$

在 secp256k1 裡，表示為：

```
ge_mul(X_i, a_i)
```

並用 group-add 逐一疊加：

```
gej_add(X_tilde, a_i * X_i)
```

 你需要用到：

- group.h / group_impl.h（EC point add/double）
- scalar.h（純量）
- hash_impl.h（hash L and Xi）
---

###  3. session2.h

目的：定義 nonce 與簽章 session 資料結構

Musig2 的 session 需要保存：
- multiple nonces
- aggregated nonces
- message
- aggregated key
- challenge
- etc.

你應該定義以下 struct（示例）：

```c
typedef struct {
    secp256k1_scalar r[MU_N_NONCES]; // local secret nonces
    secp256k1_ge R[MU_N_NONCES];     // local public nonces
    secp256k1_ge R_agg;              // aggregated nonce
    secp256k1_scalar b_coeff;        // nonce coefficient
    secp256k1_scalar c_challenge;    // challenge
    secp256k1_ge X_tilde;            // aggregated key
} musig2_session;
```

---

###  4. session2_impl.h

目的：實作所有 Musig2 重要流程

#### 此檔最重要，主要包含：

---

#### (A) Round 1: Multi-nonce Sampling

每個 signer 產生多個 nonce：

$$  
r_{i,j} \leftarrow \mathbb{Z}_p  
$$

並計算它們的公開 nonce：
$$  
R_{i,j} = g^{, r_{i,j}}  
$$
所有 $j = 1, \dots, \nu$ 

---

####  (B) Nonce Aggregation

對所有 signer 的第 ( j ) 個 nonce 聚合：

$$  
R_j = \prod_{i=1}^{n} R_{i,j}  
$$

---

#### (C) Nonce Coefficient

Musig2 的 nonce hashing：

$$  
b = H_{\text{non}}(\tilde{X}, (R_1, \dots, R_\nu), m)  
$$

---

#### (D) Effective Nonce

Musig2 的有效 nonce 定義：

$$  
R = \prod_{j=1}^{\nu} R_j^{, b^{j-1}}  
$$

---

#### (E) Signature Challenge

標準 Schnorr 挑戰值：

$$  
c = H_{\text{sig}}(\tilde{X}, R, m)  
$$

此 ( c ) 最終會被所有 signer 共用。

---

#### (F) Partial Signature

每個 signer 的部分簽章：

$$  
s_i = c \cdot a_i \cdot x_i ;+; \sum_{j=1}^{\nu} r_{i,j} , b^{, j-1}  
$$

---

###  5. main2_impl.h

📌 目的：整合所有流程成「一條龍 Musig2 API」

你應提供高階 API，比如：

```c
int musig2_sign(
    const secp256k1_keypair *keypairs,
    const size_t n_signers,
    const unsigned char msg32[32],
    unsigned char final_sig64[64]
);
```

這個模組需依序呼叫：

1. KeyAgg
2. NonceGen
3. NonceAgg
4. NonceCoeff
5. Challenge
6. PartialSign
7. PartialAgg
8. OutputSignature (R, s)
    
相當於你之前整理的演算法：

$$  
\sigma = (R, s)  
$$

其中：

$$  
s = \sum_{i=1}^{n} s_i  
$$

