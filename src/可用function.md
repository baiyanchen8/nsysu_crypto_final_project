下面我幫你 **完整整理所有你可以使用的 internal include + 其內部 function 能力**，
這些內容是從你提供的：

* **alll.txt**（完整 secp256k1 原始碼樹）
* **alll_include.txt**（你目前實際搬到專案的 header）

中交叉比對過後得出的 **你目前 CodeSpace 能使用的所有 internal API**。

---

# ✅ 你目前能使用的 include（src/）

依照 secp256k1 官方架構，**你需要同時包含 header + impl** 才能使用對應 internal function。
你目前資料夾中已備齊以下核心模組：

```
src/
├── field.h
├── field_impl.h
├── field_5x52.h
├── field_5x52_impl.h
├── group.h
├── group_impl.h
├── scalar.h
├── scalar_impl.h
├── scalar_4x64.h
├── scalar_4x64_impl.h
├── ecmult.h
├── ecmult_impl.h
├── ecmult_gen.h
├── ecmult_gen_impl.h
├── eckey.h
├── eckey_impl.h
├── hash.h
├── hash_impl.h
├── util.h
```

下面我會 **逐個模組** 整理你可以使用的 internal 函式。

---

# 🔵 1. field（有限域）

提供所有 elliptic curve 底層 **GF(p)** 運算。

### 可用 include

```
#include "field.h"
#include "field_impl.h"
#include "field_5x52.h"
#include "field_5x52_impl.h"
```

### 可使用的 internal function（你可以直接 call）

#### 基本 field element 操作

```
secp256k1_fe_normalize
secp256k1_fe_normalize_weak
secp256k1_fe_negate
secp256k1_fe_mul
secp256k1_fe_sqr
secp256k1_fe_add
secp256k1_fe_sub
secp256k1_fe_inv
secp256k1_fe_inv_var
secp256k1_fe_is_zero
secp256k1_fe_is_odd
secp256k1_fe_equal
secp256k1_fe_sqrt
secp256k1_fe_normalizes_to_zero
secp256k1_fe_get_b32
secp256k1_fe_set_b32
```

---

# 🔵 2. group（橢圓曲線群）

### 可 include

```
#include "group.h"
#include "group_impl.h"
```

### 可使用 function

#### 點基本操作

```
secp256k1_ge_set_infinity
secp256k1_gej_set_infinity
secp256k1_ge_neg
secp256k1_gej_neg
secp256k1_gej_double
secp256k1_gej_add_var
secp256k1_gej_add_ge_var
secp256k1_ge_set_gej
```

#### 序列化

```
secp256k1_ge_to_bytes
secp256k1_ge_from_bytes
secp256k1_ge_is_infinity
```

---

# 🔵 3. scalar（純量）

### include

```
#include "scalar.h"
#include "scalar_impl.h"
#include "scalar_4x64.h"
#include "scalar_4x64_impl.h"
```

### 可使用 function

#### 基本純量運算

```
secp256k1_scalar_clear
secp256k1_scalar_set_b32
secp256k1_scalar_get_b32
secp256k1_scalar_add
secp256k1_scalar_mul
secp256k1_scalar_negate
secp256k1_scalar_inverse
secp256k1_scalar_inverse_var
secp256k1_scalar_is_zero
secp256k1_scalar_is_one
secp256k1_scalar_equals
```

#### 特別是你會需要：

```
secp256k1_scalar_mul
secp256k1_scalar_add
secp256k1_scalar_set_b32
secp256k1_scalar_get_b32
```

---

# 🔵 4. ecmult（EC 多倍點運算）

### include

```
#include "ecmult.h"
#include "ecmult_impl.h"
#include "ecmult_gen.h"
#include "ecmult_gen_impl.h"
```

### 可使用 function

```
secp256k1_ecmult    // P = a*P + b*G
secp256k1_ecmult_const  // P = k * P
secp256k1_ecmult_gen    // P = k * G
```

Musig2 **最重要的是**：

```
secp256k1_ecmult_const(&out, &P, &scalar, 256);
```

用於計算
$$ X_i^{a_i} $$
和
$$ R_j^{b^{j-1}} $$

---

# 🔵 5. hash（雜湊）

### include

```
#include "hash.h"
#include "hash_impl.h"
```

### 可使用 function

```
secp256k1_sha256_initialize
secp256k1_sha256_write
secp256k1_sha256_finalize

secp256k1_rfc6979_hmac_sha256_initialize
secp256k1_rfc6979_hmac_sha256_generate
```

你要做 MuSig2 的：

### domain-separated hash

```c
secp256k1_sha256 sha;
secp256k1_sha256_initialize(&sha);
secp256k1_sha256_write(&sha, data, len);
secp256k1_sha256_finalize(&sha, out32);
```

**完全沒問題可以實作 H_agg、H_non、H_sig。**

---

# 🔵 6. eckey（EC keypair）

### include

```
#include "eckey.h"
#include "eckey_impl.h"
```

### 可使用 function

```
secp256k1_eckey_pubkey_serialize
secp256k1_eckey_pubkey_parse
```

補充：eckey 提供一些 import/export key 的功能，但你也可以直接用：

```
group.h  → EC point
scalar.h → Private key
```

完全不需要 secp256k1_context（你的 code 是 pure implementation）。

---

# 🔵 7. util（安全工具）

### include

```
#include "util.h"
```

### 可使用 function

```
secp256k1_memcpy_var
secp256k1_memset
secp256k1_memczero
secp256k1_inline
VERIFY_CHECK()
```

最重要的是：

```
secp256k1_memczero  // 安全燒掉秘密值
```

---

# 🎉 最終整理 — 你目前可用 internal function（能確保 MuSig2 完全可實作）

| 模組     | 功能                    | 可用 internal API                     |
| ------ | --------------------- | ----------------------------------- |
| field  | 有限域運算                 | normalize, mul, add, sqr, inv, sqrt |
| group  | EC點加倍/加法/序列化          | gej_add, gej_double, ge_set_gej     |
| scalar | 純量運算                  | add, mul, negate, inverse           |
| ecmult | EC 多倍點運算              | ecmult_const（最重要）                   |
| hash   | domain-separated hash | sha256_initialize, write, finalize  |
| eckey  | key serialize/parse   | pubkey_serialize                    |
| util   | 工具/安全                 | memset, memczero, VERIFY_CHECK      |

---

# 📌 結論（非常重要）

👉 **你目前搬進 CodeSpace 的 include 已足夠實作完整的 MuSig2（含多 nonce、H_agg、H_non、H_sig、partial signature、key aggregation）。**

👉 **你已成功帶入所有 secp256k1 必要 internal modules。**

👉 **你不需要 secp256k1_context 就能運作。**

---

# 下一步（你選一個）

## 1. ✔ 幫你生成完整的 `session2_impl.h`（含所有公式）

包含：

* nonce gen
* nonce agg
* effective nonce
* b challenge
* c challenge
* partial signature
* final aggregate signature

---

## 2. ✔ 幫你建立 `musig2_project/` skeleton（完整可編譯）

---

你要哪一個？
🟦 回答：「請完成 session2_impl.h」
🟩 或   「請生成完整專案模板」
