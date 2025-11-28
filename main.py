import hashlib
import secrets
from ecdsa import SECP256k1
from ecdsa.ecdsa import int_to_string, string_to_int

curve = SECP256k1
G = curve.generator
n = curve.order

# --------- 基礎工具 ---------

def rand_scalar():
    k = secrets.randbelow(n)
    return k if k != 0 else 1

def encode_x(P):
    return int_to_string(P.x()).rjust(32, b"\x00")

def tagged_hash(tag: str, data: bytes) -> int:
    tag_h = hashlib.sha256(tag.encode()).digest()
    h = hashlib.sha256(tag_h + tag_h + data).digest()
    return string_to_int(h) % n

def H_tag(tag: str, *args) -> int:
    data = b""
    for a in args:
        if isinstance(a, int):
            data += int_to_string(a).rjust(32, b"\x00")
        elif hasattr(a, "x"):  # Point
            data += encode_x(a)
            data += int_to_string(a.y()).rjust(32, b"\x00")
        elif isinstance(a, (bytes, bytearray)):
            data += a
        else:
            data += str(a).encode()
    return tagged_hash(tag, data)

# --------- Key aggregation ---------

def sort_pubkeys(pks):
    return sorted(pks, key=lambda P: encode_x(P))

def key_agg_coef(L, Xi):
    L_bytes = b"".join(encode_x(P) for P in L)
    return H_tag("MuSig2/AggCoeff", L_bytes, encode_x(Xi)) or 1

def key_agg(L):
    Ls = sort_pubkeys(L)
    Xe = None
    for Xi in Ls:
        ai = key_agg_coef(Ls, Xi)
        term = ai * Xi
        Xe = term if Xe is None else Xe + term
    return Xe

# --------- MuSig2 Demo ---------

def musig2_demo_step_by_step(n_signers=3, nu=2):
    print("==========================================")
    print("     MuSig2 Demo (逐步顯示 + 驗證成功)    ")
    print("==========================================")

    msg = b"MuSig2 test message"

    # 0. 產生 keypair
    print("\n[0] 產生 signer 金鑰：")
    sks = []
    pks = []
    for i in range(n_signers):
        sk = rand_scalar()
        pk = sk * G
        sks.append(sk)
        pks.append(pk)
        print(f"Signer {i+1}: sk={sk}, pk.x={pk.x()}")

    # 1. Key aggregation
    print("\n[1] Key Aggregation：")
    Ls = sort_pubkeys(pks)
    Xe = key_agg(Ls)
    print("Aggregate Public Key Xe.x =", Xe.x())

    # 2. Round 1: 每個 signer 產生 ν 個 nonce
    print("\n[2] Round 1：所有 signer 產生 nonce：")

    all_rs = []   # [ [r_i1, r_i2], ...]
    all_Rs = []   # [ [R_i1, R_i2], ...]

    for i in range(n_signers):
        rs_i = [rand_scalar() for _ in range(nu)]
        Rs_i = [r * G for r in rs_i]
        all_rs.append(rs_i)
        all_Rs.append(Rs_i)

        print(f"\nSigner {i+1}:")
        for j in range(nu):
            print(f"  r[{j+1}] = {rs_i[j]}")
            print(f"  R[{j+1}].x = {Rs_i[j].x()}")

    # 聚合每個 j 的 R_i,j
    print("\n→ 聚合 nonce：")
    agg_Rs = []
    for j in range(nu):
        Rj = None
        for i in range(n_signers):
            R_ij = all_Rs[i][j]
            Rj = R_ij if Rj is None else Rj + R_ij
        agg_Rs.append(Rj)
        print(f"R_agg[{j+1}].x = {Rj.x()}")

    # 3. Round 2: 算 b, R_eff, c
    print("\n[3] Round 2：計算 b, R, c，然後每個 signer 算 s_i")

    b = H_tag(
        "MuSig2/NonceCoeff",
        encode_x(Xe),
        *(encode_x(Rj) for Rj in agg_Rs),
        msg
    )
    print("\nNonce coefficient b =", b)

    # R = ∑_j b^{j} * R_j   (j from 0)
    R_eff = None
    for j, Rj in enumerate(agg_Rs):
        coeff = pow(b, j, n)
        term = coeff * Rj
        R_eff = term if R_eff is None else R_eff + term
    print("Effective R.x =", R_eff.x())

    c = H_tag("MuSig2/Challenge", encode_x(Xe), encode_x(R_eff), msg)
    print("Challenge c =", c)

    # 每個 signer 計算 a_i 與 s_i
    partial_sigs = []
    print("\n→ 每個 signer 計算部分簽章 s_i：")

    for i in range(n_signers):
        Xi = pks[i]
        ai = key_agg_coef(Ls, Xi)
        sk = sks[i]
        rs = all_rs[i]

        lin = 0
        for j, rj in enumerate(rs):
            lin = (lin + rj * pow(b, j, n)) % n

        s_i = (lin + c * ai * sk) % n
        partial_sigs.append(s_i)

        print(f"\nSigner {i+1}:")
        print(f"  ai = {ai}")
        print(f"  線性 nonce 和 (r1 + r2*b mod n...) = {lin}")
        print(f"  s_{i+1} = {s_i}")

    # 4. 聚合簽章
    s_final = sum(partial_sigs) % n

    print("\n[4] 最終簽章:")
    print("R.x =", R_eff.x())
    print("s   =", s_final)

    # 5. 驗證
    print("\n[5] 驗證簽章：")
    c_verify = H_tag("MuSig2/Challenge", encode_x(Xe), encode_x(R_eff), msg)

    LHS = s_final * G
    RHS = R_eff + c_verify * Xe

    print("LHS.x =", LHS.x() if LHS is not None else None)
    print("RHS.x =", RHS.x() if RHS is not None else None)

    if LHS == RHS:
        print("\n✔ 簽章驗證成功！")
    else:
        print("\n✘ 驗證失敗！")


if __name__ == "__main__":
    musig2_demo_step_by_step(n_signers=3, nu=2)

