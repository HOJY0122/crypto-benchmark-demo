import time, os, math
import streamlit as st
import pandas as pd
from Crypto.Cipher import AES, Blowfish, PKCS1_OAEP
from Crypto.PublicKey import RSA, ECC
from Crypto.Util.Padding import pad, unpad
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

# ----------------------------------------------------------------
# helpers
# ----------------------------------------------------------------

def hexview(b: bytes, max_bytes: int = 64) -> str:
    """Pretty hex dump, truncated for display."""
    h = b[:max_bytes].hex()
    grouped = " ".join(h[i:i+2] for i in range(0, len(h), 2))
    if len(b) > max_bytes:
        grouped += f" … (+{len(b)-max_bytes} more bytes)"
    return grouped

def bignum(n: int, keep: int = 24) -> str:
    """Show a huge integer truncated, with digit count."""
    s = str(n)
    if len(s) <= keep * 2:
        return f"{s}  ({len(s)} digits)"
    return f"{s[:keep]} … {s[-keep:]}  ({len(s)} digits)"

def step(title: str, body: str, code: str | None = None):
    with st.expander(title, expanded=True):
        st.markdown(body)
        if code is not None:
            st.code(code, language="text")

# ----------------------------------------------------------------
# page setup
# ----------------------------------------------------------------

st.set_page_config(page_title="Crypto Demo System", page_icon=" ", layout="wide")

st.markdown("""
<style>
    .stApp { background: #0b1220; }
    h1,h2,h3,h4,p,label,.stMarkdown { color:#e6edf3 !important; }
    div[data-testid="stExpander"] { background:#111a2e; border:1px solid #1f2d4a; border-radius:10px; }
    div[data-testid="stMetric"] { background:#111a2e; border:1px solid #1f2d4a; border-radius:10px; padding:12px 16px; }
    div[data-testid="stMetricValue"] { color:#4fd1c5 !important; }
    .stButton>button { background:#1a2a4a; color:#4fd1c5; border:1px solid #2c3f66; }
    .stButton>button:hover { border-color:#4fd1c5; color:#e6edf3; }
    .ok  { color:#68d391 !important; font-weight:600; }
    .bad { color:#fc8181 !important; font-weight:600; }
</style>
""", unsafe_allow_html=True)

st.title("Cryptography Demo System")
st.caption("Symmetric vs Asymmetric · Interactive Input -> Process -> Output")

tab_walk, tab_aes, tab_bf, tab_rsa, tab_ecc, tab_bench = st.tabs(
    ["Code Walkthrough", "AES (Symmetric)", "Blowfish (Symmetric)",
     "RSA (Asymmetric)", "ECC (Asymmetric)", "Benchmark"]
)

# ================================================================
# AES TAB
# ================================================================
with tab_aes:
    st.subheader("AES — Advanced Encryption Standard")

    cfg, io = st.columns([1, 2])
    with cfg:
        st.markdown("**⚙ Configuration**")
        aes_bits = st.selectbox("Key size (bits)", [128, 192, 256], index=2)
        aes_mode = st.selectbox("Mode of operation", ["GCM (authenticated)", "CBC", "CTR", "ECB (insecure!)"])
        if aes_mode.startswith("ECB"):
            st.warning("ECB leaks patterns — shown for education only.")
    with io:
        st.markdown("**✍ Input**")
        aes_msg = st.text_area("Plaintext message", "Hello BMIT2043! This is a secret message.",
                               key="aes_in", height=90)
        go_aes = st.button("🔒 Encrypt with AES", key="go_aes")

    if go_aes and aes_msg:
        pt = aes_msg.encode("utf-8")
        key = os.urandom(aes_bits // 8)
        mode_name = aes_mode.split(" ")[0]
        t0 = time.perf_counter()

        step("Step 1 — Convert plaintext to bytes",
             f"UTF-8 encode the message → **{len(pt)} bytes**.",
             hexview(pt))

        step("Step 2 — Generate random secret key",
             f"`os.urandom({aes_bits//8})` → one **{aes_bits}-bit** key shared by sender & receiver "
             f"(this is what makes it *symmetric*).",
             hexview(key, 32))

        if mode_name == "GCM":
            cipher = AES.new(key, AES.MODE_GCM)
            ct, tag = cipher.encrypt_and_digest(pt)
            nonce = cipher.nonce
            step("Step 3 — Generate nonce (number used once)",
                 "GCM needs a unique nonce per message so identical plaintexts encrypt differently.",
                 hexview(nonce, 32))
            step("Step 4 — Encrypt + authenticate",
                 "GCM encrypts (CTR-style keystream XOR plaintext) **and** produces a 128-bit "
                 "authentication tag that detects any tampering.",
                 f"CIPHERTEXT: {hexview(ct)}\nAUTH TAG  : {hexview(tag, 32)}")
            dec = AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
        elif mode_name == "CBC":
            iv = os.urandom(16)
            padded = pad(pt, AES.block_size)
            ct = AES.new(key, AES.MODE_CBC, iv).encrypt(padded)
            step("Step 3 — Pad to 16-byte blocks (PKCS#7)",
                 f"AES is a block cipher: input must be a multiple of 16 bytes. "
                 f"{len(pt)} bytes → padded to **{len(padded)} bytes** "
                 f"({len(padded)//16} blocks).",
                 hexview(padded))
            step("Step 4 — Encrypt block-by-block with IV chaining",
                 "Each plaintext block is XORed with the previous ciphertext block before "
                 "encryption (the IV seeds block 1).",
                 f"IV        : {hexview(iv, 32)}\nCIPHERTEXT: {hexview(ct)}")
            dec = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), AES.block_size)
        elif mode_name == "CTR":
            cipher = AES.new(key, AES.MODE_CTR)
            ct = cipher.encrypt(pt)
            nonce = cipher.nonce
            step("Step 3 — Build keystream from counter",
                 "CTR turns AES into a stream cipher: encrypt nonce‖counter, XOR with plaintext. "
                 "No padding needed.",
                 f"NONCE     : {hexview(nonce, 32)}\nCIPHERTEXT: {hexview(ct)}")
            dec = AES.new(key, AES.MODE_CTR, nonce=nonce).decrypt(ct)
        else:  # ECB
            padded = pad(pt, AES.block_size)
            ct = AES.new(key, AES.MODE_ECB).encrypt(padded)
            step("Step 3 — Encrypt each block independently",
                 "⚠ Identical plaintext blocks → identical ciphertext blocks. "
                 "This is why ECB leaks structure.",
                 f"PADDED    : {hexview(padded)}\nCIPHERTEXT: {hexview(ct)}")
            dec = unpad(AES.new(key, AES.MODE_ECB).decrypt(ct), AES.block_size)

        ms = (time.perf_counter() - t0) * 1000
        ok = dec == pt
        step("Final step — Decrypt with the SAME key (verification)",
             f"Receiver uses the identical key → recovers the plaintext. "
             f"Match: {'✅ YES' if ok else '❌ NO'}",
             dec.decode("utf-8", "replace"))

        c1, c2, c3 = st.columns(3)
        c1.metric("Key size", f"{aes_bits} bits")
        c2.metric("Ciphertext size", f"{len(ct)} bytes")
        c3.metric("Total time", f"{ms:.3f} ms")

# ================================================================
# BLOWFISH TAB
# ================================================================
with tab_bf:
    st.subheader("Blowfish — legacy 64-bit block cipher")

    cfg, io = st.columns([1, 2])
    with cfg:
        st.markdown("**⚙ Configuration**")
        bf_bits = st.select_slider("Key size (bits)", options=[64, 128, 192, 256, 320, 448], value=256)
        bf_mode = st.selectbox("Mode", ["CBC", "ECB (insecure!)"], key="bf_mode")
    with io:
        st.markdown("**✍ Input**")
        bf_msg = st.text_area("Plaintext message", "Blowfish demo message", key="bf_in", height=90)
        go_bf = st.button("🔒 Encrypt with Blowfish", key="go_bf")

    if go_bf and bf_msg:
        pt = bf_msg.encode()
        key = os.urandom(bf_bits // 8)
        t0 = time.perf_counter()

        step("Step 1 — Variable-length key",
             f"Blowfish accepts 32–448 bit keys. Using **{bf_bits} bits**. Key setup is expensive "
             "(it rebuilds 4 S-boxes + P-array), which is why Blowfish is slow to re-key.",
             hexview(key, 56))

        padded = pad(pt, Blowfish.block_size)  # 8-byte blocks
        step("Step 2 — Pad to 8-byte blocks",
             f"Block size is only **64 bits (8 bytes)** — vs AES's 128. "
             f"{len(pt)} bytes → {len(padded)} bytes = **{len(padded)//8} blocks**. "
             "The small block size enables birthday attacks (SWEET32) on large data — "
             "a key reason Blowfish is considered legacy.",
             hexview(padded))

        if bf_mode.startswith("CBC"):
            iv = os.urandom(8)
            ct = Blowfish.new(key, Blowfish.MODE_CBC, iv).encrypt(padded)
            extra = f"IV        : {hexview(iv, 16)}\n"
            dec = unpad(Blowfish.new(key, Blowfish.MODE_CBC, iv).decrypt(ct), Blowfish.block_size)
        else:
            ct = Blowfish.new(key, Blowfish.MODE_ECB).encrypt(padded)
            extra = ""
            dec = unpad(Blowfish.new(key, Blowfish.MODE_ECB).decrypt(ct), Blowfish.block_size)

        step("Step 3 — Encrypt (16-round Feistel network)",
             "Each 8-byte block goes through 16 Feistel rounds using the key-dependent S-boxes.",
             f"{extra}CIPHERTEXT: {hexview(ct)}")

        ms = (time.perf_counter() - t0) * 1000
        ok = dec == pt
        step("Final step — Decrypt & verify",
             f"Match: {'✅ YES' if ok else '❌ NO'}", dec.decode("utf-8", "replace"))

        c1, c2, c3 = st.columns(3)
        c1.metric("Block size", "64 bits")
        c2.metric("Blocks", f"{len(padded)//8}")
        c3.metric("Total time", f"{ms:.3f} ms")

# ================================================================
# RSA TAB
# ================================================================
with tab_rsa:
    st.subheader("RSA — public-key encryption")

    cfg, io = st.columns([1, 2])
    with cfg:
        st.markdown("**⚙ Configuration**")
        rsa_bits = st.selectbox("Key size (bits)", [1024, 2048, 3072], index=1)
        if rsa_bits == 1024:
            st.warning("1024-bit RSA is breakable — demo only.")
    with io:
        st.markdown("**✍ Input**")
        rsa_msg = st.text_input("Message to encrypt (short — RSA encrypts small data only)",
                                "Secret AES key handoff!", key="rsa_in")
        go_rsa_key = st.button("① Generate key pair", key="go_rsa_key")
        go_rsa_enc = st.button("② Encrypt + decrypt message", key="go_rsa_enc",
                               disabled="rsa_key" not in st.session_state)

    if go_rsa_key:
        with st.spinner(f"Searching for two {rsa_bits//2}-bit primes…"):
            t0 = time.perf_counter()
            st.session_state.rsa_key = RSA.generate(rsa_bits)
            st.session_state.rsa_ms = (time.perf_counter() - t0) * 1000
        st.rerun()

    if "rsa_key" in st.session_state:
        k = st.session_state.rsa_key
        st.metric("Key generation time", f"{st.session_state.rsa_ms:.1f} ms")

        step("Process — Key generation math",
             "1. Pick two random primes **p, q**  →  2. **n = p × q** (the modulus)  →  "
             "3. φ(n) = (p−1)(q−1)  →  4. choose **e** (public exponent)  →  "
             "5. **d = e⁻¹ mod φ(n)** (private exponent).\n\n"
             "Security rests on: given n, factoring back into p and q is infeasible.",
             f"p (prime 1)      : {bignum(k.p)}\n"
             f"q (prime 2)      : {bignum(k.q)}\n"
             f"n = p × q        : {bignum(k.n)}\n"
             f"e (public)       : {k.e}\n"
             f"d (private)      : {bignum(k.d)}")

        st.markdown("🔓 **Public key** = (n, e) — share with anyone.  "
                    "🔒 **Private key** = d — never leaves the owner.")

        if go_rsa_enc and rsa_msg:
            pt = rsa_msg.encode()
            m_int = int.from_bytes(pt, "big")

            step("Step 1 — Message as a number",
                 "RSA operates on integers: the message bytes are interpreted as one big number **m** "
                 "(must be smaller than n — that's why RSA only encrypts small payloads like AES keys).",
                 f"m = {bignum(m_int)}")

            t0 = time.perf_counter()
            c_int = pow(m_int, k.e, k.n)          # textbook RSA for the math display
            enc_ms = (time.perf_counter() - t0) * 1000
            step("Step 2 — Encrypt with PUBLIC key:  c = mᵉ mod n",
                 f"Anyone can do this — e and n are public. ({enc_ms:.3f} ms)",
                 f"c = m^{k.e} mod n\nc = {bignum(c_int)}")

            t0 = time.perf_counter()
            m_back = pow(c_int, k.d, k.n)
            dec_ms = (time.perf_counter() - t0) * 1000
            recovered = m_back.to_bytes((m_back.bit_length() + 7) // 8, "big")
            step("Step 3 — Decrypt with PRIVATE key:  m = cᵈ mod n",
                 f"Only the holder of d can reverse it. ({dec_ms:.3f} ms — note: much slower than "
                 f"encryption because d is huge while e = {k.e} is tiny)",
                 f"m = c^d mod n\nRecovered: {recovered.decode('utf-8','replace')}  "
                 f"{'✅ match' if recovered == pt else '❌ mismatch'}")

            # real-world padding
            oaep_ct = PKCS1_OAEP.new(k.publickey()).encrypt(pt)
            step("Real-world note — OAEP padding",
                 "Textbook RSA above is deterministic → same message = same ciphertext (unsafe). "
                 "Production RSA adds random OAEP padding first:",
                 f"OAEP CIPHERTEXT: {hexview(oaep_ct)}")

# ================================================================
# ECC TAB
# ================================================================
with tab_ecc:
    st.subheader("ECC — elliptic curve cryptography")

    cfg, io = st.columns([1, 2])
    with cfg:
        st.markdown("**⚙ Configuration**")
        curve = st.selectbox("Curve", ["P-256", "P-384", "P-521"])
        sec = {"P-256": 128, "P-384": 192, "P-521": 256}[curve]
        st.info(f"≈ {sec}-bit security (RSA would need "
                f"{ {128:3072, 192:7680, 256:15360}[sec] }-bit keys for the same).")
    with io:
        st.markdown("**✍ Input**")
        ecc_msg = st.text_input("Message to sign (ECDSA)", "I approve this transaction", key="ecc_in")
        go_ecc = st.button("🔑 Generate keys + sign + verify", key="go_ecc")

    if go_ecc and ecc_msg:
        t0 = time.perf_counter()
        ek = ECC.generate(curve=curve)
        gen_ms = (time.perf_counter() - t0) * 1000

        step("Step 1 — Key generation (why ECC is fast)",
             f"Private key **d** = one random number. Public key **Q = d × G** "
             f"(scalar-multiply the curve's base point). One operation vs RSA's prime hunt "
             f"→ generated in **{gen_ms:.2f} ms**.\n\n"
             "Security rests on: given Q and G, finding d (the elliptic-curve discrete log) is infeasible.",
             f"d (private scalar): {bignum(int(ek.d))}\n"
             f"Q.x (public)      : {bignum(int(ek.pointQ.x))}\n"
             f"Q.y (public)      : {bignum(int(ek.pointQ.y))}")

        h = SHA256.new(ecc_msg.encode())
        step("Step 2 — Hash the message",
             "ECDSA signs a fixed-size SHA-256 digest, not the raw message.",
             f"SHA-256: {h.hexdigest()}")

        t0 = time.perf_counter()
        sig = DSS.new(ek, "fips-186-3").sign(h)
        sign_ms = (time.perf_counter() - t0) * 1000
        step("Step 3 — Sign with PRIVATE key",
             f"Produces signature (r, s) — {len(sig)} bytes total. ({sign_ms:.2f} ms)",
             hexview(sig, 96))

        t0 = time.perf_counter()
        try:
            DSS.new(ek.public_key(), "fips-186-3").verify(SHA256.new(ecc_msg.encode()), sig)
            verified = True
        except ValueError:
            verified = False
        ver_ms = (time.perf_counter() - t0) * 1000
        step("Step 4 — Verify with PUBLIC key",
             f"Anyone holding Q can check authenticity + integrity. ({ver_ms:.2f} ms)\n\n"
             f"Result: {'✅ signature VALID' if verified else '❌ INVALID'}")

        # tamper demo
        tampered = ecc_msg + "!"
        try:
            DSS.new(ek.public_key(), "fips-186-3").verify(SHA256.new(tampered.encode()), sig)
            t_ok = True
        except ValueError:
            t_ok = False
        step("Step 5 — Tamper test",
             f"Change the message to “{tampered}” and re-verify with the same signature:\n\n"
             f"Result: {'⚠ still valid (should not happen!)' if t_ok else '❌ REJECTED — tampering detected ✅'}")

# ================================================================
# BENCHMARK TAB — Original (exact) methodology, or Configurable
# ================================================================
with tab_bench:
    st.subheader("⏱ Performance Benchmark")

    bench_mode = st.radio(
        "Methodology",
        ["Original (exact code as submitted)", "Configurable"],
        horizontal=True,
    )

    if "bench" not in st.session_state:
        st.session_state.bench = {}

    # ------------------------------------------------------------
    # ORIGINAL MODE — loops, data sizes, and timing formula are
    # copied VERBATIM from the submitted script. Do not modify.
    # ------------------------------------------------------------
    if bench_mode.startswith("Original"):
        st.caption("100 iterations · AES: 1 MB · Blowfish: data[:1024] · "
                   "timing = (time.time()-start)*10 — identical to the report script.")

        r1, r2, r3, r4 = st.columns(4)

        if r1.button("Run AES-256", key="o_aes"):
            with st.spinner("AES-256 — 100 × 1 MB…"):
                # --- AES-256: Symmetric Encryption ---
                key_aes = os.urandom(32)           # 256-bit key
                data    = os.urandom(1024 * 1024)  # 1 MB of data
                start = time.time()
                for _ in range(100):
                    AES.new(key_aes, AES.MODE_GCM).encrypt_and_digest(data)
                st.session_state.bench["AES-256"] = ((time.time()-start)*10, "ms per MB")
            st.rerun()

        if r2.button("Run Blowfish", key="o_bf"):
            with st.spinner("Blowfish — 100 × 1 KB…"):
                data   = os.urandom(1024 * 1024)
                # --- Blowfish: Symmetric Encryption ---
                key_bf = os.urandom(32)            # 256-bit key
                start  = time.time()
                for _ in range(100):
                    Blowfish.new(key_bf, Blowfish.MODE_ECB).encrypt(data[:1024])
                st.session_state.bench["Blowfish"] = ((time.time()-start)*10, "ms per block")
            st.rerun()

        if r3.button("Run RSA-2048 ⚠ minutes", key="o_rsa"):
            with st.spinner("RSA-2048 — generating 100 key pairs (several minutes)…"):
                # --- RSA-2048: Asymmetric Key Generation ---
                start = time.time()
                for _ in range(100):
                    RSA.generate(2048)
                st.session_state.bench["RSA-2048 keygen"] = ((time.time()-start)*10, "ms per key pair")
            st.rerun()

        if r4.button("Run ECC-256", key="o_ecc"):
            with st.spinner("ECC P-256 — 100 key pairs…"):
                # --- ECC-256: Asymmetric Key Generation ---
                start = time.time()
                for _ in range(100):
                    ECC.generate(curve='P-256')
                st.session_state.bench["ECC-256 keygen"] = ((time.time()-start)*10, "ms per key pair")
            st.rerun()

    # ------------------------------------------------------------
    # CONFIGURABLE MODE — adjustable parameters, scaled timing
    # ------------------------------------------------------------
    else:
        st.caption("Adjustable parameters — timing formula scales with settings (total/n × 1000 ms).")
        b1, b2, b3 = st.columns(3)
        iters   = b1.slider("Iterations", 10, 200, 100, 10)
        mb_size = b2.slider("Symmetric data size (MB)", 1, 8, 1)
        rsa_it  = b3.slider("RSA iterations (each ≈ 0.5–3 s!)", 1, 20, 5)

        def per_iter_ms(total_s, n): return total_s / n * 1000

        r1, r2, r3, r4 = st.columns(4)
        if r1.button("Run AES-256-GCM", key="c_aes"):
            key, data = os.urandom(32), os.urandom(1024 * 1024 * mb_size)
            with st.spinner("AES…"):
                t0 = time.time()
                for _ in range(iters):
                    AES.new(key, AES.MODE_GCM).encrypt_and_digest(data)
                st.session_state.bench["AES-256"] = (per_iter_ms(time.time()-t0, iters)/mb_size, "ms per MB")
            st.rerun()
        if r2.button("Run Blowfish (full MB — fair)", key="c_bf"):
            key, data = os.urandom(32), os.urandom(1024 * 1024 * mb_size)
            with st.spinner("Blowfish…"):
                t0 = time.time()
                for _ in range(iters):
                    Blowfish.new(key, Blowfish.MODE_ECB).encrypt(data)
                st.session_state.bench["Blowfish"] = (per_iter_ms(time.time()-t0, iters)/mb_size, "ms per MB")
            st.rerun()
        if r3.button("Run RSA-2048 keygen", key="c_rsa"):
            with st.spinner(f"Generating {rsa_it} RSA key pairs…"):
                t0 = time.time()
                for _ in range(rsa_it):
                    RSA.generate(2048)
                st.session_state.bench["RSA-2048 keygen"] = (per_iter_ms(time.time()-t0, rsa_it), "ms per key pair")
            st.rerun()
        if r4.button("Run ECC P-256 keygen", key="c_ecc"):
            with st.spinner("ECC…"):
                t0 = time.time()
                for _ in range(iters):
                    ECC.generate(curve="P-256")
                st.session_state.bench["ECC-256 keygen"] = (per_iter_ms(time.time()-t0, iters), "ms per key pair")
            st.rerun()

    # ------------------------------------------------------------
    # shared results display
    # ------------------------------------------------------------
    if st.session_state.bench:
        st.divider()
        res = st.session_state.bench
        mcols = st.columns(len(res))
        for col, (name, (v, unit)) in zip(mcols, res.items()):
            col.metric(name, f"{v:.2f} {unit}")

        sym  = {k: v for k, (v, u) in res.items() if "keygen" not in k}
        asym = {k: v for k, (v, u) in res.items() if "keygen" in k}
        cc1, cc2 = st.columns(2)
        if sym:
            cc1.markdown("**Symmetric encryption time (ms, lower = faster)**")
            cc1.bar_chart(pd.DataFrame({"ms": sym.values()}, index=sym.keys()), color="#4fd1c5")
        if asym:
            cc2.markdown("**Asymmetric key generation (ms per key pair)**")
            cc2.bar_chart(pd.DataFrame({"ms": asym.values()}, index=asym.keys()), color="#f6ad55")

        if "RSA-2048 keygen" in res and "ECC-256 keygen" in res and res["ECC-256 keygen"][0] > 0:
            st.success(f"ECC keygen is **{res['RSA-2048 keygen'][0]/res['ECC-256 keygen'][0]:,.0f}× faster** "
                       f"than RSA-2048 at similar security.")

        if st.button("✕ Clear benchmark results"):
            st.session_state.bench = {}
            st.rerun()

# ================================================================
# 🏭 CODE WALKTHROUGH TAB — "bread factory tour" of the ORIGINAL
# script: each click executes the highlighted line(s) for real,
# shows the output, then moves to the next line.
# ================================================================
import html as _html

def _render_code(code_lines, active, executed):
    """Code panel with the current line highlighted like a factory station."""
    rows = []
    for i, ln in enumerate(code_lines):
        safe = _html.escape(ln) if ln else "&nbsp;"
        if i in active:
            rows.append(f'<div style="background:#14532d;border-left:4px solid #4ade80;'
                        f'padding:2px 8px;color:#d1fae5;">▶ {safe}</div>')
        elif i in executed:
            rows.append(f'<div style="border-left:4px solid #2c3f66;padding:2px 8px;'
                        f'color:#5b6b8c;">✓ {safe}</div>')
        else:
            rows.append(f'<div style="border-left:4px solid transparent;padding:2px 8px;'
                        f'color:#93a4c3;">&nbsp; {safe}</div>')
    return ('<pre style="background:#0d1526;border:1px solid #1f2d4a;border-radius:10px;'
            'padding:12px;font-size:0.85rem;line-height:1.7;overflow-x:auto;">'
            + "".join(rows) + "</pre>")

def _need_data(v):
    """`data` is defined in the AES section of the original script; recreate it
    identically if the user tours another algorithm first."""
    if "data" not in v:
        v["data"] = os.urandom(1024 * 1024)
    return v["data"]

# ---- step executors (each runs the REAL line and reports what happened) ----

def _aes_s0(v):
    v["key_aes"] = os.urandom(32)
    return ("🔑 Generated the 256-bit symmetric key (32 random bytes):\n\n"
            f"`{hexview(v['key_aes'], 32)}`")

def _aes_s1(v):
    v["data"] = os.urandom(1024 * 1024)
    return ("📦 Generated 1 MB (1,048,576 bytes) of random data to encrypt. First bytes:\n\n"
            f"`{hexview(v['data'], 24)}`")

def _timer_note(v):
    return ("⏱ Timer line reached. To keep the measurement honest, the clock starts the "
            "instant the loop executes on your next click — the time you spend reading "
            "this is **not** counted.")

def _aes_loop(v):
    start = time.time()
    for _ in range(100):
        AES.new(v["key_aes"], AES.MODE_GCM).encrypt_and_digest(v["data"])
    v["aes_elapsed"] = time.time() - start
    demo = AES.new(v["key_aes"], AES.MODE_GCM)
    ct, tag = demo.encrypt_and_digest(v["data"])
    return ("🏭 The production line ran: **100 iterations**, each encrypting the full 1 MB "
            f"with a fresh GCM nonce. Total loop time: **{v['aes_elapsed']*1000:.1f} ms**.\n\n"
            "Sample of what one iteration produces (display only, not timed):\n\n"
            f"CIPHERTEXT: `{hexview(ct, 24)}`\n\nAUTH TAG: `{hexview(tag, 16)}`")

def _aes_print(v):
    v["final"] = f"AES-256: {v['aes_elapsed']*10:.2f} ms per MB"
    return (f"🖨 The print line computes `(time.time()-start)*10` = total seconds ÷ 100 "
            f"iterations × 1000 = **milliseconds per MB**:\n\n### `{v['final']}`")

def _bf_s0(v):
    v["key_bf"] = os.urandom(32)
    return ("🔑 Generated the 256-bit Blowfish key (Blowfish accepts 32–448 bit keys):\n\n"
            f"`{hexview(v['key_bf'], 32)}`")

def _bf_loop(v):
    data = _need_data(v)
    start = time.time()
    for _ in range(100):
        Blowfish.new(v["key_bf"], Blowfish.MODE_ECB).encrypt(data[:1024])
    v["bf_elapsed"] = time.time() - start
    ct = Blowfish.new(v["key_bf"], Blowfish.MODE_ECB).encrypt(data[:1024])
    return ("🏭 100 iterations, each encrypting `data[:1024]` — the **first 1 KB slice** of the "
            "1 MB buffer (= 128 Blowfish blocks of 8 bytes each), in ECB mode. "
            f"Total: **{v['bf_elapsed']*1000:.1f} ms**.\n\n"
            f"Sample ciphertext (display only): `{hexview(ct, 24)}`")

def _bf_print(v):
    v["final"] = f"Blowfish: {v['bf_elapsed']*10:.2f} ms per block"
    return f"🖨 Result:\n\n### `{v['final']}`"

def _rsa_loop(v):
    start = time.time()
    for _ in range(100):
        RSA.generate(2048)
    v["rsa_elapsed"] = time.time() - start
    sample = RSA.generate(2048)
    return ("🏭 The heavy machinery: **100 × RSA-2048 key generation**. Each key requires "
            "hunting for two random 1024-bit primes — that's why this station took "
            f"**{v['rsa_elapsed']:.1f} seconds** total.\n\n"
            "Sample key pair (display only, not timed):\n\n"
            f"n (modulus): `{bignum(sample.n, 20)}`\n\ne (public): `{sample.e}`\n\n"
            f"d (private): `{bignum(sample.d, 20)}`")

def _rsa_print(v):
    v["final"] = f"RSA-2048 keygen: {v['rsa_elapsed']*10:.2f} ms"
    return f"🖨 Result — milliseconds **per key pair**:\n\n### `{v['final']}`"

def _ecc_loop(v):
    start = time.time()
    for _ in range(100):
        ECC.generate(curve='P-256')
    v["ecc_elapsed"] = time.time() - start
    sample = ECC.generate(curve='P-256')
    return ("🏭 **100 × ECC P-256 key generation.** Each key = pick one random 256-bit number d, "
            "compute Q = d×G. No prime hunting — the whole loop finished in "
            f"**{v['ecc_elapsed']*1000:.1f} ms**.\n\n"
            "Sample key (display only):\n\n"
            f"d (private): `{bignum(int(sample.d), 20)}`\n\n"
            f"Q.x (public): `{bignum(int(sample.pointQ.x), 20)}`")

def _ecc_print(v):
    v["final"] = f"ECC-256 keygen: {v['ecc_elapsed']*10:.2f} ms"
    return f"🖨 Result — milliseconds **per key pair**:\n\n### `{v['final']}`"

WALK = {
    "AES-256 — Symmetric Encryption": {
        "code": [
            "key_aes = os.urandom(32)           # 256-bit key",
            "data    = os.urandom(1024 * 1024)  # 1 MB of data",
            "start = time.time()",
            "for _ in range(100):",
            "    AES.new(key_aes, AES.MODE_GCM).encrypt_and_digest(data)",
            "print(f'AES-256: {(time.time()-start)*10:.2f} ms per MB')",
        ],
        "steps": [
            {"lines": [0], "title": "Station 1 — Make the secret key", "run": _aes_s0},
            {"lines": [1], "title": "Station 2 — Prepare 1 MB of raw material", "run": _aes_s1},
            {"lines": [2], "title": "Station 3 — Arm the stopwatch", "run": _timer_note},
            {"lines": [3, 4], "title": "Station 4 — Run the encryption line ×100", "run": _aes_loop},
            {"lines": [5], "title": "Station 5 — Package the result", "run": _aes_print},
        ],
    },
    "Blowfish — Symmetric Encryption": {
        "code": [
            "key_bf = os.urandom(32)            # 256-bit key",
            "start  = time.time()",
            "for _ in range(100):",
            "    Blowfish.new(key_bf, Blowfish.MODE_ECB).encrypt(data[:1024])",
            "print(f'Blowfish: {(time.time()-start)*10:.2f} ms per block')",
        ],
        "steps": [
            {"lines": [0], "title": "Station 1 — Make the Blowfish key", "run": _bf_s0},
            {"lines": [1], "title": "Station 2 — Arm the stopwatch", "run": _timer_note},
            {"lines": [2, 3], "title": "Station 3 — Encrypt the 1 KB slice ×100", "run": _bf_loop},
            {"lines": [4], "title": "Station 4 — Package the result", "run": _bf_print},
        ],
    },
    "RSA-2048 — Asymmetric Key Generation": {
        "code": [
            "start = time.time()",
            "for _ in range(100):",
            "    RSA.generate(2048)",
            "print(f'RSA-2048 keygen: {(time.time()-start)*10:.2f} ms')",
        ],
        "steps": [
            {"lines": [0], "title": "Station 1 — Arm the stopwatch", "run": _timer_note},
            {"lines": [1, 2], "title": "Station 2 — Forge 100 key pairs ⚠ takes MINUTES", "run": _rsa_loop},
            {"lines": [3], "title": "Station 3 — Package the result", "run": _rsa_print},
        ],
    },
    "ECC-256 — Asymmetric Key Generation": {
        "code": [
            "start = time.time()",
            "for _ in range(100):",
            "    ECC.generate(curve='P-256')",
            "print(f'ECC-256 keygen: {(time.time()-start)*10:.2f} ms')",
        ],
        "steps": [
            {"lines": [0], "title": "Station 1 — Arm the stopwatch", "run": _timer_note},
            {"lines": [1, 2], "title": "Station 2 — Forge 100 key pairs (fast!)", "run": _ecc_loop},
            {"lines": [3], "title": "Station 3 — Package the result", "run": _ecc_print},
        ],
    },
}

with tab_walk:
    st.subheader("🏭 Code Walkthrough — watch the algorithm run line by line")
    st.caption("Like touring a bread factory: each click executes the highlighted line(s) "
               "of the ORIGINAL report script for real, shows what came out, and moves on.")

    walk_algo = st.selectbox("Choose the production line to tour", list(WALK.keys()))

    w = st.session_state.setdefault("walk", {"algo": None, "step": 0, "log": [], "vars": {}})
    if w["algo"] != walk_algo:
        st.session_state.walk = w = {"algo": walk_algo, "step": 0, "log": [], "vars": {}}

    plan = WALK[walk_algo]
    steps, code_lines = plan["steps"], plan["code"]
    done_lines = [ln for s in steps[:w["step"]] for ln in s["lines"]]
    active = steps[w["step"]]["lines"] if w["step"] < len(steps) else []

    code_col, out_col = st.columns([1, 1])

    with code_col:
        st.markdown("**The algorithm (original script)**")
        st.markdown(_render_code(code_lines, active, done_lines), unsafe_allow_html=True)
        st.progress(w["step"] / len(steps),
                    text=f"Station {min(w['step']+1, len(steps))} of {len(steps)}")

        b1, b2 = st.columns(2)
        if w["step"] < len(steps):
            nxt = steps[w["step"]]
            label = "▶ Start the tour" if w["step"] == 0 else "▶ Next station"
            if b1.button(f"{label}: {nxt['title']}", key="walk_next", use_container_width=True):
                with st.spinner(f"Running: {nxt['title']}…"):
                    out = nxt["run"](w["vars"])
                w["log"].append((nxt["title"], out))
                w["step"] += 1
                st.rerun()
        if b2.button("⟲ Restart tour", key="walk_reset", use_container_width=True):
            st.session_state.walk = {"algo": walk_algo, "step": 0, "log": [], "vars": {}}
            st.rerun()

    with out_col:
        st.markdown("**What each station produced**")
        if not w["log"]:
            st.info("Click **Start the tour** — the first line of code lights up, runs, "
                    "and its output appears here.")
        for i, (title, out) in enumerate(w["log"], 1):
            with st.expander(f"✓ {title}", expanded=(i == len(w["log"]))):
                st.markdown(out)
        if w["step"] >= len(steps):
            st.success(f"🏁 End of the line — final product:  **`{w['vars'].get('final','')}`**")
            st.balloons()
