"""
Crypto Benchmark Demo — BMIT2043
UI wrapper only. The benchmark algorithms below are UNCHANGED from the
original script: same keys, same data sizes, same 100 iterations,
same timing formula ((time.time()-start)*10).
"""

import time, os
import streamlit as st
import pandas as pd
from Crypto.Cipher import AES, Blowfish
from Crypto.PublicKey import RSA, ECC

# ---------------------------------------------------------------
# ORIGINAL ALGORITHMS (do not modify — copied verbatim into funcs)
# ---------------------------------------------------------------

def bench_aes():
    key_aes = os.urandom(32)           # 256-bit key
    data    = os.urandom(1024 * 1024)  # 1 MB of data
    start = time.time()
    for _ in range(100):
        AES.new(key_aes, AES.MODE_GCM).encrypt_and_digest(data)
    return (time.time() - start) * 10  # ms per MB

def bench_blowfish():
    data   = os.urandom(1024 * 1024)
    key_bf = os.urandom(32)            # 256-bit key
    start  = time.time()
    for _ in range(100):
        Blowfish.new(key_bf, Blowfish.MODE_ECB).encrypt(data[:1024])
    return (time.time() - start) * 10  # ms per block

def bench_rsa():
    start = time.time()
    for _ in range(100):
        RSA.generate(2048)
    return (time.time() - start) * 10  # ms per key pair

def bench_ecc():
    start = time.time()
    for _ in range(100):
        ECC.generate(curve='P-256')
    return (time.time() - start) * 10  # ms per key pair

# ---------------------------------------------------------------
# UI
# ---------------------------------------------------------------

st.set_page_config(page_title="Crypto Benchmark", page_icon="🔐", layout="wide")

st.markdown("""
<style>
    .stApp { background: #0b1220; }
    h1, h2, h3, p, label, .stMarkdown { color: #e6edf3 !important; }
    div[data-testid="stMetric"] {
        background: #111a2e;
        border: 1px solid #1f2d4a;
        border-radius: 10px;
        padding: 14px 18px;
    }
    div[data-testid="stMetric"] label { color: #7d8ca8 !important; }
    div[data-testid="stMetricValue"] { color: #4fd1c5 !important; }
    .algo-card {
        background: #111a2e;
        border: 1px solid #1f2d4a;
        border-radius: 10px;
        padding: 16px 18px;
        margin-bottom: 8px;
        min-height: 120px;
    }
    .algo-card h4 { color: #4fd1c5; margin: 0 0 6px 0; font-family: monospace; }
    .algo-card p  { color: #93a4c3 !important; font-size: 0.85rem; margin: 0; }
    .stButton>button {
        background: #1a2a4a; color: #4fd1c5; border: 1px solid #2c3f66;
        width: 100%;
    }
    .stButton>button:hover { border-color: #4fd1c5; color: #e6edf3; }
</style>
""", unsafe_allow_html=True)

st.title("🔐 Symmetric vs Asymmetric Cryptography — Live Benchmark")
st.caption("BMIT2043 Internet Security · pycryptodome · 100 iterations per test")

if "results" not in st.session_state:
    st.session_state.results = {}

BENCHES = {
    "AES-256-GCM": {
        "fn": bench_aes,
        "unit": "ms per MB",
        "kind": "Symmetric",
        "desc": "Encrypts 1 MB, 100 rounds. Hardware-accelerated (AES-NI) with built-in authentication (GCM tag).",
        "eta": "≈ 1 second",
    },
    "Blowfish": {
        "fn": bench_blowfish,
        "unit": "ms per block",
        "kind": "Symmetric",
        "desc": "Encrypts a 1 KB slice, 100 rounds, ECB mode (throughput measurement only — ECB is not secure in practice).",
        "eta": "≈ 1 second",
    },
    "RSA-2048": {
        "fn": bench_rsa,
        "unit": "ms per key pair",
        "kind": "Asymmetric",
        "desc": "Generates 100 full 2048-bit key pairs. Slow: each key requires searching for two large random primes.",
        "eta": "⚠ several minutes (100 key pairs)",
    },
    "ECC P-256": {
        "fn": bench_ecc,
        "unit": "ms per key pair",
        "kind": "Asymmetric",
        "desc": "Generates 100 P-256 key pairs. Fast: a key is just a random 256-bit scalar × base point.",
        "eta": "≈ 1 second",
    },
}

# --- benchmark cards -------------------------------------------
cols = st.columns(4)
for col, (name, cfg) in zip(cols, BENCHES.items()):
    with col:
        st.markdown(
            f"""<div class="algo-card">
                <h4>{name}</h4>
                <p><b>{cfg['kind']}</b> · {cfg['desc']}</p>
                <p style="margin-top:6px;color:#5b6b8c!important;">Runtime: {cfg['eta']}</p>
            </div>""",
            unsafe_allow_html=True,
        )
        if st.button(f"Run {name}", key=f"btn_{name}"):
            with st.spinner(f"Running {name} — 100 iterations…"):
                st.session_state.results[name] = cfg["fn"]()
            st.rerun()

run_all_col, clear_col = st.columns([1, 1])
with run_all_col:
    if st.button("▶ Run ALL benchmarks (RSA takes minutes)"):
        prog = st.progress(0, text="Starting…")
        for i, (name, cfg) in enumerate(BENCHES.items()):
            prog.progress(i / len(BENCHES), text=f"Running {name}…")
            st.session_state.results[name] = cfg["fn"]()
        prog.progress(1.0, text="Done")
        st.rerun()
with clear_col:
    if st.button("✕ Clear results"):
        st.session_state.results = {}
        st.rerun()

st.divider()

# --- results ----------------------------------------------------
if not st.session_state.results:
    st.info("Click a **Run** button above. Results appear here as each benchmark completes.")
else:
    st.subheader("Results")

    mcols = st.columns(4)
    for col, (name, cfg) in zip(mcols, BENCHES.items()):
        with col:
            if name in st.session_state.results:
                st.metric(f"{name} ({cfg['kind']})",
                          f"{st.session_state.results[name]:.2f} {cfg['unit']}")
            else:
                st.metric(f"{name} ({cfg['kind']})", "—")

    # chart: symmetric vs asymmetric shown separately because units differ
    done = st.session_state.results
    c1, c2 = st.columns(2)

    sym = {k: v for k, v in done.items() if BENCHES[k]["kind"] == "Symmetric"}
    if sym:
        with c1:
            st.markdown("**Symmetric encryption time (ms, lower = faster)**")
            st.bar_chart(pd.DataFrame({"ms": sym.values()}, index=sym.keys()),
                         color="#4fd1c5")

    asym = {k: v for k, v in done.items() if BENCHES[k]["kind"] == "Asymmetric"}
    if asym:
        with c2:
            st.markdown("**Asymmetric key generation time (ms per key pair)**")
            st.bar_chart(pd.DataFrame({"ms": asym.values()}, index=asym.keys()),
                         color="#f6ad55")

    if "RSA-2048" in done and "ECC P-256" in done and done["ECC P-256"] > 0:
        ratio = done["RSA-2048"] / done["ECC P-256"]
        st.success(f"**Key takeaway:** ECC P-256 key generation is **{ratio:,.0f}× faster** "
                   f"than RSA-2048 at equivalent (~128-bit) security level.")

st.caption("Note: symmetric results use different data sizes per the original methodology "
           "(AES: 1 MB · Blowfish: 1 KB slice), so units differ and bars are not directly comparable.")
