import json
import os
import subprocess

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import mpl_toolkits.mplot3d

from common import RESULTS, FIGURES, LINKS, frames

plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Times New Roman", "DejaVu Serif"],
    "font.size": 7.5,
    "axes.labelsize": 8,
    "axes.titlesize": 8,
    "legend.fontsize": 7,
    "xtick.labelsize": 7,
    "ytick.labelsize": 7,
    "axes.grid": True,
    "grid.linestyle": ":",
    "grid.linewidth": 0.4,
    "grid.alpha": 0.7,
    "lines.linewidth": 1.1,
    "patch.linewidth": 0.6,
})

SHORT = {
    "PQ-TLS 1.3/ML-DSA-44": "PQ-TLS/MLDSA",
    "PQ-TLS 1.3/Falcon-padded-512": "PQ-TLS/Falcon",
    "PQ-TLS 1.3/ML-DSA-87": "PQ-TLS/MLDSA",
    "PQ-TLS 1.3/Falcon-padded-1024": "PQ-TLS/Falcon",
    "EDHOC (method 0)/ML-DSA-44": "EDHOC/MLDSA",
    "EDHOC (method 0)/ML-DSA-87": "EDHOC/MLDSA",
    "KEMTLS": "KEMTLS",
    "KEMTLS-PDK": "KEMTLS-PDK",
    "PQ-WireGuard": "PQ-WG",
    "FSXY KEM-AKE": "FSXY",
    "Kyber.AKE": "Kyber.AKE",
    "EDHOC-KEM": "EDHOC-KEM",
    "TLS 1.3 PSK+KEM": "TLS-PSK+KEM",
    "CLASP-0 (enrolment)": "CLASP-0",
    "CLASP": "CLASP",
}

HATCH = ["", "//", "\\\\", "xx", "..", "++", "oo", "--", "||", "**", "OO", "@@"]


def key_of(r):
    return r["name"] + ("/" + r["sig"] if r["sig"] else "")


def save(fig, name):
    os.makedirs(FIGURES, exist_ok=True)
    eps = os.path.join(FIGURES, name + ".eps")
    fig.savefig(eps, format="eps", bbox_inches="tight", pad_inches=0.02)
    plt.close(fig)
    subprocess.run(["epstopdf", eps, "--outfile=" + os.path.join(FIGURES, name + ".pdf")],
                   check=True)
    print("wrote", name)


def load():
    with open(os.path.join(RESULTS, "handshake.json")) as f:
        hs = json.load(f)
    with open(os.path.join(RESULTS, "robustness.json")) as f:
        rb = json.load(f)
    with open(os.path.join(RESULTS, "scaling.json")) as f:
        sc = json.load(f)
    with open(os.path.join(RESULTS, "throughput.json")) as f:
        tp = json.load(f)
    return hs, rb, sc, tp


def ordered(rows):
    out = [r for r in rows if r["name"] != "CLASP-0 (enrolment)" and r["name"] != "CLASP"]
    out.sort(key=lambda r: -r["bytes_total"])
    out += [r for r in rows if r["name"] == "CLASP-0 (enrolment)"]
    out += [r for r in rows if r["name"] == "CLASP"]
    return out


def fig_bytes(hs):
    rows = ordered(hs["ML-KEM-768"])
    labels = [SHORT[key_of(r)] for r in rows]
    up = np.array([r["bytes_up"] for r in rows])
    dn = np.array([r["bytes_dn"] for r in rows])
    x = np.arange(len(rows))
    fig, ax = plt.subplots(figsize=(3.45, 1.72))
    ax.bar(x, up, 0.62, color="0.35", edgecolor="black", label="device to gateway")
    ax.bar(x, dn, 0.62, bottom=up, color="0.82", edgecolor="black", hatch="//",
           label="gateway to device")
    for i, r in enumerate(rows):
        ax.text(i, up[i] + dn[i] + 130, str(up[i] + dn[i]), ha="center", fontsize=5.4, rotation=90)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=55, ha="right")
    ax.set_ylabel("handshake bytes")
    ax.set_ylim(0, max(up + dn) * 1.28)
    ax.legend(loc="upper right", framealpha=0.95)
    save(fig, "fig_bytes")


def fig_frames(hs):
    rows = ordered(hs["ML-KEM-768"])
    links = list(LINKS.keys())
    data = np.array([[r["links"][l]["frames"] for l in links] for r in rows])
    fig, ax = plt.subplots(figsize=(3.45, 1.88))
    im = ax.imshow(data.T, aspect="auto", cmap="Greys", vmin=0, vmax=data.max())
    ax.set_xticks(range(len(rows)))
    ax.set_xticklabels([SHORT[key_of(r)] for r in rows], rotation=55, ha="right")
    ax.set_yticks(range(len(links)))
    ax.set_yticklabels(links)
    for i in range(data.shape[0]):
        for j in range(data.shape[1]):
            v = data[i, j]
            ax.text(i, j, str(v), ha="center", va="center", fontsize=5.2,
                    color="white" if v > data.max() * 0.55 else "black")
    ax.grid(False)
    ax.set_title("link-layer frames per handshake")
    save(fig, "fig_frames")


def fig_time(hs):
    rows = ordered(hs["ML-KEM-768"])
    labels = [SHORT[key_of(r)] for r in rows]
    ai = np.array([r["asym_init_us"] for r in rows])
    ar = np.array([r["asym_resp_us"] for r in rows])
    x = np.arange(len(rows))
    fig, ax = plt.subplots(figsize=(3.45, 1.72))
    ax.bar(x - 0.2, ai, 0.4, color="0.3", edgecolor="black", label="device")
    ax.bar(x + 0.2, ar, 0.4, color="0.85", edgecolor="black", hatch="//", label="gateway")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=55, ha="right")
    ax.set_ylabel(r"asymmetric time [$\mu$s]")
    ax.set_yscale("log")
    ax.legend(loc="upper right", framealpha=0.95)
    save(fig, "fig_time")


def fig_m4(hs):
    rows = [r for r in ordered(hs["ML-KEM-768"]) if r["m4_cycles_init"] is not None]
    labels = [SHORT[key_of(r)] for r in rows]
    cyc = np.array([r["m4_cycles_init"] for r in rows]) / 1e6
    stack = np.array([r["m4_stack_init"] for r in rows]) / 1024.0
    x = np.arange(len(rows))
    fig, ax = plt.subplots(figsize=(3.45, 1.72))
    ax.bar(x, cyc, 0.6, color="0.45", edgecolor="black")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=55, ha="right")
    ax.set_ylabel("device cycles [$10^6$]")
    ax2 = ax.twinx()
    ax2.plot(x, stack, "k^--", markersize=3.4, linewidth=0.9, label="peak stack")
    ax2.set_ylabel("peak stack [KiB]")
    ax2.grid(False)
    ax2.legend(loc="upper right", framealpha=0.95)
    save(fig, "fig_m4")


def fig_levels(hs):
    levels = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]
    names = ["KEMTLS-PDK", "PQ-WireGuard", "FSXY KEM-AKE", "EDHOC-KEM", "TLS 1.3 PSK+KEM", "CLASP"]
    fig, axes = plt.subplots(1, 2, figsize=(7.0, 1.95))
    x = np.arange(len(levels))
    for i, n in enumerate(names):
        b = []
        c = []
        for lv in levels:
            r = [q for q in hs[lv] if q["name"] == n][0]
            b.append(r["bytes_total"])
            c.append(r["m4_cycles_init"] / 1e6)
        axes[0].plot(x, b, marker="os^vDP"[i], color="0." + str(min(7, i + 1)),
                     markersize=3.6, label=SHORT[n])
        axes[1].plot(x, c, marker="os^vDP"[i], color="0." + str(min(7, i + 1)), markersize=3.6)
    for a, lab in zip(axes, ["handshake bytes", "device cycles [$10^6$]"]):
        a.set_xticks(x)
        a.set_xticklabels([l.replace("ML-KEM-", "level ") for l in levels])
        a.set_ylabel(lab)
    axes[0].legend(ncol=2, framealpha=0.95)
    save(fig, "fig_levels")


def fig_energy3d(rb):
    P = np.array(rb["payload_grid"])
    R = np.array(rb["loss_grid"])
    X, Y = np.meshgrid(R, P)
    fig = plt.figure(figsize=(3.5, 2.20))
    ax = fig.add_subplot(111, projection="3d")
    styles = [("KEMTLS-PDK", "0.75", 0.85), ("CLASP", "0.25", 0.95)]
    for name, col, alpha in styles:
        Z = np.array(rb["surfaces"][name])
        ax.plot_surface(X, Y, Z, color=col, alpha=alpha, linewidth=0.15,
                        edgecolor="black", rstride=2, cstride=1, shade=False)
    ax.set_xlabel("frame loss $\\rho$", labelpad=-4)
    ax.set_ylabel("link payload [B]", labelpad=-3)
    ax.set_zlabel("device energy [mJ]", labelpad=-9)
    ax.tick_params(axis="x", pad=-3)
    ax.tick_params(axis="y", pad=-2)
    ax.tick_params(axis="z", pad=-1)
    ax.view_init(elev=22, azim=-125)
    ax.set_box_aspect((1.05, 1.05, 0.78))
    from matplotlib.patches import Patch
    ax.legend(handles=[Patch(facecolor="0.75", edgecolor="black", label="KEMTLS-PDK"),
                       Patch(facecolor="0.25", edgecolor="black", label="CLASP")],
              loc="upper left", bbox_to_anchor=(-0.06, 1.02), framealpha=0.95)
    save(fig, "fig_energy3d")


def fig_energy_loss(rb):
    fig, ax = plt.subplots(figsize=(3.45, 1.66))
    mk = "os^vD"
    shown = ["CLASP", "TLS 1.3 PSK+KEM", "KEMTLS-PDK", "PQ-WireGuard", "PQ-TLS 1.3/ML-DSA-44"]
    for i, (name, rows) in enumerate((k, rb["monte_carlo"][k]) for k in shown):
        rho = [r["rho"] for r in rows]
        e = [r["sim_mJ"] for r in rows]
        ax.plot(rho, e, marker=mk[i % len(mk)], markersize=3.4,
                color="0." + str(min(7, i + 1)), label=SHORT.get(name, name))
        ax.plot(rho, [r["analytic_mJ"] for r in rows], "k:", linewidth=0.7)
    ax.set_xlabel(r"per-frame loss probability $\rho$")
    ax.set_ylabel("device energy [mJ]")
    ax.legend(ncol=2, framealpha=0.95)
    save(fig, "fig_energy_loss")


def fig_scaling(sc):
    rows = sc["rows"]
    n = np.array([r["devices"] for r in rows])
    hit = np.array([r["lookup_hit_ns"] for r in rows])
    scan = np.array([r["linear_scan_ns"] for r in rows])
    fig, ax = plt.subplots(figsize=(3.45, 1.66))
    ax.loglog(n, hit / 1e3, "ks-", markersize=3.6, label="CLASP indexed lookup")
    ax.loglog(n, scan / 1e6, "o--", color="0.45", markersize=3.6,
              label=r"linear rescan ($\times 10^{3}$)")
    ax.set_xlabel("enrolled devices $N$")
    ax.set_ylabel(r"responder lookup [$\mu$s]")
    ax.legend(framealpha=0.95)
    save(fig, "fig_scaling")


CLUSTERS = [
    (["PQ-TLS 1.3/ML-DSA-44", "EDHOC (method 0)/ML-DSA-44"],
     "signature based\n(PQ-TLS 1.3, EDHOC)", (-96, 14)),
    (["KEMTLS", "KEMTLS-PDK", "PQ-WireGuard", "FSXY KEM-AKE", "Kyber.AKE",
      "EDHOC-KEM", "CLASP-0 (enrolment)"],
     "KEM based, 7 protocols", (8, 26)),
    (["TLS 1.3 PSK+KEM"], "TLS 1.3 PSK with KEM", (14, 20)),
    (["CLASP"], "CLASP", (18, -14)),
]


def fig_pareto(hs):
    rows = {key_of(r): r for r in hs["ML-KEM-768"]}
    fig, ax = plt.subplots(figsize=(3.45, 2.10))
    for keys, label, off in CLUSTERS:
        xs = [rows[k]["m4_cycles_init"] / 1e6 for k in keys]
        ys = [rows[k]["bytes_total"] for k in keys]
        star = label == "CLASP"
        ax.scatter(xs, ys, s=70 if star else 20, marker="*" if star else "o",
                   color="black" if star else "0.45", zorder=3)
        cx = sum(xs) / len(xs)
        cy = sum(ys) / len(ys)
        ax.annotate(label, (cx, cy), textcoords="offset points", xytext=off,
                    fontsize=5.9, va="center",
                    arrowprops=dict(arrowstyle="-", linewidth=0.4, color="0.3",
                                    shrinkA=1, shrinkB=3))
    ax.set_xlabel("device computation [$10^6$ cycles]")
    ax.set_ylabel("handshake bytes")
    ax.set_xlim(-0.4, 8.6)
    ax.set_ylim(1000, 9200)
    save(fig, "fig_pareto")


def main():
    hs, rb, sc, tp = load()
    fig_bytes(hs)
    fig_frames(hs)
    fig_time(hs)
    fig_m4(hs)
    fig_levels(hs)
    fig_energy3d(rb)
    fig_energy_loss(rb)
    fig_scaling(sc)
    fig_pareto(hs)


if __name__ == "__main__":
    main()
