# plot_results.py - Plots of the ESP32 measurements (PDF §5)
#
# Reads the CSV files in this folder (a plot is skipped if its CSV is missing):
#   measure_esp32.csv    from common/medir.py           columns: test,L,packet,ms
#   latency_esp32.csv    from option 3 of esp32/main.py  columns: i,rtt_ms
#
# Saves in this same folder:
#   packet_size.png      message size vs packet size (bytes added by the protection)
#   crypto_time.png      seal time (encrypt + TAG) and open time (verify + decrypt)
#   latency.png          round-trip time and how much of it is cryptography
#   operation_cost.png   handshake (once per session) vs cost of each message
# and prints a Markdown table with the results.
#
# Usage:  python results/plot_results.py      (needs matplotlib, see requirements.txt)

import csv
import os
import statistics

import matplotlib
matplotlib.use("Agg")       # only save the PNG files, do not open windows
import matplotlib.pyplot as plt

FOLDER = os.path.dirname(os.path.abspath(__file__))

# Fixed parts of the DATA packet (notes §4.2): 42 B + C
HEADER = 10         # TYPE | IDS | SID | SEQ
IV = 16
TAG = 16
HANDSHAKE_B = 614   # HELLO 274 + RESPONSE 306 + CONFIRM 34
L_PING = 8          # the PING (11 B) uses the same 58 B packet as L = 8

# Colors: categorical palette in a fixed order, text in gray (never the series color)
BLUE = "#2a78d6"
ORANGE = "#eb6834"
AQUA = "#1baf7a"
YELLOW = "#eda100"
MAGENTA = "#e87ba4"
TEXT = "#0b0b0b"
TEXT_2 = "#52514e"
GRID = "#e4e3df"

plt.rcParams.update({
    "figure.facecolor": "white",
    "axes.facecolor": "white",
    "axes.edgecolor": GRID,
    "axes.labelcolor": TEXT_2,
    "axes.titlecolor": TEXT,
    "axes.titlesize": 12,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": True,
    "axes.grid.axis": "y",
    "axes.axisbelow": True,
    "grid.color": GRID,
    "grid.linewidth": 0.8,
    "xtick.color": TEXT_2,
    "ytick.color": TEXT_2,
    "legend.frameon": False,
    "font.size": 10,
})


# ---------- Read data ----------

def read_csv(name):
    path = os.path.join(FOLDER, name)
    if not os.path.exists(path):
        return None
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def load_measure():
    # [(test, L, packet, ms), ...]
    rows = read_csv("measure_esp32.csv")
    if not rows:
        return None
    return [(r["test"], int(r["L"]), int(r["packet"]), float(r["ms"])) for r in rows]


def load_latency():
    # [rtt_ms, ...]
    rows = read_csv("latency_esp32.csv")
    if not rows:
        return None
    return [float(r["rtt_ms"]) for r in rows]


def times(rows, test, L=None):
    return [ms for t, l, _, ms in rows if t == test and (L is None or l == L)]


def sizes(rows):
    # [(L, packet), ...] sorted by L
    return sorted({(l, packet) for t, l, packet, _ in rows if t == "seal"})


def mean_sd(xs):
    if len(xs) < 2:
        return xs[0], 0.0
    return statistics.mean(xs), statistics.stdev(xs)


def save(fig, name):
    path = os.path.join(FOLDER, name)
    fig.savefig(path, dpi=200, bbox_inches="tight")
    plt.close(fig)
    print("Saved:", path)


# ---------- Plots ----------

def plot_packet_size(rows):
    sz = sizes(rows)
    n = len(sz)
    parts = [
        ("Plaintext", [l for l, _ in sz], BLUE),
        ("PKCS#7 padding", [packet - l - HEADER - IV - TAG for l, packet in sz], ORANGE),
        ("Header (TYPE, ID, SID, SEQ)", [HEADER] * n, AQUA),
        ("IV", [IV] * n, YELLOW),
        ("TAG (HMAC-SHA256, 16 B)", [TAG] * n, MAGENTA),
    ]

    fig, ax = plt.subplots(figsize=(8, 5))
    x = list(range(n))
    bottom = [0] * n
    for name, values, color in parts:
        ax.bar(x, values, bottom=bottom, width=0.6, color=color, edgecolor="white", linewidth=1.5, label=name)
        bottom = [b + v for b, v in zip(bottom, values)]
    for i, (l, packet) in enumerate(sz):
        ax.annotate("%d B\n+%d B (%.0f%%)" % (packet, packet - l, 100 * (packet - l) / l), (i, packet),
                    xytext=(0, 4), textcoords="offset points", ha="center", va="bottom", color=TEXT, fontsize=9)

    ax.set_xticks(x)
    ax.set_xticklabels([str(l) for l, _ in sz])
    ax.set_ylim(0, max(packet for _, packet in sz) * 1.25)
    ax.set_xlabel("Plaintext message size L (bytes)")
    ax.set_ylabel("Bytes sent")
    ax.set_title("Protected packet size: 42 + 16·(⌊L/16⌋ + 1) bytes")
    ax.legend(loc="upper left")
    save(fig, "packet_size.png")


def plot_crypto_time(rows):
    Ls = [l for l, _ in sizes(rows)]
    seal = [mean_sd(times(rows, "seal", l)) for l in Ls]
    open_ = [mean_sd(times(rows, "open", l)) for l in Ls]
    reject = times(rows, "reject")

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.errorbar(Ls, [m for m, _ in seal], yerr=[d for _, d in seal], fmt="-o", color=BLUE,
                linewidth=2, markersize=6, capsize=3, label="Encrypt + MAC (seal)")
    ax.errorbar(Ls, [m for m, _ in open_], yerr=[d for _, d in open_], fmt="-o", color=ORANGE,
                linewidth=2, markersize=6, capsize=3, label="Verify + decrypt (open)")
    if reject:
        m, d = mean_sd(reject)
        L_reject = next(l for t, l, _, _ in rows if t == "reject")
        ax.errorbar([L_reject], [m], yerr=[d], fmt="D", color=AQUA, markersize=8, capsize=3,
                    label="Rejected packet (TAG check only)")

    ax.set_xscale("log", base=2)
    ax.set_xticks(Ls)
    ax.set_xticklabels([str(l) for l in Ls])
    ax.minorticks_off()
    ax.set_ylim(bottom=0)
    ax.set_xlabel("Plaintext message size L (bytes)")
    ax.set_ylabel("Time per message (ms), mean ± SD")
    ax.set_title("ESP32: time to protect and check one message (n = %d per point)"
                 % len(times(rows, "seal", Ls[0])))
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.14), ncol=3)
    save(fig, "crypto_time.png")


def plot_latency(rtt, rows):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4.5), gridspec_kw={"width_ratios": [1, 1.4]})

    # a) RTT of each PING/PONG, in the order they were sent
    ax1.plot(range(1, len(rtt) + 1), rtt, "-o", color=BLUE, linewidth=1.5, markersize=4)
    m, d = mean_sd(rtt)
    # The mean goes in the legend, below the points, so the text does not cover the line
    ax1.axhline(m, color=TEXT_2, linestyle="--", linewidth=1, label="mean %.1f ± %.1f ms" % (m, d))
    ax1.legend(loc="lower right")
    ax1.set_ylim(bottom=0)
    ax1.set_xlabel("PING number")
    ax1.set_ylabel("Round-trip time (ms)")
    ax1.set_title("Alice ↔ Bob protected PING/PONG (n = %d)" % len(rtt))

    # b) How much of the RTT is cryptography: each board does one seal and one open
    ax2.grid(axis="x", color=GRID)
    ax2.grid(axis="y", visible=False)
    if rows:
        crypto = 2 * (statistics.mean(times(rows, "seal", L_PING)) + statistics.mean(times(rows, "open", L_PING)))
        crypto = min(crypto, m)
        ax2.barh(0, crypto, height=0.5, color=BLUE, edgecolor="white", linewidth=1.5,
                 label="Cryptography (2 seal + 2 open)")
        ax2.barh(0, m - crypto, left=crypto, height=0.5, color=ORANGE, edgecolor="white", linewidth=1.5,
                 label="Network + other processing")
        ax2.annotate("RTT %.1f ms\ncrypto %.1f ms (%.0f%%)" % (m, crypto, 100 * crypto / m), (m, 0),
                     xytext=(6, 0), textcoords="offset points", va="center", color=TEXT, fontsize=9)
        ax2.set_xlim(0, m * 1.45)
        ax2.set_ylim(-1, 1)
        ax2.set_yticks([0])
        ax2.set_yticklabels(["ESP32 ↔ ESP32"])
        ax2.legend(loc="upper center", bbox_to_anchor=(0.5, -0.18), ncol=2)
    else:
        ax2.text(0.5, 0.5, "Missing measure_esp32.csv", ha="center", va="center",
                 color=TEXT_2, transform=ax2.transAxes)
    ax2.set_xlabel("Mean round-trip time (ms)")
    ax2.set_title("Share of the RTT spent on cryptography")
    fig.tight_layout()
    save(fig, "latency.png")


def plot_operation_cost(rows):
    hs = times(rows, "handshake")
    if not hs:
        print("No handshake data: operation_cost.png skipped")
        return
    L = 32
    items = [
        ("Handshake\n(once per session)", mean_sd(hs), len(hs)),
        ("seal, L = %d B" % L, mean_sd(times(rows, "seal", L)), len(times(rows, "seal", L))),
        ("open, L = %d B" % L, mean_sd(times(rows, "open", L)), len(times(rows, "open", L))),
    ]
    if times(rows, "reject"):
        items.append(("Reject (bad TAG)", mean_sd(times(rows, "reject")), len(times(rows, "reject"))))

    fig, ax = plt.subplots(figsize=(8, 1.4 + 0.7 * len(items)))
    y = list(range(len(items)))
    ax.barh(y, [m for _, (m, _), _ in items], height=0.5, color=BLUE)
    for i, (_, (m, d), n) in enumerate(items):
        ax.annotate("%.1f ± %.1f ms (n = %d)" % (m, d, n), (m, i), xytext=(6, 0), textcoords="offset points",
                    va="center", color=TEXT, fontsize=9)
    ax.set_yticks(y)
    ax.set_yticklabels([name for name, _, _ in items])
    ax.invert_yaxis()
    ax.grid(axis="x", color=GRID)
    ax.grid(axis="y", visible=False)
    ax.set_xlim(0, max(m for _, (m, _), _ in items) * 1.35)
    ax.set_xlabel("Time on the ESP32 (ms), mean ± SD")
    ax.set_title("Cost of each operation on the ESP32\n"
                 "Handshake: DHE-PSK ffdhe2048, both sides on one board, %d bytes once per session" % HANDSHAKE_B)
    save(fig, "operation_cost.png")


# ---------- Table for the report ----------

def print_table(rows, rtt):
    if rows:
        print()
        print("| L (B) | Packet (B) | Overhead (B) | seal (ms) | open (ms) |")
        print("|---|---|---|---|---|")
        for l, packet in sizes(rows):
            s = mean_sd(times(rows, "seal", l))
            o = mean_sd(times(rows, "open", l))
            print("| %d | %d | %d | %.3f ± %.3f | %.3f ± %.3f |" % (l, packet, packet - l, s[0], s[1], o[0], o[1]))
        for test, name in (("reject", "Reject (bad TAG)"), ("handshake", "Handshake")):
            if times(rows, test):
                m, d = mean_sd(times(rows, test))
                print("%s: %.3f ± %.3f ms (n = %d)" % (name, m, d, len(times(rows, test))))
    if rtt:
        m, d = mean_sd(rtt)
        print()
        print("| Link | n | RTT (ms) | Latency ~ RTT/2 (ms) |")
        print("|---|---|---|---|")
        print("| ESP32 ↔ ESP32 | %d | %.1f ± %.1f | %.1f |" % (len(rtt), m, d, m / 2))


def main():
    rows = load_measure()
    rtt = load_latency()
    if not rows and not rtt:
        print("No CSV files in", FOLDER)
        print("First run common/medir.py on the ESP32 and option 3 (latency) of main.py")
        return
    if rows:
        plot_packet_size(rows)
        plot_crypto_time(rows)
        plot_operation_cost(rows)
    else:
        print("Missing measure_esp32.csv: packet_size, crypto_time and operation_cost skipped")
    if rtt:
        plot_latency(rtt, rows)
    else:
        print("Missing latency_esp32.csv: latency.png skipped")
    print_table(rows, rtt)


if __name__ == "__main__":
    main()
