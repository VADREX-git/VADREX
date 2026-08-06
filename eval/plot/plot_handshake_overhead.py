from __future__ import annotations

import matplotlib.pyplot as plt

from common import empty_figure, parse_io, read_csv, save


def main() -> None:
    args = parse_io("Plot gateway handshake overhead by synthetic Study size")
    df = read_csv(args.input)
    df = df[df.get("status", "") == "ok"] if not df.empty else df
    if df.empty:
        save(empty_figure("No successful handshake data"), args.output)
        return

    grouped = df.groupby("studySizeLabel", as_index=False).agg(
        baselineDirectMs=("baselineDirectMs", "mean"),
        gatewayHandshakeMs=("gatewayHandshakeMs", "mean"),
        overheadMs=("overheadMs", "mean"),
    )
    x = range(len(grouped))
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.bar([i - 0.2 for i in x], grouped["baselineDirectMs"], width=0.4, label="Direct WADO->STOW")
    ax.bar([i + 0.2 for i in x], grouped["gatewayHandshakeMs"], width=0.4, label="Gateway handshake")
    ax.set_xticks(list(x), grouped["studySizeLabel"])
    ax.set_xlabel("Synthetic Study size")
    ax.set_ylabel("Latency (ms)")
    ax.set_title("Handshake overhead")
    ax.legend()
    save(fig, args.output)


if __name__ == "__main__":
    main()

