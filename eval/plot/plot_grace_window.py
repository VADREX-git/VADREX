from __future__ import annotations

import matplotlib.pyplot as plt

from common import empty_figure, parse_io, read_csv, save


def main() -> None:
    args = parse_io("Plot grace window tradeoff")
    df = read_csv(args.input)
    df = df[df.get("status", "") == "success"] if not df.empty else df
    if df.empty:
        save(empty_figure("No successful grace-window data"), args.output)
        return

    grouped = df.groupby("deltaMaxSec", as_index=False).agg(
        verifyMs=("verifyMs", "mean"),
        eligibleReceiverAnchors=("eligibleReceiverAnchors", "mean"),
    )
    fig, ax1 = plt.subplots(figsize=(8, 4.5))
    ax2 = ax1.twinx()
    ax1.plot(grouped["deltaMaxSec"], grouped["verifyMs"], marker="o", color="tab:blue", label="Verify time")
    ax2.plot(grouped["deltaMaxSec"], grouped["eligibleReceiverAnchors"], marker="s", color="tab:green", label="Eligible receiver anchors")
    ax1.set_xlabel("ANCHOR_MAX_INTERVAL_SEC (Delta max)")
    ax1.set_ylabel("Verify time (ms)", color="tab:blue")
    ax2.set_ylabel("Eligible receiver anchors", color="tab:green")
    ax1.set_title("Grace window tradeoff")
    save(fig, args.output)


if __name__ == "__main__":
    main()

