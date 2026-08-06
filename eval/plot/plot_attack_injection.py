from __future__ import annotations

import matplotlib.pyplot as plt

from common import empty_figure, parse_io, read_csv, save


def main() -> None:
    args = parse_io("Plot attack injection detection results")
    df = read_csv(args.input)
    df = df[df.get("status", "") != "skipped"] if not df.empty else df
    if df.empty:
        save(empty_figure("No attack-injection data"), args.output)
        return

    grouped = df.groupby(["property", "attackType"], as_index=False).agg(
        detectionRate=("detected", "mean"),
        detectionMs=("detectionMs", "mean"),
    )
    labels = grouped["property"] + "\n" + grouped["attackType"]
    fig, axes = plt.subplots(2, 1, figsize=(10, 7))
    axes[0].bar(labels, grouped["detectionRate"] * 100)
    axes[1].bar(labels, grouped["detectionMs"])
    axes[0].set_ylabel("Detection rate (%)")
    axes[1].set_ylabel("Mean detection time (ms)")
    axes[0].set_xticks(range(len(labels)), labels, rotation=35, ha="right")
    axes[1].set_xticks(range(len(labels)))
    axes[1].set_xticklabels(labels, rotation=35, ha="right")
    axes[0].set_title("Attack injection detection")
    save(fig, args.output)


if __name__ == "__main__":
    main()
