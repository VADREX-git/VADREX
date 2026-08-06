from __future__ import annotations

import matplotlib.pyplot as plt

from common import empty_figure, parse_io, read_csv, save


def main() -> None:
    args = parse_io("Plot revocation anchoring delay distribution")
    df = read_csv(args.input)
    df = df[df.get("status", "") == "ok"] if not df.empty else df
    if df.empty:
        save(empty_figure("No successful revocation delay data"), args.output)
        return

    df["observedDelaySec"] = df["observedDelayMs"] / 1000.0
    fig, ax = plt.subplots(figsize=(8, 4.5))
    groups = [part["observedDelaySec"].to_numpy() for _, part in df.groupby("anchorIntervalSec")]
    labels = [str(key) for key, _ in df.groupby("anchorIntervalSec")]
    ax.boxplot(groups, tick_labels=labels, showmeans=True)
    ax.set_xlabel("ANCHOR_INTERVAL_SEC")
    ax.set_ylabel("Revocation anchoring delay (s)")
    ax.set_title("Revocation anchoring delay")
    save(fig, args.output)


if __name__ == "__main__":
    main()

