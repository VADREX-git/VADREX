from __future__ import annotations

import matplotlib.pyplot as plt

from common import empty_figure, parse_io, read_csv, save

# Proof size only. The verification-time panel was dropped: all three series are flat across
# log sizes, so it plotted two constants that the text states directly, and on a linear axis
# the two RFC 6962 series sat on the x axis where nothing could be read off them.
#
# Log x only, so O(log n) reads as a straight line; a log y axis would bend it.
# SMT non-inclusion is annotated rather than plotted -- at 17,791 B it is twelve times the
# RFC 6962 series (688-1,449 B) and would take over the y axis, hiding exactly the growth
# this panel exists to show.
#
# The figure is sized for a single journal column. Drawing it wider only means a larger
# downscale at typesetting time, which is what made the tick labels unreadable before.

SMT = "smtNonInclusion"
LABELS = {"inclusion": "Inclusion", "consistency": "Consistency"}
COLORS = {"inclusion": "C0", "consistency": "C1", SMT: "C2"}


def main() -> None:
    args = parse_io("Plot proof size scaling")
    df = read_csv(args.input)
    if df.empty:
        save(empty_figure("No scaling data"), args.output)
        return

    grouped = df.groupby(["logicalLeaves", "proofType"], as_index=False).agg(
        proofBytes=("proofBytes", "mean"),
    )

    fig, ax = plt.subplots(figsize=(3.7, 2.7))

    for proof_type in ("inclusion", "consistency"):
        part = grouped[grouped["proofType"] == proof_type].sort_values("logicalLeaves")
        ax.plot(
            part["logicalLeaves"], part["proofBytes"],
            marker="o", markersize=4.5, linewidth=1.6,
            color=COLORS[proof_type], label=LABELS[proof_type],
        )

    smt = grouped[grouped["proofType"] == SMT]
    if not smt.empty:
        ax.text(
            0.03, 0.95,
            f"SMT non-inclusion: {int(round(smt['proofBytes'].mean())):,} B (fixed, depth 256)",
            transform=ax.transAxes, va="top", ha="left", fontsize=7.5, color=COLORS[SMT],
        )

    ax.set_xscale("log")
    ax.set_ylim(0, 1750)
    ax.set_xlabel("Log size (leaves)", fontsize=9)
    ax.set_ylabel("Proof size (bytes)", fontsize=9)
    ax.legend(loc="lower right", fontsize=8)
    ax.grid(True, alpha=0.3, linewidth=0.5)
    ax.tick_params(labelsize=8)

    fig.tight_layout()
    save(fig, args.output)


if __name__ == "__main__":
    main()
