from __future__ import annotations

import matplotlib.pyplot as plt

from common import empty_figure, parse_io, read_csv, save


def main() -> None:
    args = parse_io("Plot verify-non-transfer cost by elapsed anchors")
    df = read_csv(args.input)
    df = df[df.get("status", "") == "success"] if not df.empty else df
    if df.empty:
        save(empty_figure("No successful verify-cost data"), args.output)
        return

    grouped = df.groupby("targetElapsedAnchors", as_index=False).agg(
        verifyMs=("verifyMs", "mean"),
        apiResponseBytes=("apiResponseBytes", "mean"),
        apiCalls=("apiCalls", "mean"),
        rpcCalls=("rpcCalls", "mean"),
    )
    fig, axes = plt.subplots(1, 2, figsize=(11, 4))
    axes[0].plot(grouped["targetElapsedAnchors"], grouped["verifyMs"], marker="o")
    axes[1].plot(grouped["targetElapsedAnchors"], grouped["apiResponseBytes"], marker="o", label="API response bytes")
    axes[1].plot(grouped["targetElapsedAnchors"], grouped["apiCalls"], marker="s", label="API calls")
    axes[1].plot(grouped["targetElapsedAnchors"], grouped["rpcCalls"], marker="^", label="RPC calls")
    axes[0].set_xlabel("Elapsed anchors after revocation")
    axes[1].set_xlabel("Elapsed anchors after revocation")
    axes[0].set_ylabel("Verify time (ms)")
    axes[1].set_ylabel("Count / bytes")
    axes[0].set_title("Verification time")
    axes[1].set_title("Data and call cost")
    axes[1].legend()
    save(fig, args.output)


if __name__ == "__main__":
    main()

