from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


def parse_io(description: str) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--input", required=True, help="Input CSV path")
    parser.add_argument("--output", required=True, help="Output PNG path")
    return parser.parse_args()


def read_csv(path: str) -> pd.DataFrame:
    input_path = Path(path)
    if not input_path.exists() or input_path.stat().st_size == 0:
        return pd.DataFrame()
    return pd.read_csv(input_path)


def save(fig: plt.Figure, output: str) -> None:
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(output_path, dpi=180)
    plt.close(fig)


def empty_figure(message: str):
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.text(0.5, 0.5, message, ha="center", va="center")
    ax.set_axis_off()
    return fig

