"""Assemble independently reviewed Zeek captures without changing their labels or capture splits."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from tools.training_data import prepare


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("recipe", type=Path)
    parser.add_argument("--output", type=Path, required=True, help="New, private dataset version directory.")
    args = parser.parse_args()
    try:
        manifest = prepare(args.recipe, args.output)
    except (ValueError, KeyError, OSError) as exc:
        parser.exit(2, f"Dataset preparation failed: {exc}\n")
    print(json.dumps({key: manifest[key] for key in ("name", "records", "class_counts", "ready_for_training")}, indent=2))
    print(f"Prepared dataset: {args.output}")


if __name__ == "__main__":
    main()
