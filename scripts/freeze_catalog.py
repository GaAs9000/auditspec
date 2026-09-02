from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from auditspec.catalog import catalog_digest, combined_catalog_digest  # noqa: E402
from auditspec.spec import load_spec  # noqa: E402

SPEC_PATHS = tuple(sorted((ROOT / "examples").glob("*.yaml")))
FREEZE_PATH = ROOT / "examples" / "CATALOG_FREEZE.json"


def current_manifest() -> dict[str, object]:
    specs = [load_spec(path) for path in SPEC_PATHS]
    packs: dict[str, object] = {}
    for path, spec in zip(SPEC_PATHS, specs):
        splits: dict[str, list[str]] = {"development": [], "held_out": []}
        for name, query in spec.queries.items():
            splits.setdefault(query.split, []).append(name)
        packs[path.stem] = {
            "spec": spec.name,
            "catalog_version": spec.metadata.get("catalog_version"),
            "mechanism_count": len(spec.mechanisms),
            "catalog_sha256": catalog_digest(spec),
            "query_splits": {name: sorted(values) for name, values in splits.items()},
        }
    return {
        "format": "AuditSpec-catalog-freeze-v1",
        "scope": "Mechanism payloads only; query expressions are excluded from catalog digests.",
        "independent_preregistration": False,
        "limitation": "This artifact manifest detects post-freeze catalog edits but is not an externally timestamped preregistration.",
        "combined_catalog_sha256": combined_catalog_digest(specs),
        "packs": packs,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--write",
        action="store_true",
        help="Write the initial manifest. Refuses to overwrite an existing file.",
    )
    args = parser.parse_args(argv)
    current = current_manifest()
    if args.write:
        if FREEZE_PATH.exists():
            raise SystemExit(
                f"Refusing to overwrite frozen catalog: {FREEZE_PATH}. Remove it explicitly only when creating a new catalog version."
            )
        FREEZE_PATH.write_text(
            json.dumps(current, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(f"wrote {FREEZE_PATH}")
        return 0

    if not FREEZE_PATH.exists():
        raise SystemExit(f"Missing freeze manifest: {FREEZE_PATH}")
    frozen = json.loads(FREEZE_PATH.read_text(encoding="utf-8"))
    if frozen != current:
        print(json.dumps({"valid": False, "frozen": frozen, "current": current}, indent=2))
        return 1
    print(
        json.dumps(
            {
                "valid": True,
                "combined_catalog_sha256": current["combined_catalog_sha256"],
                "packs": sorted(current["packs"]),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
