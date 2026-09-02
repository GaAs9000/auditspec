"""Validate two sdists by content and emit one deterministic tar.gz archive."""

from __future__ import annotations

import argparse
import gzip
import io
import json
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Sequence


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-date-epoch", type=int, required=True)
    args = parser.parse_args(argv)
    if len(args.input) < 2:
        raise ValueError("at least two independently built sdists are required")
    result = normalize(
        inputs=[path.resolve() for path in args.input],
        output=args.output.resolve(),
        source_date_epoch=args.source_date_epoch,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


def normalize(
    *, inputs: Sequence[Path], output: Path, source_date_epoch: int
) -> dict[str, object]:
    if output.exists():
        raise ValueError("canonical sdist output already exists")
    if source_date_epoch <= 0:
        raise ValueError("SOURCE_DATE_EPOCH must be positive")
    trees: list[dict[str, tuple[str, bytes | None, int]]] = []
    with tempfile.TemporaryDirectory(prefix="auditspec-sdist-normalize-") as raw:
        temporary = Path(raw)
        for index, source in enumerate(inputs):
            if not source.is_file() or source.is_symlink():
                raise ValueError("sdist input must be a regular non-symlink file")
            target = temporary / f"input-{index}"
            target.mkdir()
            with tarfile.open(source, "r:gz") as archive:
                _safe_members(archive)
                archive.extractall(target, filter="data")
            trees.append(_content_tree(target))
        if any(tree != trees[0] for tree in trees[1:]):
            raise ValueError("independent sdist extracted contents differ")
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("xb") as raw_output:
            with gzip.GzipFile(fileobj=raw_output, mode="wb", filename="", mtime=0) as zipped:
                with tarfile.open(
                    fileobj=zipped, mode="w", format=tarfile.USTAR_FORMAT
                ) as archive:
                    for name, (kind, content, mode) in sorted(trees[0].items()):
                        info = tarfile.TarInfo(name)
                        info.mtime = source_date_epoch
                        info.uid = 0
                        info.gid = 0
                        info.uname = "root"
                        info.gname = "root"
                        info.mode = mode
                        if kind == "directory":
                            info.type = tarfile.DIRTYPE
                            archive.addfile(info)
                        else:
                            assert content is not None
                            info.size = len(content)
                            archive.addfile(info, io.BytesIO(content))
    return {
        "status": "PASS",
        "input_count": len(inputs),
        "entry_count": len(trees[0]),
        "extracted_contents_equal": True,
        "output": output.name,
        "source_date_epoch": source_date_epoch,
    }


def _safe_members(archive: tarfile.TarFile) -> None:
    for member in archive.getmembers():
        name = PurePosixPath(member.name)
        if name.is_absolute() or ".." in name.parts:
            raise ValueError("sdist contains an unsafe path")
        if not (member.isdir() or member.isfile()):
            raise ValueError("sdist contains a link or unsupported member type")


def _content_tree(root: Path) -> dict[str, tuple[str, bytes | None, int]]:
    result: dict[str, tuple[str, bytes | None, int]] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise ValueError("extracted sdist contains a symlink")
        if path.is_dir():
            result[relative] = ("directory", None, path.stat().st_mode & 0o777)
        elif path.is_file():
            result[relative] = ("file", path.read_bytes(), path.stat().st_mode & 0o777)
        else:
            raise ValueError("extracted sdist contains an unsupported path")
    return result


if __name__ == "__main__":
    raise SystemExit(main())
