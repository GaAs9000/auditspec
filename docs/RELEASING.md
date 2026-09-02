# Release procedure

AuditSpec release builds use a fixed timestamp so identical source and build
inputs produce byte-identical wheels:

```bash
python -m pip install build
SOURCE_DATE_EPOCH=1704067200 python -m build --wheel --outdir dist-a
SOURCE_DATE_EPOCH=1704067200 python -m build --wheel --outdir dist-b
cmp dist-a/*.whl dist-b/*.whl
```

Before a release:

1. run the complete Python and Rust verification commands from `README.md`;
2. run the isolated wheel attestation/runtime consumer;
3. confirm the version matches in `pyproject.toml`, `auditspec.__version__`,
   `Cargo.toml`, and `Cargo.lock`;
4. create an immutable, signed or transparency-attested tag;
5. publish wheel, sdist, SBOM, checksums, and build provenance together.

The source repository and release metadata authenticate build inputs. A package
hash alone does not establish production deployment, evidence truth, or an
open-world guarantee.
