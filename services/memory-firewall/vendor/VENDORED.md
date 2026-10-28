# Vendored: Memory Firewall library

`memory-firewall/` is a **verbatim copy** of part of the Memory Firewall repository. Do not edit
it here: change the source repository, then copy it again. `tests/test_vendor.py` fails if any file
differs from `SHA256SUMS`.

| | |
| --- | --- |
| Source | `github.com/rikton9/ai-sec-agent-memory` (private) |
| Commit | `807b972` (Session 9: interactive Streamlit web demo) |
| Copied | `pyproject.toml` (read for the version), `src/guard`, `src/scan`, `src/lab` |
| Left out | `src/eval` (measurements, demos, report), `demo/`, `tests/`, `results/`, `data/`, `PROJECT_BRIEF.md` |
| Line endings | as committed (LF); `.gitattributes` marks this folder `-text` so Git never converts them |

Confidential: the library is unpublished research. Keep this repository private and share it only
with people who may see the Memory Firewall code.

## Updating to a newer commit

From the Guardrail repository root, with the Memory Firewall checkout at `$MF` and the new commit
in `$REV`:

```bash
DEST=services/memory-firewall/vendor/memory-firewall
rm -rf "$DEST" && mkdir -p "$DEST"
for p in $(git -C "$MF" ls-tree -r --name-only "$REV" pyproject.toml src/guard src/scan src/lab); do
  mkdir -p "$DEST/$(dirname "$p")" && git -C "$MF" cat-file blob "$REV:$p" > "$DEST/$p"
done
(cd "$DEST" && find . -type f | sort | sed 's|^\./||' | xargs sha256sum) > services/memory-firewall/vendor/SHA256SUMS
```

Then update the commit in this file, check `requirements.txt` against the library's `uv.lock`, and
run the service's tests.
