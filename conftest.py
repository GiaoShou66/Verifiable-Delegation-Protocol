"""Repo-root conftest.

Its only job is to make the project root the rootdir pytest prepends to
sys.path, so `import policy` resolves to the source tree without an install
step. VDP's enforcement path depends on nothing beyond the standard library;
pytest and hypothesis are test-only.
"""
