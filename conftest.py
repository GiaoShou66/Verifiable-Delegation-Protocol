"""Repo-root conftest.

Its first job is to make the project root the rootdir pytest prepends to
sys.path, so `import policy` resolves to the source tree without an install
step. VDP's enforcement path depends on nothing beyond the standard library;
pytest and hypothesis are test-only.

Also registers the Hypothesis profile the suite runs under. Several tests
already pass `deadline=None` individually, for the same reason it is set
globally here: these are PROPERTY tests over an automaton, and a single
example being slow is a statement about the machine, not about phi. Leaving
the default 200ms deadline in place makes the suite fail on a loaded laptop
or a shared CI runner, which trains everyone to re-run red builds -- the
worst habit a security-relevant repository can teach.
"""

from hypothesis import HealthCheck, settings

settings.register_profile(
    "vdp",
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.load_profile("vdp")
