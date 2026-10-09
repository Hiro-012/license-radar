"""A legacy setup.py fixture exercising static dependency extraction.

Mirrors real projects: a module-level requirements list referenced by name,
an inline extras dict, a tests_require list, and a dynamically-computed entry
that must be skipped (never guessed at) rather than fabricated.
"""

from setuptools import setup

# A dynamically-assembled entry cannot be resolved statically.
_dynamic = "some-" + "package"

# The very common `REQUIRES = [...]; setup(install_requires=REQUIRES)` pattern.
REQUIRES = [
    "requests>=2.0",
    "flask",
    # A GPL runtime dependency declared only here would previously be invisible.
    "python-levenshtein>=0.12; python_version >= '3.8'",
    # A non-literal element must be skipped, not turned into a bogus name.
    _dynamic,
]

setup(
    name="legacy-project",
    version="1.0.0",
    install_requires=REQUIRES,
    extras_require={
        "docs": ["sphinx"],
        "test": ["pytest>=7", "coverage"],
    },
    tests_require=["nose"],
)
