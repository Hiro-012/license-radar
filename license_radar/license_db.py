"""Static package -> SPDX license lookup table.

This is a small, hand-curated offline database used when no network lookup
is available (or desired, e.g. in CI). Entries are keyed by
``(ecosystem, normalized_package_name)``. Ecosystem is one of "pypi" or
"npm". Package names are lowercased and, for pypi, normalized by replacing
``_``/``.`` with ``-`` per PEP 503.

A handful of entries with the ``test-`` prefix are synthetic fixtures used
only by the test suite to exercise the strong-copyleft / unknown-license
code paths without asserting real-world facts about a live package's
license.
"""

PYPI_LICENSES = {
    "requests": "Apache-2.0",
    "flask": "BSD-3-Clause",
    "django": "BSD-3-Clause",
    "numpy": "BSD-3-Clause",
    "pandas": "BSD-3-Clause",
    "pytest": "MIT",
    "click": "BSD-3-Clause",
    "pyyaml": "MIT",
    "sqlalchemy": "MIT",
    "celery": "BSD-3-Clause",
    "scrapy": "BSD-3-Clause",
    "twisted": "MIT",
    "pillow": "HPND",
    "setuptools": "MIT",
    "wheel": "MIT",
    "six": "MIT",
    "certifi": "MPL-2.0",
    "idna": "BSD-3-Clause",
    "urllib3": "MIT",
    "jinja2": "BSD-3-Clause",
    "markupsafe": "BSD-3-Clause",
    "itsdangerous": "BSD-3-Clause",
    "werkzeug": "BSD-3-Clause",
    "gunicorn": "MIT",
    "redis": "MIT",
    "boto3": "Apache-2.0",
    "botocore": "Apache-2.0",
    "pyqt5": "GPL-3.0-only",
    "psycopg2": "LGPL-3.0-only",
    "paramiko": "LGPL-2.1-only",
    "chardet": "LGPL-2.1-only",
    # synthetic fixtures (not a claim about any real package)
    "test-strong-copyleft-pkg": "AGPL-3.0-only",
    "test-weak-copyleft-pkg": "MPL-2.0",
    "test-permissive-pkg": "MIT",
    "test-proprietary-pkg": "LicenseRef-Proprietary",
}

NPM_LICENSES = {
    "react": "MIT",
    "lodash": "MIT",
    "express": "MIT",
    "axios": "MIT",
    "moment": "MIT",
    "chalk": "MIT",
    "commander": "MIT",
    "webpack": "MIT",
    "eslint": "MIT",
    "typescript": "Apache-2.0",
    "rxjs": "Apache-2.0",
    "core-js": "MIT",
    "sqlite3": "BSD-3-Clause",
    # synthetic fixtures (not a claim about any real package)
    "test-strong-copyleft-pkg": "GPL-3.0-only",
    "test-weak-copyleft-pkg": "LGPL-3.0-only",
    "test-permissive-pkg": "ISC",
}

_DB = {
    "pypi": PYPI_LICENSES,
    "npm": NPM_LICENSES,
}


def normalize_pypi_name(name: str) -> str:
    return name.strip().lower().replace("_", "-").replace(".", "-")


def lookup(ecosystem: str, name: str) -> str | None:
    """Return the SPDX license id for a package, or None if unknown."""
    table = _DB.get(ecosystem, {})
    key = normalize_pypi_name(name) if ecosystem == "pypi" else name.strip().lower()
    return table.get(key)
