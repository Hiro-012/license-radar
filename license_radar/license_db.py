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
    # Below: verified 2026-07-25 against the live PyPI JSON API
    # (license_expression / classifiers / license field, in that priority
    # order). Compound expressions ("A AND B", "A OR B") are collapsed to
    # a single representative id: for AND, the more restrictive tier (all
    # terms apply); for OR, a permissive alternative (the licensee may
    # choose it) when all options are same-tier.
    "fastapi": "MIT",
    "httpx": "BSD-3-Clause",
    "aiohttp": "Apache-2.0",  # "Apache-2.0 AND MIT", both permissive
    "pydantic": "MIT",
    "starlette": "BSD-3-Clause",
    "uvicorn": "BSD-3-Clause",
    "cryptography": "Apache-2.0",  # "Apache-2.0 OR BSD-3-Clause"
    "attrs": "MIT",
    "packaging": "Apache-2.0",  # "Apache-2.0 OR BSD-2-Clause"
    "platformdirs": "MIT",
    "tomli": "MIT",
    "typing-extensions": "PSF-2.0",
    "zipp": "MIT",
    "tqdm": "MPL-2.0",  # "MPL-2.0 AND MIT": MPL-2.0 terms still bind
    "rich": "MIT",
    "pygments": "BSD-2-Clause",
    "markdown": "BSD-3-Clause",
    "pyjwt": "MIT",
    "bcrypt": "Apache-2.0",
    "python-dateutil": "Apache-2.0",  # dual Apache-2.0/BSD, both permissive
    "pytz": "MIT",
    "tzdata": "Apache-2.0",
    "charset-normalizer": "MIT",
    "cffi": "MIT-0",
    "pycparser": "BSD-3-Clause",
    "greenlet": "MIT",  # "MIT AND PSF-2.0", both permissive
    "yarl": "Apache-2.0",
    "anyio": "MIT",
    "sniffio": "MIT",  # "MIT OR Apache-2.0", both permissive
    "h11": "MIT",
    "websockets": "BSD-3-Clause",
    "psutil": "BSD-3-Clause",
    "lxml": "BSD-3-Clause",
    "beautifulsoup4": "MIT",
    "matplotlib": "PSF-2.0",
    "grpcio": "Apache-2.0",
    "pymongo": "Apache-2.0",
    "flask-cors": "MIT",
    "black": "MIT",
    "mypy": "MIT",
    "ruff": "MIT",
    "poetry-core": "MIT",
    "virtualenv": "MIT",
    "pip": "MIT",
    "pluggy": "MIT",
    "iniconfig": "MIT",
    "exceptiongroup": "MIT",
    "filelock": "MIT",
    "distlib": "PSF-2.0",
    "protobuf": "BSD-3-Clause",  # registry text: "3-Clause BSD License"
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
    # Below: verified 2026-07-25 against the live npm registry API
    # (registry.npmjs.org/<pkg>/latest "license" field, already SPDX).
    "vue": "MIT",
    "angular": "MIT",
    "jquery": "MIT",
    "bootstrap": "MIT",
    "tailwindcss": "MIT",
    "vite": "MIT",
    "rollup": "MIT",
    "babel-core": "MIT",
    "@babel/core": "MIT",
    "prettier": "MIT",
    "jest": "MIT",
    "mocha": "MIT",
    "chai": "MIT",
    "sinon": "BSD-3-Clause",
    "yargs": "MIT",
    "inquirer": "MIT",
    "dotenv": "BSD-2-Clause",
    "uuid": "MIT",
    "semver": "ISC",
    "glob": "BlueOak-1.0.0",
    "minimist": "MIT",
    "nodemon": "MIT",
    "pm2": "AGPL-3.0",
    "socket.io": "MIT",
    "ws": "MIT",
    "cors": "MIT",
    "body-parser": "MIT",
    "cookie-parser": "MIT",
    "morgan": "MIT",
    "helmet": "MIT",
    "joi": "BSD-3-Clause",
    "zod": "MIT",
    "graphql": "MIT",
    "apollo-server": "MIT",
    "next": "MIT",
    "nuxt": "MIT",
    "svelte": "MIT",
    "preact": "MIT",
    "underscore": "MIT",
    "ramda": "MIT",
    "immer": "MIT",
    "redux": "MIT",
    "mobx": "MIT",
    "classnames": "MIT",
    "styled-components": "MIT",
    "uglify-js": "BSD-2-Clause",
    "terser": "BSD-2-Clause",
    "postcss": "MIT",
    "autoprefixer": "MIT",
    "sass": "MIT",
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
