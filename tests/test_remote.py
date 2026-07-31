"""Offline unit tests for the --online payload reducer.

``license_radar.remote`` hits the network in ``fetch_*_license`` and is
therefore excluded from this deterministic suite, but its pure payload
reduction (``reduce_pypi_info``) must stay correct -- it decides which field of
a PyPI ``info`` object becomes the token handed to the classifier -- so it is
exercised here with hand-built payloads and no network.
"""

from license_radar.remote import reduce_pypi_info


def test_prefers_license_expression():
    # Modern PyPI puts dual-license SPDX expressions here; this is the field
    # that made real packages (packaging, pycurl, orjson) resolvable online.
    info = {
        "license_expression": "Apache-2.0 OR BSD-2-Clause",
        "license": "should be ignored",
        "classifiers": ["License :: OSI Approved :: MIT License"],
    }
    assert reduce_pypi_info(info) == "Apache-2.0 OR BSD-2-Clause"


def test_falls_back_to_osi_classifier():
    info = {
        "license_expression": "",
        "license": "",
        "classifiers": [
            "Programming Language :: Python :: 3",
            "License :: OSI Approved :: Apache Software License",
        ],
    }
    assert reduce_pypi_info(info) == "Apache Software License"


def test_falls_back_to_short_free_text():
    info = {"license_expression": "", "license": "MIT", "classifiers": []}
    assert reduce_pypi_info(info) == "MIT"


def test_accepts_long_single_line_spdx_expression():
    # pyside6 declares its expression in the legacy free-text field and it is
    # 44 chars -- a 40-char cap would wrongly drop it. It must survive to the
    # classifier (which resolves the OR to weak-copyleft).
    expr = "LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only"
    info = {"license_expression": "", "license": expr, "classifiers": []}
    assert reduce_pypi_info(info) == expr


def test_rejects_full_license_text_dump():
    blob = "Permission is hereby granted, free of charge, to any person " * 3
    info = {"license_expression": "", "license": blob, "classifiers": []}
    assert reduce_pypi_info(info) is None


def test_rejects_multiline_free_text():
    info = {"license_expression": "", "license": "MIT\nplus extra terms", "classifiers": []}
    assert reduce_pypi_info(info) is None


def test_empty_payload_returns_none():
    assert reduce_pypi_info({}) is None
