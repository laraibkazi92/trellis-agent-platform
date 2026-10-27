# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Contract of the browser sealing page, read as source.

This is the test that keeps "no plaintext leaves the page" true: the POST body is the
``envelope`` object literal and nothing else, the AAD is built in the canonical order the
edge recomputes, and inputs exist only for ``secret_keys`` (``variable_keys`` are chips,
so an endpoint override cannot even be typed here).

It parses the partial rather than running a browser: no JS engine, no new dependency.
"""

import re
from pathlib import Path

PARTIAL = Path(__file__).resolve().parents[1] / "templates" / "partials" / "edge_secret_form.html"

ENVELOPE_FIELDS = {
    "v",
    "alg",
    "key_fp",
    "key_id",
    "aad",
    "wrapped_key",
    "iv",
    "ciphertext",
    "keys",
}


def _source() -> str:
    return PARTIAL.read_text(encoding="utf-8")


def _block(source: str, marker: str) -> str:
    """The ``{ ... }`` body that follows ``marker``, brace-matched."""
    start = source.index(marker) + len(marker)
    start = source.index("{", start)
    depth = 0
    for index in range(start, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start + 1:index]
    raise AssertionError(f"unbalanced braces after {marker!r}")


# --- the posted body ----------------------------------------------------------


def test_posted_body_is_exactly_the_envelope():
    body = _block(_source(), "const envelope =")

    fields = set(re.findall(r"^\s*([A-Za-z_][A-Za-z0-9_]*):", body, re.MULTILINE))

    assert fields == ENVELOPE_FIELDS


def test_the_envelope_is_what_is_sent():
    source = _source()

    assert "JSON.stringify(envelope)" in source
    # The request body is the envelope only: no form field, no plaintext value map.
    assert re.search(r"body:\s*JSON\.stringify\(envelope\)", source)
    for forbidden in ("localStorage", "sessionStorage", "plaintext:", "values:"):
        assert forbidden not in source


def test_post_carries_the_csrf_header_and_the_target_path():
    source = _source()

    assert '"X-CSRF-Token": csrfToken' in source
    assert "/configuration/edge-secrets/" in source
    assert "/pubkey" in source


# --- the AAD ------------------------------------------------------------------


def test_aad_is_built_in_the_canonical_order():
    match = re.search(r"const aad = \[(.*?)\]\.join\(\"\\?\|\"\);", _source())

    assert match, "the partial must build the AAD as an array joined with '|'"
    tokens = re.findall(r'"([^"]*)"|([A-Za-z_][A-Za-z0-9_]*)', match.group(1))
    parts = [quoted or bare for quoted, bare in tokens]
    assert parts == ["v1", "site", "kind", "name", "identity", "key_id"]


# --- which names get an input -------------------------------------------------


def test_inputs_are_rendered_only_for_secret_keys():
    source = _source()
    fields = _block(source, "function renderFields(payload)")

    assert "payload.secret_keys.forEach" in fields
    assert "input.type = \"password\"" in fields
    assert "payload.variable_keys" not in fields


def test_variable_keys_are_read_only():
    source = _source()
    variables = _block(source, "function renderVariables(payload)")

    assert "payload.variable_keys.forEach" in variables
    assert "payload.secret_keys" not in variables
    assert 'createElement("input")' not in variables
    assert "createElement(\"span\")" in variables


def test_rotation_state_is_offered():
    source = _source()

    assert "re-enter credentials (edge key rotated)" in source
    # The server's needsReentry is the only verdict: during a healthy rotation
    # overlap a previous-key blob still opens, so comparing fps would be wrong.
    assert "current.needsReentry" in source
    assert "storedFp !== payload.key_fp" not in source


# --- approval state -----------------------------------------------------------


def test_the_fingerprint_the_page_encrypts_to_is_displayed():
    source = _source()

    assert 'id="edge-secret-fingerprint"' in source
    assert 'id="edge-secret-fingerprint-value"' in source
    assert "fingerprintValueEl.textContent = payload.key_fp;" in source


def test_a_pending_key_blocks_sealing_and_names_the_fingerprint():
    source = _source()
    open_modal = _block(source, "async function openModal(button)")

    assert 'id="edge-secret-pending"' in source
    assert 'id="edge-secret-pending-message"' in source
    # 409 key_pending_approval is its own state: it shows the server's message (which
    # names the fingerprint) instead of a generic error.
    assert 'payload.error === "key_pending_approval"' in open_modal
    assert "showPending(payload.detail" in open_modal
    # Nothing on the pending path can enable the submit button: it is set once at the
    # start, and only the success path may re-evaluate it.
    assert "submitBtn.disabled = false" not in open_modal


# --- the page wiring ----------------------------------------------------------


def test_configuration_page_opens_the_modal_per_edge_target():
    page = (PARTIAL.parents[1] / "configuration.html").read_text(encoding="utf-8")

    assert '{% include "partials/edge_secret_form.html" %}' in page
    for attribute in (
        "data-edge-secret-open",
        "data-site",
        "data-kind",
        "data-name",
        "data-key-fp",
        "data-needs-reentry",
    ):
        assert attribute in page
    assert "re-enter credentials (edge key rotated)" in page
