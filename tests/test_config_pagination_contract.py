# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Contract of the shared /configuration search + pagination script.

Both ``configuration.html`` and ``admin_configuration.html`` render
``#pagination-controls`` inside ``{% if items %}``: a page with no configuration
keys (and no edge credential cards) has no controls element at all, while
``#no-results-msg`` is always rendered. ``updateUI()`` runs on
``DOMContentLoaded``, so an unguarded dereference threw
``TypeError: Cannot set properties of null (setting 'innerHTML')`` on every empty
page -- and again on each keystroke, because the input listener is attached
before the first call.

Parses the partial as source, like ``test_edge_secret_ui_contract``: no JS engine,
no new dependency.
"""

from pathlib import Path

TEMPLATES = Path(__file__).resolve().parents[1] / "templates"
PARTIAL = TEMPLATES / "partials" / "_config_search_pagination.html"
PAGES = ("configuration.html", "admin_configuration.html")


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


def test_render_pagination_returns_before_touching_missing_controls():
    body = _block(_source(), "function renderPagination(totalPages)")
    before_first_write = body.split("paginationControls.innerHTML", 1)[0]

    assert "!paginationControls" in before_first_write


def test_no_match_message_is_only_for_a_filter_miss():
    """An empty page must not claim that a search matched nothing."""
    body = _block(_source(), "function updateUI()")
    empty_items_branch = body.split("else {", 1)[0]

    assert "items.length > 0" in empty_items_branch
    assert "noResultsMsg.classList" not in empty_items_branch


def test_optional_elements_are_only_written_through_the_guarded_helpers():
    source = _source()

    for unguarded_write in ("paginationSummary.textContent =", "noResultsMsg.classList."):
        assert unguarded_write not in source


def test_the_controls_really_are_conditional_in_both_pages():
    """Pins the reason the JS guard is load-bearing."""
    for name in PAGES:
        source = (TEMPLATES / name).read_text(encoding="utf-8")
        block_start = source.index("{% if items %}")
        block_end = source.index("{% endif %}", block_start)

        assert 'id="pagination-controls"' in source[block_start:block_end]
        assert 'id="no-results-msg"' not in source[block_start:block_end]
