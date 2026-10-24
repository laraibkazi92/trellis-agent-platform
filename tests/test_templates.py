# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Every template must parse before it can be deployed.

A literal Jinja tag inside a JavaScript comment (for example writing
``{% if items %}`` to describe another template) opens a real block. The page then
500s at render time with "Unexpected end of template", and unit tests that only
exercise the route helpers never compile the template -- which is exactly how that
shipped once.

Parsing is enough to catch it; nothing is rendered, so this needs no app context.
"""

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

TEMPLATES = Path(__file__).resolve().parents[1] / "templates"


def test_every_template_parses():
    env = Environment(loader=FileSystemLoader(str(TEMPLATES)))
    broken = []

    for path in sorted(TEMPLATES.rglob("*.html")):
        name = path.relative_to(TEMPLATES).as_posix()
        try:
            env.get_template(name)
        except Exception as exc:  # noqa: BLE001 - collect every broken template
            broken.append(f"{name}: {exc}")

    assert not broken, "\n".join(broken)
