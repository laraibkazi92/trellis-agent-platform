# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

import os
from pathlib import Path
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
import markdown
import nh3
from core.dependencies import templates

router = APIRouter(prefix="/docs", tags=["docs"])
BASE_DIR = Path(__file__).parent.parent.parent

@router.get("", response_class=RedirectResponse)
@router.get("/", response_class=RedirectResponse)
async def read_docs_index():
    return RedirectResponse(url="/docs/agents")

DOC_MAP = {
    "agents": ("docs/agents.md", "Agent Developer Guide"),
    "tools": ("docs/tools.md", "Tool Developer Guide"),
    "mcp": ("docs/mcp.md", "MCP Server Guide"),
    "workflows": ("docs/workflows.md", "Background Workflows Guide"),
    "proxy": ("docs/proxy.md", "Edge Proxy Guide"),
}

@router.get("/{doc_type}", response_class=HTMLResponse)
async def read_doc(request: Request, doc_type: str):
    user = request.session.get('user')
    if not user:
        return RedirectResponse(url='/login')

    doc_info = DOC_MAP.get(doc_type)
    if not doc_info:
        return HTMLResponse(content="Documentation not found", status_code=404)
        
    file_path = BASE_DIR / doc_info[0]
    title = doc_info[1]

    if not file_path.exists():
        return HTMLResponse(content="Documentation file not found on server", status_code=404)

    with open(file_path, "r", encoding="utf-8") as f:
        md_content = f.read()

    html_content = nh3.clean(
        markdown.markdown(md_content, extensions=['fenced_code', 'codehilite', 'tables']),
        tags={"p", "br", "h1", "h2", "h3", "h4", "h5", "h6", "ul", "ol", "li",
              "strong", "em", "code", "pre", "blockquote", "table", "thead",
              "tbody", "tr", "th", "td", "hr", "a", "span", "div"},
        attributes={"a": {"href", "title"}, "code": {"class"}, "span": {"class"}, "div": {"class"}, "td": {"align"}, "th": {"align"}},
    )

    return templates.TemplateResponse(
        request=request,
        name="docs.html",
        context={
            "user": user,
            "title": title,
            "html_content": html_content
        }
    )
