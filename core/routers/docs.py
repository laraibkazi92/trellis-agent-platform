import os
from pathlib import Path
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
import markdown
from core.dependencies import templates

router = APIRouter(prefix="/docs", tags=["docs"])
BASE_DIR = Path(__file__).parent.parent.parent

@router.get("", response_class=RedirectResponse)
@router.get("/", response_class=RedirectResponse)
async def read_docs_index():
    return RedirectResponse(url="/docs/agents")

DOC_MAP = {
    "agents": ("DOCS_AGENTS.md", "Agent Developer Guide"),
    "tools": ("DOCS_TOOLS.md", "Tool Developer Guide"),
    "builder": ("DOCS_AGENT_BUILDER.md", "Agent Builder Guide"),
    "mcp": ("DOCS_MCP.md", "MCP Server Guide"),
    "workflows": ("DOCS_WORKFLOWS.md", "Background Workflows Guide"),
}

@router.get("/{doc_type}", response_class=HTMLResponse)
async def read_doc(request: Request, doc_type: str):
    user = request.session.get('user')
    
    doc_info = DOC_MAP.get(doc_type)
    if not doc_info:
        return HTMLResponse(content="Documentation not found", status_code=404)
        
    file_path = BASE_DIR / doc_info[0]
    title = doc_info[1]

    if not file_path.exists():
        return HTMLResponse(content="Documentation file not found on server", status_code=404)

    with open(file_path, "r", encoding="utf-8") as f:
        md_content = f.read()

    html_content = markdown.markdown(md_content, extensions=['fenced_code', 'codehilite', 'tables'])

    return templates.TemplateResponse(
        request=request,
        name="docs.html",
        context={
            "user": user,
            "title": title,
            "html_content": html_content
        }
    )
