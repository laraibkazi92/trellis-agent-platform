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

@router.get("/{doc_type}", response_class=HTMLResponse)
async def read_doc(request: Request, doc_type: str):
    user = request.session.get('user')
    
    if doc_type == "agents":
        file_path = BASE_DIR / "DOCS_AGENTS.md"
        title = "Agent Developer Guide"
    elif doc_type == "tools":
        file_path = BASE_DIR / "DOCS_TOOLS.md"
        title = "Tool Developer Guide"
    elif doc_type == "builder":
        file_path = BASE_DIR / "DOCS_AGENT_BUILDER.md"
        title = "Agent Builder Guide"
    elif doc_type == "mcp":
        file_path = BASE_DIR / "DOCS_MCP.md"
        title = "MCP Server Guide"
    else:
        return HTMLResponse(content="Documentation not found", status_code=404)

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
