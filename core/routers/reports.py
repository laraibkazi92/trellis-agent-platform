import os
import datetime
from pathlib import Path
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from core.dependencies import templates, CSRFRoute
from core.auth import is_admin

router = APIRouter(prefix="/reports", tags=["reports"], route_class=CSRFRoute)

BASE_DIR = Path(__file__).parent.parent.parent
REPORTS_DIR = (BASE_DIR / "workspace" / "reports").resolve()

@router.get("", response_class=HTMLResponse)
@router.get("/", response_class=HTMLResponse)
async def list_reports(request: Request):
    user = request.session.get('user')
    if not user:
        return RedirectResponse(url='/login')
        
    admin_access = is_admin(request)
    
    # Ensure reports directory exists
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    
    # Recursively scan for HTML files
    reports = []
    for file_path in REPORTS_DIR.rglob("*.html"):
        # Resolve to make sure no weird symlinks or tricks
        file_path_resolved = file_path.resolve()
        if not str(file_path_resolved).startswith(str(REPORTS_DIR)):
            continue
            
        try:
            rel_path = file_path_resolved.relative_to(REPORTS_DIR)
        except ValueError:
            continue
            
        stat = file_path_resolved.stat()
        mtime = datetime.datetime.fromtimestamp(stat.st_mtime)
        size = stat.st_size
        
        # Human-readable size
        if size < 1024:
            size_str = f"{size} B"
        elif size < 1024 * 1024:
            size_str = f"{size / 1024:.1f} KB"
        else:
            size_str = f"{size / (1024 * 1024):.1f} MB"
            
        folder_name = str(rel_path.parent).replace("/", " / ").upper() if rel_path.parent != Path(".") else "SYSTEM"
        
        reports.append({
            "name": file_path_resolved.name,
            "path": str(rel_path),
            "folder": folder_name,
            "modified": mtime.strftime("%Y-%m-%d %H:%M:%S"),
            "raw_mtime": stat.st_mtime,
            "size": size_str,
            "raw_size": size
        })
        
    # Sort by modification time descending (newest first)
    reports.sort(key=lambda x: x["raw_mtime"], reverse=True)
    
    flash_msg = request.session.pop("flash_msg", None)
    
    return templates.TemplateResponse(
        request=request,
        name="reports.html",
        context={
            "user": user,
            "reports": reports,
            "is_admin": admin_access,
            "reports_count": len(reports),
            "flash_msg": flash_msg
        }
    )

@router.post("/delete", response_class=RedirectResponse)
async def delete_report(request: Request):
    user = request.session.get('user')
    if not user:
        return RedirectResponse(url='/login', status_code=303)
        
    # Strictly check admin permissions
    if not is_admin(request):
        request.session["flash_msg"] = "Access Denied: Only administrator accounts can delete report files."
        return RedirectResponse(url='/reports', status_code=303)
        
    form = await request.form()
    report_path = form.get("path")
    if not report_path:
        request.session["flash_msg"] = "Invalid request: Missing report path parameter."
        return RedirectResponse(url='/reports', status_code=303)
        
    # Strict path traversal protection
    target_path = (REPORTS_DIR / report_path).resolve()
    if not str(target_path).startswith(str(REPORTS_DIR)):
        request.session["flash_msg"] = "Security Block: Invalid target path."
        return RedirectResponse(url='/reports', status_code=303)
        
    if target_path.exists() and target_path.is_file():
        try:
            target_path.unlink()
            request.session["flash_msg"] = f"Report '{report_path}' successfully deleted from filesystem."
        except Exception as e:
            request.session["flash_msg"] = f"Failed to delete report: {str(e)}"
    else:
        request.session["flash_msg"] = "Error: Report file not found."
        
    return RedirectResponse(url='/reports', status_code=303)
