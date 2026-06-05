import os
import datetime
import math
from pathlib import Path
from fastapi import APIRouter, Request, Form, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.concurrency import run_in_threadpool
import logging

from core.dependencies import templates, CSRFRoute
from core.auth import is_admin

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/reports", tags=["reports"], route_class=CSRFRoute)

BASE_DIR = Path(__file__).parent.parent.parent
REPORTS_DIR = (BASE_DIR / "workspace" / "reports").resolve()

def _scan_reports_directories():
    agent_folders = []
    
    # Check for files directly in REPORTS_DIR (root level)
    root_report_count = 0
    root_total_size = 0
    root_latest_mtime = 0
    
    for item in REPORTS_DIR.iterdir():
        if item.is_file() and item.suffix == '.html':
            try:
                stat = item.stat()
                root_report_count += 1
                root_total_size += stat.st_size
                if stat.st_mtime > root_latest_mtime:
                    root_latest_mtime = stat.st_mtime
            except Exception as e:
                logger.warning(f"Failed to stat root file {item}: {e}")
                continue
                
        elif item.is_dir():
            folder_name = item.name
            report_count = 0
            total_size = 0
            latest_mtime = 0
            
            for file_path in item.rglob("*.html"):
                try:
                    stat = file_path.stat()
                    report_count += 1
                    total_size += stat.st_size
                    if stat.st_mtime > latest_mtime:
                        latest_mtime = stat.st_mtime
                except Exception as e:
                    logger.warning(f"Failed to stat file {file_path}: {e}")
                    continue
            
            if report_count > 0:
                agent_folders.append({
                    "name": folder_name,
                    "report_count": report_count,
                    "raw_size": total_size,
                    "raw_mtime": latest_mtime,
                })
                
    if root_report_count > 0:
        agent_folders.append({
            "name": "system-root",
            "is_root": True,
            "report_count": root_report_count,
            "raw_size": root_total_size,
            "raw_mtime": root_latest_mtime,
        })
        
    for folder in agent_folders:
        size = folder["raw_size"]
        if size < 1024:
            size_str = f"{size} B"
        elif size < 1024 * 1024:
            size_str = f"{size / 1024:.1f} KB"
        else:
            size_str = f"{size / (1024 * 1024):.1f} MB"
            
        latest_mtime = folder["raw_mtime"]
        if latest_mtime > 0:
            mtime_str = datetime.datetime.fromtimestamp(latest_mtime).strftime("%Y-%m-%d %H:%M:%S")
        else:
            mtime_str = "Never"
            
        folder["size"] = size_str
        folder["modified"] = mtime_str

    agent_folders.sort(key=lambda x: x["raw_mtime"], reverse=True)
    return agent_folders

@router.get("", response_class=HTMLResponse)
@router.get("/", response_class=HTMLResponse)
async def list_reports(request: Request):
    user = request.session.get('user')
    if not user:
        return RedirectResponse(url='/login')
        
    admin_access = is_admin(request)
    
    # Ensure reports directory exists
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    
    # Run heavy I/O operations in a threadpool to prevent event loop blocking
    agent_folders = await run_in_threadpool(_scan_reports_directories)
    
    flash_msg = request.session.pop("flash_msg", None)
    
    return templates.TemplateResponse(
        request=request,
        name="reports.html",
        context={
            "user": user,
            "agent_folders": agent_folders,
            "is_admin": admin_access,
            "folders_count": len(agent_folders),
            "flash_msg": flash_msg
        }
    )

def _scan_agent_reports(agent_name: str):
    reports = []
    
    if agent_name == "system-root":
        # Scan root directory only
        for item in REPORTS_DIR.iterdir():
            if item.is_file() and item.suffix == '.html':
                try:
                    stat = item.stat()
                    rel_path = item.relative_to(REPORTS_DIR)
                    reports.append({
                        "name": item.name,
                        "path": str(rel_path),
                        "raw_mtime": stat.st_mtime,
                        "raw_size": stat.st_size,
                    })
                except Exception as e:
                    logger.warning(f"Failed to stat root file {item}: {e}")
                    continue
    else:
        agent_dir = (REPORTS_DIR / agent_name).resolve()
        if not str(agent_dir).startswith(str(REPORTS_DIR)) or not agent_dir.exists() or not agent_dir.is_dir():
            return None
            
        for file_path in agent_dir.rglob("*.html"):
            try:
                stat = file_path.stat()
                rel_path = file_path.relative_to(REPORTS_DIR)
                reports.append({
                    "name": file_path.name,
                    "path": str(rel_path),
                    "raw_mtime": stat.st_mtime,
                    "raw_size": stat.st_size,
                })
            except Exception as e:
                logger.warning(f"Failed to stat file {file_path}: {e}")
                continue
                
    for report in reports:
        size = report["raw_size"]
        if size < 1024:
            size_str = f"{size} B"
        elif size < 1024 * 1024:
            size_str = f"{size / 1024:.1f} KB"
        else:
            size_str = f"{size / (1024 * 1024):.1f} MB"
            
        mtime = datetime.datetime.fromtimestamp(report["raw_mtime"])
        report["size"] = size_str
        report["modified"] = mtime.strftime("%Y-%m-%d %H:%M:%S")
        
    reports.sort(key=lambda x: x["raw_mtime"], reverse=True)
    return reports

@router.get("/dir/{agent_name}", response_class=HTMLResponse)
async def list_agent_reports(request: Request, agent_name: str, page: int = Query(1, ge=1), limit: int = Query(50, ge=1, le=500)):
    user = request.session.get('user')
    if not user:
        return RedirectResponse(url='/login')
        
    admin_access = is_admin(request)
    
    # Run heavy I/O operations in a threadpool
    reports = await run_in_threadpool(_scan_agent_reports, agent_name)
    
    if reports is None:
        request.session["flash_msg"] = "Agent reports directory not found."
        return RedirectResponse(url='/reports', status_code=303)
        
    total_reports = len(reports)
    total_pages = math.ceil(total_reports / limit) if total_reports > 0 else 1
    
    # Pagination slicing
    start_idx = (page - 1) * limit
    end_idx = start_idx + limit
    paginated_reports = reports[start_idx:end_idx]
    
    flash_msg = request.session.pop("flash_msg", None)
    
    return templates.TemplateResponse(
        request=request,
        name="report_list.html",
        context={
            "user": user,
            "reports": paginated_reports,
            "agent_name": agent_name,
            "is_admin": admin_access,
            "reports_count": total_reports,
            "page": page,
            "total_pages": total_pages,
            "limit": limit,
            "has_next": page < total_pages,
            "has_prev": page > 1,
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
    agent_name = form.get("agent_name")
    
    redirect_url = f'/reports/dir/{agent_name}' if agent_name else '/reports'
    
    if not report_path:
        request.session["flash_msg"] = "Invalid request: Missing report path parameter."
        return RedirectResponse(url=redirect_url, status_code=303)
        
    # Strict path traversal protection
    target_path = (REPORTS_DIR / report_path).resolve()
    if not str(target_path).startswith(str(REPORTS_DIR)):
        request.session["flash_msg"] = "Security Block: Invalid target path."
        return RedirectResponse(url=redirect_url, status_code=303)
        
    if target_path.exists() and target_path.is_file():
        try:
            target_path.unlink()
            request.session["flash_msg"] = f"Report successfully deleted."
        except Exception as e:
            request.session["flash_msg"] = f"Failed to delete report: {str(e)}"
    else:
        request.session["flash_msg"] = "Error: Report file not found."
        
    return RedirectResponse(url=redirect_url, status_code=303)
