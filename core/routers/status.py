import os
from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from core.discovery import discover_agents, discover_tools
import core.health_db as health_db
from core.routers.auth import require_auth

router = APIRouter()

# Setup Jinja2 templates (temporarily return json if template missing)
# Phase 4 will fully build status.html, for now we will just prepare the API/Router
templates_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "templates")
try:
    templates = Jinja2Templates(directory=templates_dir)
except Exception:
    templates = None

from datetime import datetime, timedelta, timezone

def generate_30_day_timeline(events, current_status):
    now = datetime.now(timezone.utc)
    timeline = []
    
    # Pre-parse timestamps once to avoid repetitive parsing in the loop
    parsed_events = []
    for e in events:
        timestamp_str = e["timestamp"].replace("Z", "+00:00")
        try:
            e_time = datetime.fromisoformat(timestamp_str)
            # If naive, make it UTC
            if e_time.tzinfo is None:
                e_time = e_time.replace(tzinfo=timezone.utc)
            parsed_events.append({"status": e["status"], "time": e_time})
        except Exception:
            continue
    
    for i in range(29, -1, -1):
        target_date = (now - timedelta(days=i)).date()
        target_datetime_end = datetime(target_date.year, target_date.month, target_date.day, 23, 59, 59, tzinfo=timezone.utc)
        
        # Determine the status for this day
        day_status = "Online"
        
        # Get the last known status up to the end of this day
        last_event_status = None
        for e in parsed_events:
            if e["time"] <= target_datetime_end:
                last_event_status = e["status"]
                
        if last_event_status:
            day_status = last_event_status
            
        # Highlight if there was ANY outage on this specific day
        for e in parsed_events:
            if e["time"].date() == target_date and e["status"] == "Offline":
                day_status = "Offline"
                break
                
        timeline.append({
            "day_label": target_date.isoformat(),
            "status": day_status,
            "index": 30 - i
        })
        
    # Ensure the final day reflects the actual current status if we have one
    if timeline and current_status:
        timeline[-1]["status"] = current_status.get("status", "Online")
        
    return timeline

@router.get("/status", response_class=HTMLResponse)
async def status_page(request: Request, user=Depends(require_auth)):
    agents = await discover_agents()
    tools = await discover_tools()
    
    total_entities = len(agents) + len(tools)
    offline_count = 0
    
    for agent in agents:
        agent_name = agent["name"]
        status_info = agent.get("health", {})
        if status_info.get("status") == "Offline":
            offline_count += 1
        events = health_db.get_events_for_entity("agent", agent_name)
        agent["timeline"] = generate_30_day_timeline(events, status_info)
        
    for tool in tools:
        tool_name = tool["name"]
        status_info = tool.get("health", {})
        if status_info.get("status") == "Offline":
            offline_count += 1
        events = health_db.get_events_for_entity("tool", tool_name)
        tool["timeline"] = generate_30_day_timeline(events, status_info)
        
    overall_status = "Operational"
    if total_entities > 0:
        if offline_count == total_entities:
            overall_status = "Major Outage"
        elif offline_count > (total_entities / 2):
            overall_status = "Major Outage"
        elif offline_count > 0:
            overall_status = "Partial Outage"
            
    context = {
        "request": request,
        "user": user,
        "overall_status": overall_status,
        "agents": agents,
        "tools": tools,
        "offline_count": offline_count,
        "total_entities": total_entities
    }
    
    # Temporarily return JSON if the template doesn't exist yet (Phase 4 creates it)
    if templates and os.path.exists(os.path.join(templates_dir, "status.html")):
        return templates.TemplateResponse(
            request=request,
            name="status.html", 
            context=context
        )
    else:
        # Before Phase 4, return JSON to verify aggregation works
        return JSONResponse({
            "overall_status": overall_status,
            "offline_count": offline_count,
            "total_entities": total_entities,
            "agents": agents,
            "tools": tools
        })
