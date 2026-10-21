"""Browser-only entry point; no filesystem reads, network calls or execution."""
import json
from download_inspector.inspection import inspect_bytes
from download_inspector.hashing import InspectionError

def dispatch(route, body, metadata, auxiliary):
    if route == "/api/health":
        return {"status": 200, "data": {"status": "ready"}}
    if route != "/api/inspect":
        raise InspectionError("Unknown analysis route.")
    return {"status": 200, "data": inspect_bytes(body, metadata.get("name", "selected-file"), metadata.get("expected"))}

def _dispatch_json(route, body, metadata, auxiliary):
    try:
        result = dispatch(route, body, json.loads(metadata), auxiliary)
    except (InspectionError, ValueError, TypeError):
        result = {"status": 400, "data": {"error": "입력을 검사하지 못했습니다. 파일 형식·크기와 SHA-256 기준값을 확인해주세요."}}
    return json.dumps(result, ensure_ascii=True, allow_nan=False)
