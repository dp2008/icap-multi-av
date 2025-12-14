from fastapi import FastAPI, UploadFile, File
import hashlib
import redis
import asyncio
import httpx
import json
import uvicorn
from typing import List, Dict

app = FastAPI()

# Redis for cache
try:
    cache = redis.Redis(host='hash-db', port=6379, decode_responses=True, socket_connect_timeout=5)
    cache.ping()
    print("Redis connected successfully")
except Exception as e:
    print(f"Warning: Redis connection failed: {e}")
    cache = None

# Engine endpoints (hardcoded for now, later from config)
engines = {
    'clamav': {
        'url': 'http://clamav:8080/scan',
        'active': True,
        'signature_version': '1.0.0',
        'last_update': '2024-12-14 10:00:00',
        'auto_update': False,
        'update_schedule': 'daily'
    },
    'yara': {
        'url': 'http://yara:8080/scan',
        'active': True,
        'signature_version': '4.3.2',
        'last_update': '2024-12-14 10:00:00',
        'auto_update': False,
        'update_schedule': 'daily'
    },
    'oletools': {
        'url': 'http://oletools:8080/scan',
        'active': True,
        'signature_version': '0.60.1',
        'last_update': '2024-12-14 10:00:00',
        'auto_update': False,
        'update_schedule': 'weekly'
    },
    'capa': {
        'url': 'http://capa:8080/scan',
        'active': True,
        'signature_version': '7.0.1',
        'last_update': '2024-12-14 10:00:00',
        'auto_update': False,
        'update_schedule': 'weekly'
    },
}

# Signature files storage (in-memory for demo)
signature_files = {
    'clamav': [],
    'yara': [],
    'oletools': [],
    'capa': []
}

async def scan_with_engine(engine_name: str, file_hash: str, file_content: bytes):
    if not engines[engine_name]['active']:
        return {engine_name: 'inactive'}
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            files = {'file': ('uploaded_file', file_content, 'application/octet-stream')}
            response = await client.post(engines[engine_name]['url'], files=files)
            return {engine_name: response.json()}
        except Exception as e:
            return {engine_name: {'error': str(e)}}

@app.post("/scan")
async def scan_file(file: UploadFile = File(...)):
    file_content = await file.read()
    file_hash = hashlib.sha256(file_content).hexdigest()

    # Check cache
    if cache:
        try:
            cached_result = cache.get(file_hash)
            if cached_result:
                return json.loads(cached_result)
        except:
            pass

    # Parallel scan with active engines
    tasks = [scan_with_engine(name, file_hash, file_content) for name in engines]
    results = await asyncio.gather(*tasks)

    result = {}
    for res in results:
        result.update(res)

    # Cache result
    if cache:
        try:
            cache.set(file_hash, json.dumps(result))
        except:
            pass

    return result

@app.get("/engines")
def get_engines():
    return engines

@app.post("/engines/{engine}/toggle")
async def toggle_engine(engine: str, data: dict):
    active = data.get('active', False)
    
    if engine in engines:
        engines[engine]['active'] = active
        return {"status": "updated"}
    return {"error": "engine not found"}

@app.post("/maintenance/clear-cache")
def clear_cache():
    if cache:
        try:
            cache.flushdb()
            return {"status": "success", "message": "Cache cleared"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    return {"status": "error", "message": "Cache not available"}

@app.get("/engines/{engine}/signatures")
def get_signatures(engine: str):
    if engine in signature_files:
        return {"engine": engine, "signatures": signature_files[engine]}
    return {"error": "engine not found"}

@app.post("/engines/{engine}/signatures/upload")
async def upload_signature(engine: str, file: UploadFile = File(...)):
    if engine not in signature_files:
        return {"error": "engine not found"}
    
    try:
        content = await file.read()
        signature_files[engine].append({
            'name': file.filename,
            'size': len(content),
            'uploaded': '2024-12-14 15:00:00'
        })
        return {"status": "success", "message": f"Signature {file.filename} uploaded"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.delete("/engines/{engine}/signatures/{signature_name}")
def delete_signature(engine: str, signature_name: str):
    if engine not in signature_files:
        return {"error": "engine not found"}
    
    signature_files[engine] = [s for s in signature_files[engine] if s['name'] != signature_name]
    return {"status": "success", "message": f"Signature {signature_name} deleted"}

@app.post("/engines/{engine}/signatures/update")
async def update_signatures(engine: str):
    if engine not in engines:
        return {"error": "engine not found"}
    
    from datetime import datetime
    engines[engine]['last_update'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    engines[engine]['signature_version'] = f"{engines[engine]['signature_version'].split('.')[0]}.{int(engines[engine]['signature_version'].split('.')[1]) + 1}.0"
    
    return {
        "status": "success",
        "message": f"Signatures for {engine} updated",
        "version": engines[engine]['signature_version'],
        "last_update": engines[engine]['last_update']
    }

@app.post("/engines/{engine}/auto-update")
async def set_auto_update(engine: str, data: dict):
    if engine not in engines:
        return {"error": "engine not found"}
    
    engines[engine]['auto_update'] = data.get('enabled', False)
    engines[engine]['update_schedule'] = data.get('schedule', 'daily')
    
    return {
        "status": "success",
        "auto_update": engines[engine]['auto_update'],
        "schedule": engines[engine]['update_schedule']
    }
