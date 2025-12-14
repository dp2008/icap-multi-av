from fastapi import FastAPI, UploadFile, File
import hashlib
import redis
import asyncio
import requests
import json
from typing import List, Dict

app = FastAPI()

# Redis for cache
cache = redis.Redis(host='hash-db', port=6379, decode_responses=True)

# Engine endpoints (hardcoded for now, later from config)
engines = {
    'clamav': {'url': 'http://clamav:8080/scan', 'active': True},
    'yara': {'url': 'http://yara:8080/scan', 'active': True},
    'oletools': {'url': 'http://oletools:8080/scan', 'active': True},
    'capa': {'url': 'http://capa:8080/scan', 'active': True},
}

async def scan_with_engine(engine_name: str, file_hash: str, file_content: bytes):
    if not engines[engine_name]['active']:
        return {engine_name: 'inactive'}
    try:
        response = requests.post(engines[engine_name]['url'], files={'file': file_content}, timeout=30)
        return {engine_name: response.json()}
    except Exception as e:
        return {engine_name: {'error': str(e)}}

@app.post("/scan")
async def scan_file(file: UploadFile = File(...)):
    file_content = await file.read()
    file_hash = hashlib.sha256(file_content).hexdigest()

    # Check cache
    cached_result = cache.get(file_hash)
    if cached_result:
        return json.loads(cached_result)

    # Parallel scan with active engines
    tasks = [scan_with_engine(name, file_hash, file_content) for name in engines]
    results = await asyncio.gather(*tasks)

    result = {}
    for res in results:
        result.update(res)

    # Cache result
    cache.set(file_hash, json.dumps(result))

    return result

@app.get("/engines")
def get_engines():
    return engines

@app.post("/engines/{engine}/toggle")
def toggle_engine(engine: str, active: bool):
    if engine in engines:
        engines[engine]['active'] = active
        return {"status": "updated"}
    return {"error": "engine not found"}
