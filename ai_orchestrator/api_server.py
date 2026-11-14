import asyncio
import json
import sqlite3
import subprocess
import sys
import os
from datetime import datetime
from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="pydantic")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

log_queue = asyncio.Queue()
active_threats = set()
blocked_ips = set() 

DB_PATH = os.path.abspath("aegis_soc.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE,
            reason TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    
    cursor.execute("SELECT ip_address FROM blocked_ips")
    for row in cursor.fetchall():
        blocked_ips.add(row[0])
        
    conn.close()
    print(f"\n[AegisNet] SQLite DB active at: {DB_PATH}")
    print(f"[AegisNet] Currently Blocked IPs: {blocked_ips}\n")

init_db()

async def read_cpp_sniffer():
    """Runs the C++ DPI engine and strictly filters traffic."""
    cmd = ["docker", "compose", "exec", "-T", "dpi_engine", "./build/aegis_sniffer"]
    
    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )

    while True:
        line = await process.stdout.readline()
        if not line:
            break
        
        decoded_line = line.decode('utf-8', errors='ignore').strip()
        if not decoded_line:
            continue
        
        # 1. AGGRESSIVE NOISE FILTERING
        # Blocks Docker Desktop background traffic and raw HTTP fragments
        noise = ["api.moby.localhost", "Docker-Client", "DockerDesktopUI", "/v1.", "/_ping", "/images/", "/containers/", "/networks", "HTTP/1.1Host:"]
        if any(n in decoded_line for n in noise):
            continue
        
        # 2. EXTRACT IP & PAYLOAD SAFELY
        src_ip = "127.0.0.1" # Fallback if split fails
        payload = decoded_line
        
        if "SRC:" in decoded_line:
            try:
                src_ip = decoded_line.split("SRC:")[1].split("|")[0].strip()
            except:
                pass
                
        if "L7_PAYLOAD:" in decoded_line:
            try:
                payload = decoded_line.split("L7_PAYLOAD:")[1].strip()
            except:
                pass
        
        # 3. STRICT BLOCKLIST ENFORCEMENT
        # If the IP is in SQLite, drop the packet completely so it never hits the UI
        if src_ip in blocked_ips:
            continue

        # 4. THREAT DETECTION (Matches run_idps.sh exactly)
        is_suspicious = "'1'='1" in decoded_line or "%27" in decoded_line or "login.php" in decoded_line

        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        log_entry = {
            "type": "log",
            "timestamp": timestamp,
            "ip": src_ip,
            "payload": payload[:150], # Keep UI neatly truncated
            "isSuspicious": is_suspicious
        }
        
        await log_queue.put(log_entry)

        # Trigger AI exactly once per IP
        if is_suspicious and src_ip not in active_threats:
            active_threats.add(src_ip)
            asyncio.create_task(trigger_ai_investigation(src_ip, decoded_line))


async def trigger_ai_investigation(ip, raw_packet_line):
    """Executes the real orchestrator.py and streams its terminal stdout."""
    await log_queue.put({
        "type": "investigation_step", 
        "ip": ip, 
        "triggerPayload": raw_packet_line[:100] + "...", 
        "msg": f"Initiating live CrewAI Agents for {ip}..."
    })
    
    # Execute your existing CrewAI script
    process = await asyncio.create_subprocess_exec(
        sys.executable, "-u", "orchestrator.py", raw_packet_line,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT
    )
    
    # Read Ollama/CrewAI terminal output line-by-line and push to React
    while True:
        line = await process.stdout.readline()
        if not line:
            break
            
        out_line = line.decode('utf-8', errors='ignore').strip()
        if out_line:
            await log_queue.put({
                "type": "investigation_step",
                "ip": ip,
                "msg": out_line
            })
    
    await process.wait()
    await log_queue.put({"type": "investigation_complete", "ip": ip})
    
    # 15 second cooldown before this IP can trigger another alert 
    await asyncio.sleep(15)
    active_threats.discard(ip)


@app.get("/stream")
async def sse_stream():
    """Server-Sent Events endpoint."""
    async def event_generator():
        while True:
            log_data = await log_queue.get()
            yield f"data: {json.dumps(log_data)}\n\n"
    
    return StreamingResponse(event_generator(), media_type="text/event-stream")

class BlockRequest(BaseModel):
    ip: str
    reason: str = "AegisNet Auto-Block: AI SOC Recommended"

@app.post("/api/block")
async def block_ip(request: BlockRequest):
    """Executes UFW rule and logs to DB."""
    subprocess.run(["sudo", "ufw", "deny", "from", request.ip, "to", "any", "comment", "AegisNet Block"], check=False)
    
    blocked_ips.add(request.ip)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO blocked_ips (ip_address, reason) VALUES (?, ?)", (request.ip, request.reason))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    finally:
        conn.close()
        
    return {"status": "success", "blocked_ip": request.ip}

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(read_cpp_sniffer())