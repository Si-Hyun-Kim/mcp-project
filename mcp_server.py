# mcp_server.py (표준 MCP STDIO 서버 버전)
#!/usr/bin/env python3
import asyncio, re, json, subprocess
from datetime import datetime, timedelta
from collections import defaultdict, deque
from pathlib import Path
import aiofiles

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent

server = Server("security-mcp")  # 서버 이름

# 기존 상태/버퍼 (당신 코드에서 가져옴)
alert_buffer = deque(maxlen=10000)
blocked_ips = set()
rules_path = Path("/etc/suricata/rules/custom.rules")
rule_counter = 9000000

# --------- MCP Tools 정의 ---------
@server.tool("get_alerts", description="최근 알림 조회", schema={"type":"object","properties":{"count":{"type":"integer"}}})
async def get_alerts(count: int = 100):
    alerts = list(alert_buffer)[-count:]
    return {"content":[TextContent(type="text", text=json.dumps({"alerts":alerts}))]}

@server.tool("get_stats", description="보안 통계 조회", schema={"type":"object","properties":{"timeframe":{"type":"string"}}})
async def get_stats(timeframe: str="24h"):
    total_alerts = len(alert_buffer)
    critical_alerts = sum(1 for a in alert_buffer if a.get("severity")==1)
    ip_counts = defaultdict(int)
    for a in alert_buffer: ip_counts[a.get("src_ip")] += 1
    top_attackers = sorted(ip_counts.items(), key=lambda x:x[1], reverse=True)[:10]
    data = {"total_alerts":total_alerts,"critical_alerts":critical_alerts,"top_attackers":top_attackers}
    return {"content":[TextContent(type="text", text=json.dumps(data))]}

@server.tool("block_ip", description="iptables로 IP 차단", schema={"type":"object","properties":{"ip":{"type":"string"},"reason":{"type":"string"}},"required":["ip"]})
async def block_ip(ip: str, reason: str="Manual block"):
    if ip in blocked_ips:
        return {"content":[TextContent(type="text", text=f"{ip} already blocked")]}
    cmd = f"sudo iptables -A INPUT -s {ip} -j DROP"
    res = subprocess.run(cmd.split(), capture_output=True, text=True)
    if res.returncode==0:
        blocked_ips.add(ip)
        return {"content":[TextContent(type="text", text=f"Blocked {ip}: {reason}")]}
    return {"content":[TextContent(type="text", text=f"Failed: {res.stderr}")]}

@server.tool("get_rules", description="Suricata 룰 조회")
async def get_rules():
    try:
        async with aiofiles.open(rules_path,'r') as f:
            rules_text = await f.read()
        rules = [line for line in rules_text.splitlines() if line.strip() and not line.startswith('#')]
        return {"content":[TextContent(type="text", text=json.dumps({"rules":rules}))]}
    except Exception as e:
        return {"content":[TextContent(type="text", text=f"error:{e}")]}    

@server.tool("toggle_rule", description="SID로 룰 on/off", schema={"type":"object","properties":{"sid":{"type":"string"}},"required":["sid"]})
async def toggle_rule(sid: str):
    try:
        async with aiofiles.open(rules_path,'r') as f:
            lines = await f.readlines()
        mod=[]
        for line in lines:
            if f"sid:{sid}" in line:
                line = line[1:] if line.startswith('#') else '#'+line
            mod.append(line)
        async with aiofiles.open(rules_path,'w') as f:
            await f.writelines(mod)
        # Suricata 룰 리로드
        subprocess.run("sudo kill -USR2 $(pidof suricata)", shell=True, check=False)
        return {"content":[TextContent(type="text", text=f"Toggled {sid}")]}
    except Exception as e:
        return {"content":[TextContent(type="text", text=f"error:{e}")]}

# --------- STDIO 진입점 ---------
async def main():
    # 경고: STDIO 서버는 print/logging을 stdout에 쓰면 안 됨 (공식 스펙 권고). :contentReference[oaicite:6]{index=6}
    async with stdio_server() as (rx, tx):
        await server.run(rx, tx)

if __name__ == "__main__":
    asyncio.run(main())
