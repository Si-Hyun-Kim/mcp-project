#!/usr/bin/env python3
"""
MCP Security Agent
Automated threat detection and response system
Integrates with MCP Server for coordinated defense
"""

import json
import asyncio
import logging
import aiohttp
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path
from collections import defaultdict, deque
import hashlib
import re
import yaml
import aiofiles

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SecurityAgent:
    """Automated Security Defense Agent"""
    
    def __init__(self, config_path: str = "agent_config.yaml"):
        self.config = self.load_config(config_path)
        self.mcp_server_url = self.config.get("mcp_server", "http://localhost:8080")
        self.check_interval = self.config.get("check_interval", 30)
        self.threat_threshold = self.config.get("threat_threshold", 50)
        self.auto_block = self.config.get("auto_block", True)
        self.whitelist = set(self.config.get("whitelist", []))
        self.threat_intelligence = {}
        self.active_threats = defaultdict(dict)
        self.response_history = deque(maxlen=1000)
        self.ml_model = None  # Placeholder for ML model
        
    def load_config(self, config_path: str) -> Dict:
        """Load agent configuration"""
        config_file = Path(config_path)
        
        # Default configuration
        default_config = {
            "mcp_server": "http://localhost:8080",
            "check_interval": 30,
            "threat_threshold": 50,
            "auto_block": True,
            "whitelist": ["127.0.0.1", "192.168.1.1"],
            "alert_thresholds": {
                "critical": 1,
                "high": 3,
                "medium": 5,
                "low": 10
            },
            "response_actions": {
                "block": True,
                "rate_limit": True,
                "alert": True,
                "isolate": False
            },
            "ml_enabled": False,
            "threat_feeds": [],
            "notification": {
                "email": "",
                "slack": "",
                "webhook": ""
            }
        }
        
        if config_file.exists():
            try:
                with open(config_path, 'r') as f:
                    user_config = yaml.safe_load(f)
                    default_config.update(user_config)
            except Exception as e:
                logger.error(f"Error loading config: {e}, using defaults")
        else:
            # Create default config file
            with open(config_path, 'w') as f:
                yaml.dump(default_config, f, default_flow_style=False)
            logger.info(f"Created default config at {config_path}")
        
        return default_config
    
    async def start(self):
        """Start the security agent"""
        logger.info("Starting Security Agent...")
        logger.info(f"MCP Server: {self.mcp_server_url}")
        logger.info(f"Check interval: {self.check_interval}s")
        logger.info(f"Auto-block: {self.auto_block}")
        
        # Start all agent tasks
        await asyncio.gather(
            self.monitor_threats(),
            self.analyze_patterns(),
            self.update_threat_intelligence(),
            self.health_check(),
            self.automated_response()
        )
    
    async def monitor_threats(self):
        """Monitor threats from MCP server"""
        logger.info("Starting threat monitoring...")
        
        while True:
            try:
                # Get alerts from MCP server
                alerts = await self.fetch_alerts()
                
                if alerts:
                    await self.process_alerts(alerts)
                
                await asyncio.sleep(self.check_interval)
                
            except Exception as e:
                logger.error(f"Error monitoring threats: {e}")
                await asyncio.sleep(self.check_interval * 2)
    
    async def fetch_alerts(self) -> List[Dict]:
        """Fetch recent alerts from MCP server"""
        try:
            async with aiohttp.ClientSession() as session:
                request_data = {
                    "method": "get_alerts",
                    "params": {"count": 100}
                }
                
                async with session.post(
                    f"{self.mcp_server_url}/api",
                    json=request_data
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get("alerts", [])
                    
        except aiohttp.ClientError as e:
            logger.error(f"Error fetching alerts: {e}")
        
        return []
    
    async def process_alerts(self, alerts: List[Dict]):
        """Process alerts and determine response"""
        # Group alerts by source IP
        ip_alerts = defaultdict(list)
        
        for alert in alerts:
            src_ip = alert.get("src_ip")
            if src_ip and src_ip not in self.whitelist:
                ip_alerts[src_ip].append(alert)
        
        # Analyze each IP
        for ip, ip_alert_list in ip_alerts.items():
            threat_score = await self.calculate_threat_score(ip, ip_alert_list)
            
            # Update active threats
            self.active_threats[ip] = {
                "score": threat_score,
                "alert_count": len(ip_alert_list),
                "last_seen": datetime.now(),
                "alerts": ip_alert_list
            }
            
            # Determine response
            if threat_score >= self.threat_threshold:
                await self.respond_to_threat(ip, threat_score, ip_alert_list)
    
    async def calculate_threat_score(self, ip: str, alerts: List[Dict]) -> float:
        """Calculate threat score using advanced analysis"""
        score = 0.0
        
        # Basic scoring based on alert count and severity
        severity_weights = {1: 30, 2: 20, 3: 10}
        
        for alert in alerts:
            severity = alert.get("severity", 3)
            score += severity_weights.get(severity, 5)
        
        # Time-based clustering (rapid alerts increase score)
        if len(alerts) > 1:
            timestamps = [datetime.fromisoformat(a["timestamp"]) for a in alerts]
            time_span = (max(timestamps) - min(timestamps)).total_seconds()
            
            if time_span > 0:
                alert_rate = len(alerts) / (time_span / 60)  # Alerts per minute
                if alert_rate > 10:
                    score += 30
                elif alert_rate > 5:
                    score += 20
                elif alert_rate > 2:
                    score += 10
        
        # Attack diversity (multiple attack types = higher threat)
        unique_signatures = len(set(a.get("signature") for a in alerts))
        if unique_signatures > 5:
            score += 25
        elif unique_signatures > 3:
            score += 15
        
        # Port scan detection
        unique_ports = len(set(a.get("dest_port") for a in alerts))
        if unique_ports > 20:
            score += 30
        elif unique_ports > 10:
            score += 20
        
        # Check threat intelligence
        if ip in self.threat_intelligence:
            threat_info = self.threat_intelligence[ip]
            score += threat_info.get("reputation_score", 0)
        
        # Machine learning enhancement (if enabled)
        if self.config.get("ml_enabled") and self.ml_model:
            ml_score = await self.get_ml_prediction(ip, alerts)
            score = (score + ml_score) / 2
        
        return min(score, 100)
    
    async def respond_to_threat(self, ip: str, score: float, alerts: List[Dict]):
        """Execute automated response to threat"""
        logger.warning(f"Threat detected: {ip} (Score: {score})")
        
        response = {
            "ip": ip,
            "score": score,
            "timestamp": datetime.now().isoformat(),
            "actions": []
        }
        
        # Determine response actions based on score
        if score >= 80 and self.config["response_actions"]["block"]:
            # Critical threat - immediate block
            success = await self.block_ip(ip, f"Critical threat score: {score}")
            response["actions"].append("block" if success else "block_failed")
            
            # Isolate if configured
            if self.config["response_actions"]["isolate"]:
                await self.isolate_host(ip)
                response["actions"].append("isolate")
        
        elif score >= 60 and self.config["response_actions"]["rate_limit"]:
            # High threat - rate limit
            success = await self.rate_limit_ip(ip)
            response["actions"].append("rate_limit" if success else "rate_limit_failed")
        
        elif score >= 40:
            # Medium threat - enhanced monitoring
            await self.enhance_monitoring(ip)
            response["actions"].append("monitor")
        
        # Send notifications
        if self.config["response_actions"]["alert"]:
            await self.send_alert(ip, score, alerts)
            response["actions"].append("alert_sent")
        
        # Log response
        self.response_history.append(response)
        await self.log_response(response)
    
    async def block_ip(self, ip: str, reason: str) -> bool:
        """Block IP through MCP server"""
        try:
            async with aiohttp.ClientSession() as session:
                request_data = {
                    "method": "block_ip",
                    "params": {
                        "ip": ip,
                        "reason": reason
                    }
                }
                
                async with session.post(
                    f"{self.mcp_server_url}/api",
                    json=request_data
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get("status") == "success":
                            logger.info(f"Successfully blocked {ip}: {reason}")
                            return True
                    
        except Exception as e:
            logger.error(f"Error blocking IP {ip}: {e}")
        
        # Fallback to local blocking
        return await self.block_ip_local(ip)
    
    async def block_ip_local(self, ip: str) -> bool:
        """Block IP locally using iptables"""
        try:
            cmd = f"sudo iptables -A INPUT -s {ip} -j DROP"
            result = subprocess.run(cmd.split(), capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info(f"Locally blocked {ip}")
                return True
            
        except Exception as e:
            logger.error(f"Error with local block: {e}")
        
        return False
    
    async def rate_limit_ip(self, ip: str) -> bool:
        """Apply rate limiting to IP"""
        try:
            # Create iptables rate limit rule
            cmd = (f"sudo iptables -A INPUT -s {ip} -m limit --limit 10/min "
                  f"--limit-burst 20 -j ACCEPT")
            result = subprocess.run(cmd.split(), capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info(f"Applied rate limiting to {ip}")
                return True
                
        except Exception as e:
            logger.error(f"Error applying rate limit: {e}")
        
        return False
    
    async def isolate_host(self, ip: str):
        """Isolate host from network (advanced feature)"""
        logger.info(f"Isolating host {ip}")
        # This would integrate with network equipment
        # to isolate the host at switch/router level
    
    async def enhance_monitoring(self, ip: str):
        """Enable enhanced monitoring for IP"""
        logger.info(f"Enhanced monitoring enabled for {ip}")
        # This would configure detailed packet capture
        # or enable additional logging for the IP
    
    async def send_alert(self, ip: str, score: float, alerts: List[Dict]):
        """Send alert notifications"""
        alert_message = f"""
🚨 Security Alert 🚨

Threat Detected:
- Source IP: {ip}
- Threat Score: {score}/100
- Alert Count: {len(alerts)}
- Severity: {'CRITICAL' if score >= 80 else 'HIGH' if score >= 60 else 'MEDIUM'}

Top Signatures:
"""
        
        # Add top attack signatures
        signatures = defaultdict(int)
        for alert in alerts:
            signatures[alert.get("signature", "Unknown")] += 1
        
        top_signatures = sorted(signatures.items(), key=lambda x: x[1], reverse=True)[:5]
        for sig, count in top_signatures:
            alert_message += f"- {sig}: {count} occurrences\n"
        
        # Send to configured channels
        await self.send_email_alert(alert_message)
        await self.send_slack_alert(alert_message)
        await self.send_webhook_alert({
            "ip": ip,
            "score": score,
            "alerts": len(alerts),
            "message": alert_message
        })
    
    async def send_email_alert(self, message: str):
        """Send email alert"""
        email = self.config["notification"].get("email")
        if email:
            # Email implementation
            logger.info(f"Email alert sent to {email}")
    
    async def send_slack_alert(self, message: str):
        """Send Slack alert"""
        slack_webhook = self.config["notification"].get("slack")
        if slack_webhook:
            try:
                async with aiohttp.ClientSession() as session:
                    await session.post(slack_webhook, json={"text": message})
                logger.info("Slack alert sent")
            except Exception as e:
                logger.error(f"Error sending Slack alert: {e}")
    
    async def send_webhook_alert(self, data: Dict):
        """Send webhook alert"""
        webhook_url = self.config["notification"].get("webhook")
        if webhook_url:
            try:
                async with aiohttp.ClientSession() as session:
                    await session.post(webhook_url, json=data)
                logger.info("Webhook alert sent")
            except Exception as e:
                logger.error(f"Error sending webhook: {e}")
    
    async def analyze_patterns(self):
        """Continuously analyze attack patterns"""
        while True:
            await asyncio.sleep(300)  # Analyze every 5 minutes
            
            if not self.active_threats:
                continue
            
            # Find persistent threats
            current_time = datetime.now()
            persistent_threats = []
            
            for ip, threat_data in self.active_threats.items():
                last_seen = threat_data.get("last_seen")
                if last_seen and (current_time - last_seen).total_seconds() < 600:
                    if threat_data.get("alert_count", 0) > 20:
                        persistent_threats.append(ip)
            
            # Take action on persistent threats
            for ip in persistent_threats:
                logger.warning(f"Persistent threat from {ip}")
                if self.auto_block:
                    await self.block_ip(ip, "Persistent threat activity")
    
    async def update_threat_intelligence(self):
        """Update threat intelligence feeds"""
        while True:
            await asyncio.sleep(3600)  # Update hourly
            
            for feed_url in self.config.get("threat_feeds", []):
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(feed_url) as response:
                            if response.status == 200:
                                data = await response.json()
                                await self.process_threat_feed(data)
                                
                except Exception as e:
                    logger.error(f"Error updating threat feed {feed_url}: {e}")
    
    async def process_threat_feed(self, feed_data: Dict):
        """Process threat intelligence feed"""
        for entry in feed_data.get("threats", []):
            ip = entry.get("ip")
            if ip:
                self.threat_intelligence[ip] = {
                    "reputation_score": entry.get("score", 50),
                    "category": entry.get("category", "unknown"),
                    "last_updated": datetime.now()
                }
        
        logger.info(f"Updated threat intelligence: {len(self.threat_intelligence)} entries")
    
    async def get_ml_prediction(self, ip: str, alerts: List[Dict]) -> float:
        """Get ML model prediction for threat score"""
        # Placeholder for ML integration
        # In production, this would use a trained model
        return 0.0
    
    async def health_check(self):
        """Periodic health check"""
        while True:
            await asyncio.sleep(60)  # Check every minute
            
            try:
                # Check MCP server connectivity
                async with aiohttp.ClientSession() as session:
                    async with session.get(f"{self.mcp_server_url}/health") as response:
                        if response.status != 200:
                            logger.warning("MCP server health check failed")
                
                # Check system resources
                await self.check_system_resources()
                
                # Clean old data
                await self.cleanup_old_data()
                
            except Exception as e:
                logger.error(f"Health check error: {e}")
    
    async def check_system_resources(self):
        """Check system resource usage"""
        try:
            # Check CPU usage
            cpu_cmd = "top -bn1 | grep 'Cpu(s)' | awk '{print $2}'"
            cpu_result = subprocess.run(cpu_cmd, shell=True, capture_output=True, text=True)
            
            # Check memory usage
            mem_cmd = "free -m | awk 'NR==2{printf \"%.1f\", $3*100/$2}'"
            mem_result = subprocess.run(mem_cmd, shell=True, capture_output=True, text=True)
            
            # Log if resources are high
            cpu_usage = float(cpu_result.stdout.strip().replace('%', ''))
            mem_usage = float(mem_result.stdout.strip())
            
            if cpu_usage > 80:
                logger.warning(f"High CPU usage: {cpu_usage}%")
            
            if mem_usage > 80:
                logger.warning(f"High memory usage: {mem_usage}%")
                
        except Exception as e:
            logger.error(f"Error checking system resources: {e}")
    
    async def cleanup_old_data(self):
        """Clean up old threat data"""
        current_time = datetime.now()
        
        # Clean inactive threats older than 24 hours
        threats_to_remove = []
        for ip, data in self.active_threats.items():
            last_seen = data.get("last_seen")
            if last_seen and (current_time - last_seen).total_seconds() > 86400:
                threats_to_remove.append(ip)
        
        for ip in threats_to_remove:
            del self.active_threats[ip]
        
        if threats_to_remove:
            logger.info(f"Cleaned up {len(threats_to_remove)} old threat entries")
    
    async def log_response(self, response: Dict):
        """Log response action"""
        log_file = Path("agent_responses.log")
        
        try:
            async with aiofiles.open(log_file, 'a') as f:
                await f.write(f"{json.dumps(response)}\n")
        except Exception as e:
            logger.error(f"Error logging response: {e}")
    
    async def automated_response(self):
        """Main automated response loop"""
        logger.info("Automated response system active")
        
        while True:
            await asyncio.sleep(10)  # Quick response cycle
            
            # Check for critical threats requiring immediate action
            for ip, threat_data in self.active_threats.items():
                if threat_data.get("score", 0) >= 90:
                    # Critical threat - immediate response
                    if ip not in self.whitelist and self.auto_block:
                        logger.critical(f"CRITICAL THREAT: Auto-blocking {ip}")
                        await self.block_ip(ip, "Critical threat - automated response")
                        
                        # Remove from active threats after blocking
                        del self.active_threats[ip]
                        break

# Configuration Management
class AgentConfig:
    """Agent configuration manager"""
    
    @staticmethod
    def create_default_config(path: str = "agent_config.yaml"):
        """Create default configuration file"""
        config = {
            "mcp_server": "http://localhost:8080",
            "check_interval": 30,
            "threat_threshold": 50,
            "auto_block": True,
            "whitelist": [
                "127.0.0.1",
                "::1",
                "192.168.1.1"
            ],
            "alert_thresholds": {
                "critical": 1,
                "high": 3,
                "medium": 5,
                "low": 10
            },
            "response_actions": {
                "block": True,
                "rate_limit": True,
                "alert": True,
                "isolate": False
            },
            "ml_enabled": False,
            "threat_feeds": [
                "https://lists.blocklist.de/lists/all.txt",
                "https://reputation.alienvault.com/reputation.data"
            ],
            "notification": {
                "email": "",
                "slack": "",
                "webhook": ""
            },
            "logging": {
                "level": "INFO",
                "file": "agent.log",
                "max_size": "100MB",
                "backup_count": 5
            }
        }
        
        with open(path, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
        
        logger.info(f"Created default config at {path}")
        return config

# Main entry point
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="MCP Security Agent")
    parser.add_argument("--config", default="agent_config.yaml", help="Configuration file path")
    parser.add_argument("--create-config", action="store_true", help="Create default config")
    args = parser.parse_args()
    
    if args.create_config:
        AgentConfig.create_default_config(args.config)
        print(f"Created config file: {args.config}")
    else:
        agent = SecurityAgent(args.config)
        try:
            asyncio.run(agent.start())
        except KeyboardInterrupt:
            logger.info("Agent shutdown requested")
        except Exception as e:
            logger.error(f"Agent error: {e}")