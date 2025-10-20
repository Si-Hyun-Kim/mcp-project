# INSTALLATION & SETUP GUIDE

1. SYSTEM REQUIREMENTS:
   - Ubuntu 20.04+ or similar Linux
   - Node.js 18+
   - Python 3.8+
   - Suricata IDS installed
   - sudo privileges

2. INSTALL DEPENDENCIES:

   - System packages
   ```bash
   sudo apt update
   sudo apt install -y nodejs npm python3 python3-pip suricata
   ```

   - Python packages
   ```bash
   pip3 install aiohttp aiofiles pyyaml
   ```

   - Node.js packages (create package.json first)
   ```bash
   npm install express cors body-parser axios ws jsonwebtoken speakeasy qrcode
   ```

3. CREATE package.json:
```json
{
  "name": "security-dashboard",
  "version": "1.0.0",
  "description": "Advanced Security Operations Center Dashboard",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js",
    "mcp-server": "python3 mcp_server.py",
    "mcp-agent": "python3 mcp_agent.py",
    "all": "concurrently \"npm run mcp-server\" \"npm run mcp-agent\" \"npm start\""
  },
  "dependencies": {
    "express": "^4.18.2",
    "cors": "^2.8.5",
    "body-parser": "^1.20.2",
    "axios": "^1.6.0",
    "ws": "^8.14.0",
    "jsonwebtoken": "^9.0.2",
    "speakeasy": "^2.0.0",
    "qrcode": "^1.5.3"
  },
  "devDependencies": {
    "nodemon": "^3.0.1",
    "concurrently": "^8.2.0"
  }
}
```


4. FILE STRUCTURE:
   
   security-dashboard/
   ├── server.js           (this file)
   ├── mcp_server.py       (MCP Server)
   ├── mcp_agent.py        (MCP Agent)
   ├── agent_config.yaml   (Agent config)
   ├── package.json        (Node dependencies)
   ├── public/
   │   └── index.html      (Dashboard HTML)
   └── logs/
       └── (auto-generated)

5. SETUP STEPS:

   - Create project directory
   ```bash
   mkdir -p ~/security-dashboard
   cd ~/security-dashboard
   ```
   
   - Copy all files to directory
   - Create public folder
   ```bash
   mkdir -p public logs
   ```
   
   - Copy HTML dashboard to public/index.html
   ```bash
   cp dashboard.html public/index.html
   ```
   
   - Install Node dependencies
   ```bash
   npm install
   ```
   
   - Create Suricata rules directory
   ```bash
   sudo mkdir -p /etc/suricata/rules
   sudo touch /etc/suricata/rules/custom.rules
   sudo chmod 666 /etc/suricata/rules/custom.rules
   ```

   - Create log directories
   ```bash
   sudo mkdir -p /var/log/suricata /var/log/hexstrike
   sudo chmod 755 /var/log/suricata /var/log/hexstrike
   ```

6. CONFIGURE SURICATA:
   
   - Edit Suricata config
   ```bash
   sudo nano /etc/suricata/suricata.yaml
   ```
   
   - Add custom rules file:
   rule-files:
     - custom.rules
   
   - Enable EVE JSON output
   outputs:
     - eve-log:
         enabled: yes
         filetype: regular
         filename: eve.json

7. START SERVICES:

   - Terminal 1 - MCP Server
   ```bash
   python3 mcp_server.py
   ```
   
   - Terminal 2 - MCP Agent
   ```bash
   python3 mcp_agent.py --create-config
   python3 mcp_agent.py
   ```
   
   - Terminal 3 - Express Server
   ```bash
   npm start
   ```

   - Or use concurrently to run all:
   ```bash
   npm run all
   ```

8. ACCESS DASHBOARD:
   
   Open browser: http://localhost:3000
   
   Login:
   - Username: admin
   - Password: admin  
   - MFA: 123456

9. TEST THE SYSTEM:

   - Generate test traffic
   ```bash
   curl http://testmynids.org/uid/index.html
   ```
   
   - Simulate port scan
   ```bash
   nmap -sS localhost
   ```
   
   - Check logs
   ```bash
   tail -f /var/log/suricata/eve.json
   ```

10. PRODUCTION DEPLOYMENT:

    - Use PM2 for process management
    ```bash
    npm install -g pm2
    ```

    - Create ecosystem file
    ```bash
    pm2 init
    ```
    
    - Start services
    ```bash
    pm2 start ecosystem.config.js
    ```

    - Setup as systemd service
    ```bash
    pm2 startup
    pm2 save
    ```

    - Configure firewall
    ```bash
    sudo ufw allow 3000/tcp
    sudo ufw allow 3001/tcp
    ```

    - Use reverse proxy (nginx)
    ```bash
    sudo apt install nginx
    ```
    - Configure SSL with Let's Encrypt

11. TROUBLESHOOTING:

    - Check service status
    ```bash
    systemctl status suricata
    ```

    - View logs
    ```bash
    journalctl -u suricata -f
    tail -f logs/*.log
    ```

    - Test MCP connectivity
    ```bash
    curl http://localhost:8080/health
    ```

    - Reset iptables if needed
    ```bash
    sudo iptables -F
    ```

    - Check port usage
    ```bash
    netstat -tulpn | grep -E '3000|3001|8080'
    ```

12. SECURITY HARDENING:

    - Change default passwords
    - Enable HTTPS only
    - Configure proper MFA
    - Restrict IP access
    - Enable audit logging
    - Regular updates
    - Backup configuration
