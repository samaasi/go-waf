# Beginner's Quickstart Guide (Step-by-Step)

Welcome! This guide is for you if you are new to servers and want to get Go-WAF running in less than 5 minutes.

## Prerequisites (What you need to install first)
Before we start, make sure you have these two tools installed on your computer or server:
1.  **Docker Desktop** (The easiest way to run applications). [Download here](https://www.docker.com/products/docker-desktop/)
2.  **Go** (Only if you want to run without Docker). [Download here](https://go.dev/dl/)

---

## Step 1: Get the Application
Download the files to your computer. If you know how to use "Git", run this in your terminal:
```bash
git clone https://github.com/samaasi/go-waf.git
cd go-waf
```
*(If you don't know Git, just download the ZIP file from GitHub and extract it).*

---

## Step 2: Start the WAF (The Easy Way)
We use a tool called **Docker Compose** that starts the WAF, the database (Redis), and the Dashboard all at once.

1.  Open your terminal (Command Prompt or PowerShell on Windows).
2.  Navigate to the `go-waf` folder.
3.  Run this command:
```bash
docker-compose up -d
```
4.  Wait about 1 minute for everything to download and start.

### "I already have my own Redis!"
If you already have a Redis database running on your server, you can tell the WAF to use it by editing the `docker-compose.yml` file. 

Look for the `WAF_REDIS_ADDR` line and change it like this:
```yaml
# Before (using the built-in one):
- WAF_REDIS_ADDR=redis:6379

# After (using your own):
- WAF_REDIS_ADDR=192.168.1.50:6379
```

---

### Option B: Running with just Docker (No Compose)
If you don't want to use Compose, you can run the WAF directly with this command:
```bash
docker run -d -p 9090:9090 -p 9091:9091 --name go-waf samaasi/go-waf
```

---

## Step 3: Connect to your existing Nginx
If you are already using Nginx to show your website, you can tell Nginx to "talk" to the WAF first.

1. Open your Nginx configuration file (usually in `/etc/nginx/sites-enabled/default`).
2. Add these lines inside your `location /` block:
```nginx
location / {
    # Tell Nginx to send everything to the WAF
    proxy_pass http://localhost:9090;
    
    # Standard Nginx settings
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}
```
3. Restart Nginx: `sudo systemctl restart nginx`.

---

## Step 4: See it in Action!
Now that the WAF is running, you can access your security command center:

1.  Open your web browser.
2.  Go to: `http://localhost:9091/admin/dashboard`
3.  You should see the **Go-WAF Security Operations** dashboard!

---

## Step 4: Test the Security (The "Attack" Test)
Let's see if the WAF is actually protecting you. We will send a "fake" attack that looks like someone trying to steal data (SQL Injection).

1.  Open your terminal.
2.  Run this command:
```bash
curl "http://localhost:9090/?id=1' OR '1'='1"
```
3.  **What happened?** You should see a message saying the request was blocked.
4.  **Check the Dashboard**: Refresh your dashboard at `http://localhost:9091/admin/dashboard`. You will see 1 "Blocked Request" on the graph!

---

## Troubleshooting (Common Fixes)

### "Port 9090 is already in use"
This means another program is using the same "door" as the WAF. 
- **Fix**: Close other web servers or change the port in the `docker-compose.yml` file.

### "Cannot connect to Docker"
- **Fix**: Make sure Docker Desktop is open and running (check the little whale icon in your taskbar).

### "I don't see any data on the dashboard"
- **Fix**: Make sure you have sent at least one request to `http://localhost:9090`. The WAF only shows data when it sees traffic.
