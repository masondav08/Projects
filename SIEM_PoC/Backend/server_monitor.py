import paramiko

def get_server_metrics(hostname, username, password):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname, username=username, password=password, timeout=5)

        # CPU usage
        stdin, stdout, _ = ssh.exec_command("top -bn1 | grep 'Cpu(s)'")
        cpu_line = stdout.read().decode()
        cpu_idle = float(cpu_line.split(",")[3].strip().split()[0])
        cpu_usage = round(100 - cpu_idle, 2)

        # Memory usage
        stdin, stdout, _ = ssh.exec_command("free -m")
        mem_line = stdout.read().decode().split('\n')[1].split()
        total_mem = int(mem_line[1])
        used_mem = int(mem_line[2])
        mem_usage = round((used_mem / total_mem) * 100, 2)

        # Uptime
        stdin, stdout, _ = ssh.exec_command("uptime -p")
        uptime = stdout.read().decode().strip()

        ssh.close()

        status = "healthy"
        if cpu_usage > 80 or mem_usage > 80:
            status = "warning"

        return {
            "status": status,
            "cpu": cpu_usage,
            "memory": mem_usage,
            "uptime": uptime
        }

    except Exception as e:
        return {
            "status": "down",
            "cpu": 0,
            "memory": 0,
            "uptime": "Unavailable",
            "error": str(e)
        }
