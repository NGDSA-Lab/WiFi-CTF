from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
import subprocess
import os
import socket
import threading
import secrets, string, random
from datetime import datetime, timezone

app = Flask(__name__)
app.secret_key = 'secret_key'  # !! CHANGE THIS to a secure random value !!
current_ip = socket.gethostbyname(socket.gethostname())

# In-memory user store (Will change in the future for proper persistence and password hashing)
USERS = {
    "admin": "admin"  # Admin account credentials. !! CHANGE THIS to a secure random value !!
}
# Mapping to track a player's container
player_containers = {}

# Container user credentials
CTF_USER = "ctf-user"
CTF_PASSWORD = "ctf"

# Pool files for resource management
POOL_FILE = "/tmp/wifi_pool.txt"
COUNTER_FILE = "/tmp/container_counter.txt"
PORT_POOL_FILE = "/tmp/port_pool.txt"

def init_pool():
    if not os.path.exists(POOL_FILE):
        with open(POOL_FILE, "w") as f:
            for i in range(1, 61):
                f.write(f"{i}\n")

def init_counter():
    if not os.path.exists(COUNTER_FILE):
        with open(COUNTER_FILE, "w") as f:
            f.write("0")

def init_port_pool():
    if not os.path.exists(PORT_POOL_FILE):
        with open(PORT_POOL_FILE, "w") as f:
            for port in range(2220, 2240):
                f.write(f"{port}\n")

init_pool()
init_counter()
init_port_pool()

def read_pool():
    with open(POOL_FILE, "r") as f:
        return [line.strip() for line in f if line.strip()]

def write_pool(pool_list):
    with open(POOL_FILE, "w") as f:
        f.write("\n".join(pool_list) + "\n")

def read_port_pool():
    with open(PORT_POOL_FILE, "r") as f:
        return [line.strip() for line in f if line.strip()]

def write_port_pool(port_list):
    with open(PORT_POOL_FILE, "w") as f:
        f.write("\n".join(port_list) + "\n")

def get_container_counter():
    with open(COUNTER_FILE, "r") as f:
        return int(f.read().strip())

def increment_container_counter():
    count = get_container_counter()
    new_count = count + 1
    with open(COUNTER_FILE, "w") as f:
        f.write(str(new_count))
    return new_count

def decrement_container_counter():
    count = get_container_counter()
    new_count = max(count - 1, 0)
    with open(COUNTER_FILE, "w") as f:
        f.write(str(new_count))
    return new_count

def launch_container():
    pool = read_pool()
    if len(pool) < 3:
        return None, "Not enough available radios in the pool."
    # Use the first three PHY numbers from the pool
    AP_PHY = pool[0]
    CLIENT_PHY = pool[1]
    EXTRA_PHY = pool[2]
    # Remove them from the pool
    remaining = pool[3:]
    write_pool(remaining)
    
    port_pool = read_port_pool()
    if len(port_pool) == 0:
        # Return PHYs back if no port is available
        pool = read_pool()
        pool.extend([AP_PHY, CLIENT_PHY, EXTRA_PHY])
        pool = sorted(list(map(int, pool)))
        write_pool([str(i) for i in pool])
        return None, "No available SSH ports."
    # Choose a random port from the port pool
    host_port = random.choice(port_pool)
    port_pool.remove(host_port)
    write_port_pool(port_pool)
    
    # Generate a container name
    random_letters = ''.join(secrets.choice(string.ascii_uppercase) for _ in range(4))
    container_name = f"NGDSA-WiFi-CTF-{random_letters}"
    
    increment_container_counter()
    
    # Docker run command
    docker_cmd = [
        "docker", "run", "-d", "--privileged", "--name", container_name,
        "-p", f"{host_port}:22",
        "-e", f"AP_PHY={AP_PHY}",
        "-e", f"CLIENT_PHY={CLIENT_PHY}",
        "-e", f"EXTRA_PHY={EXTRA_PHY}",
        "-e", "AP_IF=wlan1",
        "-e", "CLIENT_IF=wlan2",
        "-e", "EXTRA_IF=wlan3",
        "-e", f"AP_SSID={container_name}",
        "ngdsa-wifi-ctf"
    ]
    result = subprocess.run(docker_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        # If the container fails to launch return the PHYs and port back to the pool
        pool = read_pool()
        pool.extend([AP_PHY, CLIENT_PHY, EXTRA_PHY])
        pool = sorted(list(map(int, pool)))
        write_pool([str(i) for i in pool])
        
        port_pool = read_port_pool()
        port_pool.append(host_port)
        port_pool = sorted(list(map(int, port_pool)))
        write_port_pool([str(i) for i in port_pool])
        
        return None, result.stderr
    container_id = result.stdout.strip()
    
    # Wait briefly for the container to start
    subprocess.run(["sleep", "1"])
    
    # Get container's PID
    pid_cmd = ["docker", "inspect", "-f", "{{.State.Pid}}", container_name]
    result = subprocess.run(pid_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return None, "Failed to get container PID."
    container_pid = result.stdout.strip()
    
    # Move the assigned PHYs into the container's network namespace
    for phy in [AP_PHY, CLIENT_PHY, EXTRA_PHY]:
        subprocess.run(["sudo", "iw", "phy", f"phy{phy}", "set", "netns", container_pid])
    
    # Signal the container that the physical radios have been moved
    subprocess.run(["docker", "exec", container_name, "touch", "/tmp/radios_ready"])
    
    # Launch a background thread to wait for container termination and perform cleanup
    def cleanup_thread(name, AP_PHY, CLIENT_PHY, EXTRA_PHY, host_port):
        try:
            subprocess.run(["docker", "wait", name], check=True)
        except subprocess.CalledProcessError:
            pass
        subprocess.run(["sudo", "airmon-ng", "stop", "wlan3mon"], capture_output=True)
        pool = read_pool()
        pool.extend([AP_PHY, CLIENT_PHY, EXTRA_PHY])
        pool = sorted(list(map(int, pool)))
        write_pool([str(i) for i in pool])
        port_pool = read_port_pool()
        port_pool.append(host_port)
        port_pool = sorted(list(map(int, port_pool)))
        write_port_pool([str(i) for i in port_pool])
        decrement_container_counter()
        subprocess.run(["docker", "rm", name], capture_output=True)
    threading.Thread(target=cleanup_thread, args=(container_name, AP_PHY, CLIENT_PHY, EXTRA_PHY, host_port), daemon=True).start()
    
    # Retrieve container start time for uptime calculation
    started_at_cmd = ["docker", "inspect", "-f", "{{.State.StartedAt}}", container_name]
    result = subprocess.run(started_at_cmd, capture_output=True, text=True)
    started_at = result.stdout.strip() if result.returncode == 0 else "Unknown"
    
    return {
        "name": container_name,
        "host_port": host_port,
        "AP_PHY": f"phy{AP_PHY}",
        "CLIENT_PHY": f"phy{CLIENT_PHY}",
        "EXTRA_PHY": f"phy{EXTRA_PHY}",
        "credentials": {"user": CTF_USER, "password": CTF_PASSWORD},
        "ip": current_ip,
        "started_at": started_at
    }, None

def list_containers():
    result = subprocess.run(
        ["docker", "ps", "--filter", "name=NGDSA-WiFi-CTF-", "--format", "{{.Names}}|{{.Ports}}"],
        capture_output=True, text=True
    )
    containers = []
    if result.returncode == 0:
        lines = result.stdout.strip().splitlines()
        for line in lines:
            parts = line.split("|")
            if len(parts) >= 2:
                name = parts[0]
                ports = parts[1]
                inspect_cmd = [
                    "docker", "inspect", "-f",
                    "{{range $env := .Config.Env}}{{$env}};{{end}}", name
                ]
                res = subprocess.run(inspect_cmd, capture_output=True, text=True)
                env_str = res.stdout.strip()
                started_at_cmd = ["docker", "inspect", "-f", "{{.State.StartedAt}}", name]
                res = subprocess.run(started_at_cmd, capture_output=True, text=True)
                uptime = "Unknown"
                if res.returncode == 0:
                    started_at_str = res.stdout.strip()
                    try:
                        started_at_dt = datetime.fromisoformat(started_at_str.replace("Z", "+00:00"))
                        now = datetime.now(timezone.utc)
                        delta = now - started_at_dt
                        hours, remainder = divmod(int(delta.total_seconds()), 3600)
                        minutes, seconds = divmod(remainder, 60)
                        uptime = f"{hours}h {minutes}m {seconds}s"
                    except Exception:
                        uptime = "Unknown"
                containers.append({
                    "name": name,
                    "ports": ports,
                    "env": env_str,
                    "uptime": uptime
                })
    return containers


# Default Route
@app.route("/")
def index():
    if "username" in session:
        # If logged in, check if admin or player
        if session["username"] == "admin":
            return redirect(url_for("admin_panel"))
        else:
            return redirect(url_for("player_panel"))
    else:
        # Not logged in, redirect to login page
        return redirect(url_for("login"))




# Login Route
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if username in USERS and USERS[username] == password:
            session["username"] = username
            session["password"] = password
            flash("Logged in successfully.", "success")
            if username == "admin":
                return redirect(url_for("admin_panel"))
            else:
                return redirect(url_for("player_panel"))
        else:
            flash("Invalid credentials.", "error")
    return render_template("login.html")

# Login Route
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if username in USERS:
            flash("Username already exists.", "error")
        else:
            USERS[username] = password
            session["username"] = username
            session["password"] = password
            flash("Account created successfully.", "success")
            return redirect(url_for("player_panel"))
    return render_template("signup.html")

# Logout Route
@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for("login"))

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        username = session.get("username")
        # Check that the username exists and the session password matches the stored password.
        if not username or username not in USERS or USERS[username] != session.get("password"):
            session.clear()
            flash("Your account credentials have been updated or deleted. Please log in again.", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

# Admin Panel Route. Shows full stats, container management, and player account management
@app.route("/admin")
@login_required
def admin_panel():
    if session.get("username") != "admin":
        flash("Access denied.", "error")
        return redirect(url_for("player_panel"))
    containers = list_containers()
    pool = read_pool()
    port_pool = read_port_pool()
    container_count = get_container_counter()
    # Get all players (all users except admin)
    players = { username: USERS[username] for username in USERS if username != "admin" }
    return render_template("admin.html", containers=containers, pool=pool, port_pool=port_pool,
                           container_count=container_count, players=players)

# Player Panel Route. Allows a player to launch/terminate one container
@app.route("/player")
@login_required
def player_panel():
    username = session.get("username")
    container_info = None
    if username in player_containers:
        container_info = player_containers[username]
    return render_template("player.html", container=container_info)

# Admin Container Launch Route. Allows for multiple containers to be launched
@app.route("/launch", methods=["POST"])
@login_required
def launch():
    if session.get("username") != "admin":
        flash("Access denied.", "error")
        return redirect(url_for("player_panel"))
    container, error = launch_container()
    if error:
        flash(f"Error launching container: {error}", "error")
    else:
        flash(f"Launched container {container['name']} on port {container['host_port']}. "
              f"Assigned PHYs: {container['AP_PHY']}, {container['CLIENT_PHY']}, {container['EXTRA_PHY']}. "
              f"AP SSID: {container['name']}. Credentials: {container['credentials']['user']}/{container['credentials']['password']}, IP: {container['ip']}", "success")
    return redirect(url_for("admin_panel"))

# Players Container Launch Route. Allows for only one container to be launched
@app.route("/player/launch", methods=["POST"])
@login_required
def player_launch():
    username = session.get("username")
    if username in player_containers:
        flash("You already have a container running.", "error")
        return redirect(url_for("player_panel"))
    container, error = launch_container()
    if error:
        flash(f"Error launching container: {error}", "error")
    else:
        player_containers[username] = container
        flash(f"Launched container {container['name']} on port {container['host_port']}. "
              f"Credentials: {container['credentials']['user']}/{container['credentials']['password']}, IP: {container['ip']}", "success")
    return redirect(url_for("player_panel"))

# Admin Container Stop Route. Stops any container by name
@app.route("/stop/<container_name>", methods=["POST"])
@login_required
def stop(container_name):
    if session.get("username") != "admin":
        flash("Access denied.", "error")
        return redirect(url_for("player_panel"))
    
    # Find which player (if any) owns this container and remove it from the dictionary
    for user, cont in list(player_containers.items()):
        if cont["name"] == container_name:
            del player_containers[user]
            break

    # Now actually stop the container
    subprocess.run(["docker", "stop", container_name])
    flash(f"Stopped and removed container {container_name}", "success")
    return redirect(url_for("admin_panel"))

# Player Container Stop Route. Allows players to stop only their own container
@app.route("/player/stop", methods=["POST"])
@login_required
def player_stop():
    username = session.get("username")
    if username not in player_containers:
        flash("You do not have a running container.", "error")
        return redirect(url_for("player_panel"))
    container_name = player_containers[username]["name"]
    subprocess.run(["docker", "stop", container_name])
    flash(f"Stopped and removed container {container_name}", "success")
    player_containers.pop(username, None)
    return redirect(url_for("player_panel"))

# Player Password Update Route (Admin Only)
@app.route("/update_player_password/<username>", methods=["POST"])
@login_required
def update_player_password(username):
    if session.get("username") != "admin":
        flash("Access denied.", "error")
        return redirect(url_for("admin_panel"))
    if username not in USERS or username == "admin":
        flash("Invalid player.", "error")
        return redirect(url_for("admin_panel"))
    new_pass = request.form.get("new_password")
    if not new_pass:
        flash("Password cannot be empty.", "error")
        return redirect(url_for("admin_panel"))
    USERS[username] = new_pass
    flash(f"Password for {username} updated.", "success")
    # If the updated account is the current session, clear it to force re-login.
    if session.get("username") == username:
        session.clear()
    return redirect(url_for("admin_panel"))


# Player Account Deletion Route. Allows players to delete their own account
@app.route("/delete_account", methods=["POST"])
@login_required
def delete_account():
    username = session.get("username")
    if username == "admin":
        flash("Admin account cannot be deleted.", "error")
        return redirect(url_for("admin_panel"))
    # If the user has a running container, terminate it.
    if username in player_containers:
        container_name = player_containers[username]["name"]
        subprocess.run(["docker", "stop", container_name])
        player_containers.pop(username, None)
    USERS.pop(username, None)
    flash("Your account has been deleted.", "success")
    session.clear()
    return redirect(url_for("signup"))

# Admin Account Deletion Routes. Allows admin to delete any player account
@app.route("/admin/delete_account/<username>", methods=["POST"])
@login_required
def admin_delete_account(username):
    if session.get("username") != "admin":
        flash("Access denied.", "error")
        return redirect(url_for("admin_panel"))
    if username not in USERS or username == "admin":
        flash("Invalid player account.", "error")
        return redirect(url_for("admin_panel"))
    if username in player_containers:
        container_name = player_containers[username]["name"]
        subprocess.run(["docker", "stop", container_name])
        player_containers.pop(username, None)
    USERS.pop(username, None)
    flash(f"Account {username} deleted successfully.", "success")
    return redirect(url_for("admin_panel"))


# Real-Time Status Endpoint for Admin Panel
@app.route("/admin_status", methods=["GET"])
@login_required
def admin_status():
    if session.get("username") != "admin":
        return jsonify(error="Access denied."), 403
    players = { username: USERS[username] for username in USERS if username != "admin" }
    data = {
         "containers": list_containers(),
         "pool": read_pool(),
         "port_pool": read_port_pool(),
         "container_count": get_container_counter(),
         "players": players
    }
    return jsonify(data)

# Real-Time Status Endpoint for players
@app.route("/status", methods=["GET"])
def status():
    # For player panel updates (only container info)
    containers = list_containers()
    return jsonify(containers=containers)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
