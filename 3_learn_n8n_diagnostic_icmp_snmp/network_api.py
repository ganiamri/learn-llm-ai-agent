import platform
import subprocess
import json
from functools import wraps
from flask import Flask, request, jsonify, Response

app = Flask(__name__)

# --- CONFIGURATION ---
# Default credentials for Basic Auth
USERNAME = "admin"
PASSWORD = "password"

# --- HELPER CLASSES ---

class NetworkCollector:
    """Class to extract raw data from network devices (ICMP/SNMP)"""
    
    def __init__(self, target_ip, community_string="public"):
        self.ip = target_ip
        self.community = community_string

    def ping_diagnostic(self):
        """Advanced ICMP Ping (Status, Packet Loss, Latency, Jitter)"""
        count = '4'
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        # On Linux, we might want to add -i 0.2 for speed if needed, but sticking to standard for now
        command = ['ping', param, count, self.ip]
        
        try:
            output = subprocess.check_output(command, stderr=subprocess.STDOUT).decode('utf-8')
            
            result = {
                "status": "UP", 
                "packet_loss_pct": 0.0,
                "latency_avg_ms": 0.0,
                "latency_min_ms": 0.0,
                "latency_max_ms": 0.0,
                "jitter_ms": 0.0, # mdev approximation
            }

            # 1. Parse Packet Loss
            loss_index = output.find("% packet loss")
            if loss_index != -1:
                start_loss = output.rfind(" ", 0, loss_index)
                loss_str = output[start_loss+1:loss_index]
                try:
                    result['packet_loss_pct'] = float(loss_str)
                except ValueError:
                    pass

            if result['packet_loss_pct'] == 100.0:
                result['status'] = "DOWN"
                return result

            # 2. Parse Latency & Jitter (mdev on Linux)
            # Linux: "rtt min/avg/max/mdev = 0.048/0.142/0.245/0.100 ms"
            if "min/avg/max" in output:
                try:
                    vals_lines = [line for line in output.split("\n") if "min/avg/max" in line]
                    if vals_lines:
                        vals_line = vals_lines[0]
                        parts = vals_line.split(" = ")[1].split(" ")[0].split("/")
                        result['latency_min_ms'] = float(parts[0])
                        result['latency_avg_ms'] = float(parts[1])
                        result['latency_max_ms'] = float(parts[2])
                        result['jitter_ms'] = float(parts[3]) # mdev
                except Exception:
                    pass
            
            # Simple Windows fallback
            elif "Average =" in output:
                # Basic parsing for Windows if needed
                pass

            return result

        except subprocess.CalledProcessError:
            return {"status": "DOWN", "packet_loss_pct": 100.0, "error": "Ping command failed"}
        except Exception as e:
            return {"status": "UNKNOWN", "error": f"Ping error: {e}"}

    def snmp_get(self, oid):
        """Get single OID via SNMP v2c"""
        try:
            cmd = [
                "snmpwalk", "-v2c", "-c", self.community, 
                "-O", "qv", self.ip, oid
            ]
            result = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
            return result.decode("utf-8").strip()
        except subprocess.CalledProcessError:
            return None
        except Exception:
            return None

    def snmp_walk(self, oid):
        """Walk OID via SNMP v2c"""
        try:
            cmd = [
                "snmpwalk", "-v2c", "-c", self.community, 
                "-O", "qn", # qn: Quick print numeric
                self.ip, oid
            ]
            result = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode("utf-8").strip()
            return result
        except subprocess.CalledProcessError:
            return None
        except Exception:
            return None

    def collect_snmp_data(self):
        """Collect SNMP System Info and Interface Stats"""
        snmp_status = "UP"
        
        # System Info
        sys_descr = self.snmp_get('1.3.6.1.2.1.1.1.0') # sysDescr
        sys_uptime = self.snmp_get('1.3.6.1.2.1.1.3.0') # sysUpTime
        
        if not sys_descr:
             snmp_status = "DOWN"
             return {"snmp_status": "DOWN", "error": "No SNMP response"}
        
        interfaces_data = []
        
        if snmp_status == "UP":
            try:
                raw_descr = self.snmp_walk('1.3.6.1.2.1.2.2.1.2') or ""
                raw_admin = self.snmp_walk('1.3.6.1.2.1.2.2.1.7') or ""
                raw_oper  = self.snmp_walk('1.3.6.1.2.1.2.2.1.8') or ""
                
                def parse_walk_to_dict(raw_text):
                    data = {}
                    for line in raw_text.splitlines():
                        if not line: continue
                        parts = line.split(" = ")
                        if len(parts) >= 2:
                            oid_part = parts[0]
                            val_part = parts[1].strip()
                            idx = oid_part.split(".")[-1]
                            data[idx] = val_part
                    return data

                d_descr = parse_walk_to_dict(raw_descr)
                d_admin = parse_walk_to_dict(raw_admin)
                d_oper  = parse_walk_to_dict(raw_oper)
                
                for idx, name in d_descr.items():
                    a_stat = d_admin.get(idx, "0")
                    o_stat = d_oper.get(idx, "0")
                    status_map = {'1': 'UP', '2': 'DOWN', '3': 'TESTING'}
                    
                    interfaces_data.append({
                        "id": idx,
                        "name": name.strip('"'),
                        "admin_status": status_map.get(a_stat, f"Unknown({a_stat})"),
                        "oper_status": status_map.get(o_stat, f"Unknown({o_stat})")
                    })
            except Exception:
                pass

        return {
            "snmp_status": snmp_status,
            "device_info": sys_descr or "N/A",
            "uptime_raw": sys_uptime or "N/A",
            "interfaces_count": len(interfaces_data),
            "interfaces_detail": interfaces_data
        }

# --- BASIC AUTH UTILS ---

def check_auth(username, password):
    """Check if a username/password combination is valid."""
    return username == USERNAME and password == PASSWORD

def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
    'Could not verify your access level for that URL.\n'
    'You have to login with proper credentials', 401,
    {'WWW-Authenticate': 'Basic realm="Login Required"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

# --- ENDPOINTS ---

@app.route('/icmp/status', methods=['POST'])
@requires_auth
def get_icmp_status():
    data = request.get_json()
    target_ip = data.get('ip')
    if not target_ip:
        return jsonify({"error": "IP address required"}), 400

    collector = NetworkCollector(target_ip)
    # We use ping_diagnostic but only return status for this endpoint
    result = collector.ping_diagnostic()
    
    return jsonify({
        "ip": target_ip,
        "status": result.get("status", "UNKNOWN")
    })

@app.route('/icmp/qos', methods=['POST'])
@requires_auth
def get_icmp_qos():
    data = request.get_json()
    target_ip = data.get('ip')
    if not target_ip:
        return jsonify({"error": "IP address required"}), 400

    collector = NetworkCollector(target_ip)
    result = collector.ping_diagnostic()
    
    # Enrich with requested QoS fields
    response = {
        "ip": target_ip,
        "packet_loss_pct": result.get("packet_loss_pct"),
        "latency_avg_ms": result.get("latency_avg_ms"),
        "latency_min_ms": result.get("latency_min_ms"),
        "latency_max_ms": result.get("latency_max_ms"),
        "jitter_ms": result.get("jitter_ms"),
        "status": result.get("status")
    }
    return jsonify(response)

@app.route('/snmp/data', methods=['POST'])
@requires_auth
def get_snmp_data():
    data = request.get_json()
    target_ip = data.get('ip')
    community = data.get('community', 'public')
    
    if not target_ip:
        return jsonify({"error": "IP address required"}), 400

    collector = NetworkCollector(target_ip, community)
    result = collector.collect_snmp_data()
    
    result['ip'] = target_ip
    return jsonify(result)

if __name__ == '__main__':
    # Running on 0.0.0.0 to be accessible from outside if needed (e.g. Docker container)
    app.run(host='0.0.0.0', port=5000, debug=True)
