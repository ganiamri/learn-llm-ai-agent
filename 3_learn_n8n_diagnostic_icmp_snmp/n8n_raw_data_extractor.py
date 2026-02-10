import platform
import subprocess
import json

# ==============================================================================
# INSTRUCTIONS FOR N8N
# 1. Copy the code below into an n8n "Code" node (Language: Python).
# 2. Ensure the 'snmpwalk' command is installed and available in the n8n environment.
#    (e.g., install 'snmp' package in the n8n Docker container)
# 3. Adjust the 'target_ip' and 'community' inputs logic at the bottom.
# ==============================================================================

class NetworkCollector:
    """Kelas untuk mengambil data mentah dari perangkat network"""
    
    def __init__(self, target_ip, community_string):
        self.ip = target_ip
        self.community = community_string

    def ping_diagnostic(self):
        """Melakukan Advanced ICMP Ping (Status, Packet Loss, Latency, Jitter)"""
        # Sesuaikan parameter jumlah ping
        count = '4'
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        # Windows tidak support interval float standard, linux bisa -i 0.2 agar cepat
        command = ['ping', param, count, self.ip]
        
        try:
            # Capture output
            output = subprocess.check_output(command, stderr=subprocess.STDOUT).decode('utf-8')
            
            # --- Parsing Logic (Linux format assumed base on environment) ---
            # Linux: "rtt min/avg/max/mdev = 0.048/0.142/0.245/0.100 ms"
            # Windows: "Minimum = 4ms, Maximum = 10ms, Average = 6ms"
            
            # Defaults
            result = {
                "status": "UP", 
                "packet_loss_pct": 0.0,
                "latency_avg_ms": 0.0,
                "latency_min_ms": 0.0,
                "latency_max_ms": 0.0,
                "jitter_ms": 0.0, # mdev/stddev approximation
                "raw_output_snippet": output[-200:] # Debug helper
            }

            # 1. Parse Packet Loss
            # Linux: "0% packet loss"
            loss_index = output.find("% packet loss")
            if loss_index != -1:
                # Mundur cari spasi sebelumnya
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
            # Linux output line: "rtt min/avg/max/mdev = ..."
            if "min/avg/max" in output:
                try:
                    vals_lines = [line for line in output.split("\n") if "min/avg/max" in line]
                    if vals_lines:
                        vals_line = vals_lines[0]
                        # Format: rtt min/avg/max/mdev = 1.1/2.2/3.3/0.4 ms
                        # Split "=" then "/"
                        parts = vals_line.split(" = ")[1].split(" ")[0].split("/")
                        result['latency_min_ms'] = float(parts[0])
                        result['latency_avg_ms'] = float(parts[1])
                        result['latency_max_ms'] = float(parts[2])
                        result['jitter_ms'] = float(parts[3]) # mdev
                except Exception:
                    pass
            
            # Simple Windows fallback
            elif "Average =" in output:
                # Windows parsing simplified (not fully implemented in original, keeping stub)
                pass

            return result

        except subprocess.CalledProcessError:
            return {"status": "DOWN", "packet_loss_pct": 100.0, "error": "Ping command failed (Host Unreachable)"}
        except Exception as e:
            return {"status": "UNKNOWN", "error": f"Ping parsing error: {e}"}

    def snmp_get(self, oid):
        """Helper untuk mengambil single OID via SNMP v2c menggunakan snmpwalk via subprocess"""
        try:
            cmd = [
                "snmpwalk", "-v2c", "-c", self.community, 
                "-O", "qv", self.ip, oid
            ]
            
            result = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
            return result.decode("utf-8").strip()
            
        except subprocess.CalledProcessError:
            return None
        except Exception as e:
            # print(f"[!] Error reading OID {oid}: {e}") # Suppress print in n8n
            return None

    def snmp_walk(self, oid):
        """Helper untuk mengambil bulk OID via SNMP v2c (Walk) untuk tabel"""
        try:
            cmd = [
                "snmpwalk", "-v2c", "-c", self.community, 
                "-O", "qn", # qn: Quick print numeric (OID = Value)
                self.ip, oid
            ]
            
            result = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode("utf-8").strip()
            return result
            
        except subprocess.CalledProcessError:
            return None
        except Exception as e:
            # print(f"[!] Error walking OID {oid}: {e}") # Suppress print in n8n
            return None

    def collect_full_diagnostic(self):
        """Mengumpulkan snapshot data untuk AI"""
        
        # 1. Advanced ICMP Check
        ping_res = self.ping_diagnostic()
        if ping_res['status'] == 'DOWN':
             return {
                 "status": "DOWN", 
                 "ping_diagnostics": ping_res,
                 "error": "Device completely unreachable via ICMP."
             }

        # 2. SNMP Info Collection
        snmp_status = "UP"
        
        # System Info
        sys_descr = self.snmp_get('1.3.6.1.2.1.1.1.0') # sysDescr
        sys_uptime = self.snmp_get('1.3.6.1.2.1.1.3.0') # sysUpTime
        
        # Jika basic SNMP gagal
        if not sys_descr:
             snmp_status = "DOWN"
        
        interfaces_data = [] # List of dicts
        
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
                    
            except Exception as e:
                pass

        data_package = {
            "overall_status": "UP",
            "icmp_metrics": ping_res,
            "snmp_status": snmp_status,
            "device_info": sys_descr or "N/A",
            "uptime_raw": sys_uptime or "N/A",
            "interfaces_count": len(interfaces_data),
            "interfaces_detail": interfaces_data[:10],
            "note": "Showing first 10 interfaces only"
        }
        
        return data_package

# --- EXECUTION BLOCK ---

# 1. Get Inputs (This part depends on how you run it in n8n)
# For testing/demo:
target_ip = "127.0.0.1"
community = "public"

# If using n8n inputs, you might uncomment something like:
# if hasattr(_input, 'all'):
#     item = _input.all()[0].json
#     target_ip = item.get('ip', target_ip)
#     community = item.get('community', community)

# 2. Run Collector
collector = NetworkCollector(target_ip, community)
raw_data = collector.collect_full_diagnostic()

if isinstance(raw_data, dict):
    raw_data['ip'] = target_ip

# 3. Return Data (Valid in n8n Code Node)
return [{'json': raw_data}]
