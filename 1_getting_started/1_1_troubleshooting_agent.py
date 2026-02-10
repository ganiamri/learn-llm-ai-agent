import platform
import subprocess
import json

from openai import OpenAI

# --- KONFIGURASI AI LOKAL ---
# Sesuaikan base_url dengan setup AI lokal Anda (contoh: Ollama default port 11434, atau LM Studio 1234)
AI_CLIENT = OpenAI(
    base_url="http://localhost:11434/v1", 
    api_key="local-ai" # API Key biasanya dummy untuk local AI
)
AI_MODEL_NAME = "gemma3:4b" # Sesuaikan dengan nama model yang Anda load (misal: mistral, llama3, qwen)

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
                result['packet_loss_pct'] = float(loss_str)

            if result['packet_loss_pct'] == 100.0:
                result['status'] = "DOWN"
                return result

            # 2. Parse Latency & Jitter (mdev on Linux)
            # Linux output line: "rtt min/avg/max/mdev = ..."
            if "min/avg/max" in output:
                vals_line = [line for line in output.split("\n") if "min/avg/max" in line][0]
                # Format: rtt min/avg/max/mdev = 1.1/2.2/3.3/0.4 ms
                # Split "=" then "/"
                parts = vals_line.split(" = ")[1].split(" ")[0].split("/")
                result['latency_min_ms'] = float(parts[0])
                result['latency_avg_ms'] = float(parts[1])
                result['latency_max_ms'] = float(parts[2])
                result['jitter_ms'] = float(parts[3]) # mdev
            
            # Simple Windows fallback (not strictly asked but good practice)
            elif "Average =" in output:
                # Windows parsing simplified
                pass

            return result

        except subprocess.CalledProcessError:
            return {"status": "DOWN", "packet_loss_pct": 100.0, "error": "Ping command failed (Host Unreachable)"}
        except Exception as e:
            return {"status": "UNKNOWN", "error": f"Ping parsing error: {e}"}

    def snmp_get(self, oid):
        """Helper untuk mengambil single OID via SNMP v2c menggunakan snmpwalk via subprocess"""
        try:
            # Menggunakan snmpwalk via command line system (lebih robust dibanding pysnmp di python 3.12+)
            # Command: snmpwalk -v2c -c <community> -O qv <ip> <oid>
            # -O qv: Output value only (clean output)
            cmd = [
                "snmpwalk", "-v2c", "-c", self.community, 
                "-O", "qv", self.ip, oid
            ]
            
            result = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
            return result.decode("utf-8").strip()
            
        except subprocess.CalledProcessError:
            return None
        except Exception as e:
            print(f"[!] Error reading OID {oid}: {e}")
    def snmp_walk(self, oid):
        """Helper untuk mengambil bulk OID via SNMP v2c (Walk) untuk tabel"""
        try:
            # Command: snmpwalk -v2c -c <community> -O q <ip> <oid>
            # -O q: Quick print for easier parsing (value only usually, but for table we need index)
            # Kita pakai default output untuk parsing index oid
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
            print(f"[!] Error walking OID {oid}: {e}")
            return None

    def collect_full_diagnostic(self):
        """Mengumpulkan snapshot data untuk AI"""
        print(f"\n[🔄] Mengumpulkan data dari {self.ip}...")
        
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
             # Masih bisa return data ping
        
        # Interface Table Collection (IfAdminStatus, IfOperStatus, IfDescr)
        # OIDs:
        # ifDescr: .1.3.6.1.2.1.2.2.1.2
        # ifAdminStatus: .1.3.6.1.2.1.2.2.1.7 (1=up, 2=down)
        # ifOperStatus: .1.3.6.1.2.1.2.2.1.8 (1=up, 2=down)
        
        interfaces_data = [] # List of dicts
        
        if snmp_status == "UP":
            print("   [+] SNMP Contacted. Fetching interfaces...")
            try:
                # Kita ambil raw walk text dan parse manual sederhana
                # Note: Ini cara 'naive' tanpa library PySNMP/EasySNMP untuk portabilitas
                raw_descr = self.snmp_walk('1.3.6.1.2.1.2.2.1.2') or ""
                raw_admin = self.snmp_walk('1.3.6.1.2.1.2.2.1.7') or ""
                raw_oper  = self.snmp_walk('1.3.6.1.2.1.2.2.1.8') or ""
                
                # Parsing logic helper
                def parse_walk_to_dict(raw_text):
                    data = {}
                    for line in raw_text.splitlines():
                        if not line: continue
                        # Format: .1.3.6...1.2.X = ...
                        parts = line.split(" = ")
                        if len(parts) >= 2:
                            oid_part = parts[0]
                            val_part = parts[1].strip()
                            # Ambil index terakhir dari OID
                            idx = oid_part.split(".")[-1]
                            data[idx] = val_part
                    return data

                d_descr = parse_walk_to_dict(raw_descr)
                d_admin = parse_walk_to_dict(raw_admin)
                d_oper  = parse_walk_to_dict(raw_oper)
                
                # Gabungkan per index
                for idx, name in d_descr.items():
                    # Parse status from numeric (ex: 1)
                    a_stat = d_admin.get(idx, "0")
                    o_stat = d_oper.get(idx, "0")
                    
                    # Mapping status code
                    status_map = {'1': 'UP', '2': 'DOWN', '3': 'TESTING'}
                    
                    interfaces_data.append({
                        "id": idx,
                        "name": name.strip('"'), # Remove quotes if string
                        "admin_status": status_map.get(a_stat, f"Unknown({a_stat})"),
                        "oper_status": status_map.get(o_stat, f"Unknown({o_stat})")
                    })
                    
            except Exception as e:
                print(f"Error processing interfaces: {e}")

        data_package = {
            "overall_status": "UP", # Pingable
            "icmp_metrics": ping_res,
            "snmp_status": snmp_status,
            "device_info": sys_descr or "N/A",
            "uptime_raw": sys_uptime or "N/A",
            "interfaces_count": len(interfaces_data),
            "interfaces_detail": interfaces_data[:10], # Limit output agar tidak flood context
            "note": "Showing first 10 interfaces only"
        }
        
        return data_package

class TroubleshootAgent:
    """AI Agent yang menganalisa data"""
    
    def analyze(self, data_context):
        if "error" in data_context:
            return f"❌ **CRITICAL FAILURE**: {data_context['error']}\nSaran: Cek kelistrikan fisik atau jalur kabel utama."

        # Prompt Engineering: Meminta AI bertindak sebagai Network Expert
        system_prompt = """
        You are a Senior Network Support Engineer acting as an automated troubleshooting agent.
        Your goal is to analyze the provided raw network data (ICMP metrics, SNMP Interface Status) and provide a concise, actionable summary.
        
        Data Interpretation Guide:
        - Packet Loss > 0% is BAD.
        - High Jitter (> 20ms) suggests congestion or bad cabling.
        - SNMP Status DOWN with Ping UP implies SNMP configuration issue (community string/ACL).
        - Interface Admin UP / Oper DOWN implies physical layer issue (cable unplugged).
        
        Rules:
        1. Start with a "Health Verdict" (Healthy/Warning/Critical).
        2. Analyze ICMP Quality (Latency/Jitter/Loss).
        3. Analyze Interface Table (Identify ports with issues).
        4. Suggest 2-3 specific next steps (CLI commands, Physical checks).
        """

        user_message = f"""
        Please analyze this diagnostic data for IP {data_context.get('ip', 'target')}:
        {json.dumps(data_context, indent=2)}
        """

        print("[🤖] AI sedang menganalisa data...")
        
        try:
            completion = AI_CLIENT.chat.completions.create(
                model=AI_MODEL_NAME,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message}
                ],
                temperature=0.3, # Rendah agar analisis faktual & konsisten
            )
            return completion.choices[0].message.content
        except Exception as e:
            return f"Error menghubungkan ke Local AI: {e}"

# --- MAIN PROGRAM ---
if __name__ == "__main__":
    print("=== NMS AI Troubleshoot Assistant (Local) ===")
    target_ip = input("Masukkan IP Target: ")
    community = input("Masukkan SNMP Community (default: public): ") or "public"

    # 1. Collect Data
    collector = NetworkCollector(target_ip, community)
    raw_data = collector.collect_full_diagnostic()
    
    # Tambahkan IP ke context
    if isinstance(raw_data, dict):
        raw_data['ip'] = target_ip

    # 2. Analyze with AI
    agent = TroubleshootAgent()
    analysis = agent.analyze(raw_data)

    print("\n" + "="*40)
    print("📄 LAPORAN ANALISIS AI")
    print("="*40)
    print(analysis)
    print("="*40)