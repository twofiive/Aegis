import requests
import pandas as pd
import time
from datetime import datetime

# --- CONFIGURATION ---
URL = "http://localhost:9090/api/v1/query_range"
OUTPUT_FILE = "node_metrics_advanced.csv"

# Requêtes adaptées de tes dashboards (Généralisées pour tous les nœuds)
QUERIES = {
    "cpu_usage_ratio": '(1 - sum without (mode) (rate(node_cpu_seconds_total{mode=~"idle|iowait|steal"}[5m]))) / ignoring(cpu) group_left count without (cpu, mode) (node_cpu_seconds_total{mode="idle"})',
    "ram_usage_bytes": 'node_memory_MemTotal_bytes - node_memory_MemFree_bytes - node_memory_Buffers_bytes - node_memory_Cached_bytes',
    "disk_read_bytes": 'sum(rate(node_disk_read_bytes_total{device=~"sd.*|vd.*|nvme.*"}[5m])) by (instance)',
    "disk_write_bytes": 'sum(rate(node_disk_written_bytes_total{device=~"sd.*|vd.*|nvme.*"}[5m])) by (instance)',
    "net_in_bits": 'sum(rate(node_network_receive_bytes_total{device!="lo"}[5m])) by (instance) * 8',
    "net_out_bits": 'sum(rate(node_network_transmit_bytes_total{device!="lo"}[5m])) by (instance) * 8'
}

now = int(time.time())
start = now - (7 * 24 * 3600)  # 7 jours de données historiques
all_data = []

# --- EXTRACTION ---
for name, query in QUERIES.items():
    print(f"🛰️  Extraction de : {name}...")
    try:
        # On utilise un pas (step) de 1m pour la précision
        res = requests.get(URL, params={'query': query, 'start': start, 'end': now, 'step': '1m'}).json()
        results = res.get('data', {}).get('result', [])
        
        for r in results:
            # Nettoyage de l'instance pour avoir le hostname/IP propre
            node = r['metric'].get('instance', 'unknown').split(':')[0]
            for val in r['values']:
                all_data.append({
                    'timestamp': datetime.fromtimestamp(int(val[0])).replace(second=0),
                    'node': node,
                    name: float(val[1])
                })
    except Exception as e:
        print(f"❌ Erreur sur {name}: {e}")

# --- FUSION ET NETTOYAGE ---
if all_data:
    # On groupe tout par temps et par node
    df = pd.DataFrame(all_data).groupby(['timestamp', 'node']).first().reset_index()
    df = df.fillna(0)
    
    df.to_csv(OUTPUT_FILE, index=False)
    print(f"\n✅ Dataset métriques généré : {OUTPUT_FILE} ({len(df)} lignes)")
    print(f"Nodes trouvés : {df['node'].unique()}")
else:
    print("⚠️ Aucune donnée collectée.")