import requests
import time
import pandas as pd


class PrometheusLiveClient:
    def __init__(self, url="http://prometheus.aegis.local:32090"):
        self.api_url = f"{url}/api/v1/query_range"

        # Tes requêtes optimisées pour une lecture instantanée (fenêtre de 1 minute)
        self.queries = {
            "cpu_usage_ratio": '(1 - sum without (mode) (rate(node_cpu_seconds_total{mode=~"idle|iowait|steal"}[1m]))) / ignoring(cpu) group_left count without (cpu, mode) (node_cpu_seconds_total{mode="idle"})',
            "ram_usage_bytes": "node_memory_MemTotal_bytes - node_memory_MemFree_bytes - node_memory_Buffers_bytes - node_memory_Cached_bytes",
            "disk_read_bytes": 'sum(rate(node_disk_read_bytes_total{device=~"sd.*|vd.*|nvme.*"}[1m])) by (instance)',
            "disk_write_bytes": 'sum(rate(node_disk_written_bytes_total{device=~"sd.*|vd.*|nvme.*"}[1m])) by (instance)',
            "net_in_bits": 'sum(rate(node_network_receive_bytes_total{device!="lo"}[1m])) by (instance) * 8',
            "net_out_bits": 'sum(rate(node_network_transmit_bytes_total{device!="lo"}[1m])) by (instance) * 8',
        }

        # Colonne prometheus dans l'ordre
        self.prom_cols = [
            "cpu_usage_ratio",
            "ram_usage_bytes",
            "disk_read_bytes",
            "disk_write_bytes",
            "net_in_bits",
            "net_out_bits",
        ]

    def get_node_metrics(self, node_name):
        """
        Interroge Prometheus sur les 5 dernières minutes et renvoie
        un dictionnaire avec la valeur la plus récente.
        """
        metrics_dict = {k: 0.0 for k in self.queries.keys()}

        if not node_name or node_name == "unknown":
            return pd.DataFrame([metrics_dict], columns=self.prom_cols)

        # On inverse ton dictionnaire du notebook pour trouver l'IP depuis le nom
        node_to_ip = {
            "aegis-control-plane": "10.200.0.2",
            "aegis-worker-spot": "10.200.0.4",
        }
        # La cible qu'on va chercher dans Prometheus (l'IP si connue, sinon le nom)
        search_target = node_to_ip.get(node_name, node_name)

        print(
            f"🔍 [Prometheus] Recherche des métriques pour le nœud : {node_name}"
        )

        # On définit la fenêtre de temps (Les 5 dernières minutes)
        now = int(time.time())
        start = now - 300

        for name, query in self.queries.items():
            try:
                # Appel API avec start, end et step (exactement comme ton extracteur)
                response = requests.get(
                    self.api_url,
                    params={
                        "query": query,
                        "start": start,
                        "end": now,
                        "step": "1m",
                    },
                    timeout=3,
                )
                response.raise_for_status()
                data = response.json()

                results = data.get("data", {}).get("result", [])

                found = False
                for r in results:
                    instance_name = r["metric"].get("instance", "")
                    # Si le nom du nœud correspond (ex: aegis-worker-spot)
                    if search_target in instance_name:
                        # query_range renvoie une liste "values": [[timestamp, "valeur"], [timestamp, "valeur"]]
                        # On prend le TOUT DERNIER élément [-1] et sa valeur [1]
                        valeurs_historiques = r.get("values", [])
                        if valeurs_historiques:
                            derniere_valeur_brute = valeurs_historiques[-1][1]
                            metrics_dict[name] = float(derniere_valeur_brute)
                            found = True
                        break

                # Petit debug si on ne trouve rien du tout
                if not found and results:
                    instances_dispos = [
                        res["metric"].get("instance") for res in results
                    ]
                    print(
                        f"   ⚠️ Non trouvé pour {name}. Instances dispos dans Prometheus : {instances_dispos}"
                    )
            except Exception as e:
                print(f"❌ [Prometheus] Erreur sur {name} : {e}")

        return pd.DataFrame([metrics_dict], columns=self.prom_cols)


# ==========================================
# 🧪 ZONE DE TEST (Exécutée uniquement si on lance ce script directement)
# ==========================================
if __name__ == "__main__":
    import json

    # 1. Remplace par l'URL réelle de ton Prometheus si tu n'utilises pas la locale
    URL_PROMETHEUS = "http://prometheus.aegis.local:32090"

    # 2. Remplace par un vrai nom de nœud de ton cluster (ex: "aegis-worker-spot")
    NODE_A_TESTER = "aegis-control-plane"

    client = PrometheusLiveClient(url=URL_PROMETHEUS)

    print("-" * 50)
    print(f"🚀 Lancement du test sur {URL_PROMETHEUS}")
    print("-" * 50)

    # Appel de la fonction
    resultat_dict = client.get_node_metrics(NODE_A_TESTER)

    print("\n✅ Résultat (Dictionnaire Python) :")
    # Affichage formaté du dictionnaire
    print(resultat_dict)
