from flask import Flask, render_template, request, jsonify
from datetime import datetime

app = Flask(__name__)

anomalies = []


@app.route('/')
def dashboard():
    # On passe les anomalies triées par date (plus récent en haut)
    sorted_anomalies = sorted(anomalies, key=lambda x: x['timestamp'], reverse=True)
    return render_template('dashboard.html', anomalies=sorted_anomalies)

#  POST /api/webhook ────────────
# Falcosidekick envoie les events ici en JSON.
# Pour l'instant on stocke tout. Plus tard le modèle fera predict().
@app.route('/api/webhook', methods=['POST'])
def webhook():
    event = request.get_json()

    print("--- NOUVEL EVENT REÇU ---")
    print(event) # Ceci affichera le contenu dans ton terminal

    # Extraire les infos utiles du JSON Falco
    output_fields = event.get('output_fields', {})

    processed = {
        'timestamp': event.get('time', datetime.utcnow().isoformat()),
        'rule': event.get('rule', 'unknown'),
        'priority': event.get('priority', 'unknown'),
        'source': event.get('source', 'unknown'),
        'hostname': event.get('hostname', 'unknown'),
        'pod_name': output_fields.get('k8s.pod.name', 'unknown'),
        'namespace': output_fields.get('k8s.ns.name', 'unknown'),
        'container': output_fields.get('container.name', 'unknown'),
        'proc_name': output_fields.get('proc.name', 'unknown'),
        'proc_cmdline': output_fields.get('proc.cmdline', 'unknown'),
        # Pour l'instant pas de modèle, on met un placeholder
        'is_anomaly': False,
        'anomaly_score': 0.0,
    }

    anomalies.append(processed)
    return jsonify({"status": "received"}), 200

# ─── ROUTE 3 : GET /api/anomalies ───────────────────────

@app.route('/api/anomalies')
def get_anomalies():
    return jsonify(anomalies)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

