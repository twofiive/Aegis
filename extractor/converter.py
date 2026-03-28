import json
import pandas as pd

# --- CONFIGURATION ---
FILE_JSON = "falco_events.json"
FILE_CSV = "falco_security_logs.csv"

def convert_falco_json_to_csv():
    print(f"📂 Lecture et analyse de {FILE_JSON}...")
    
    with open(FILE_JSON, 'r', encoding='utf-8') as f:
        logs = json.load(f)

    structured_data = []
    
    for entry in logs:
        # 1. Extraction des métadonnées principales
        row = {
            'timestamp': entry.get('time'),
            'source': entry.get('source', 'unknown'), # Différencie syscall et k8s_audit
            'rule': entry.get('rule', 'unknown'),
            'priority': entry.get('priority', 'unknown'),
            'hostname': entry.get('hostname', 'unknown'),
            # On récupère les tags (ex: mitre_discovery) en les séparant par des virgules
            'tags': ",".join([t for t in entry.get('tags', []) if t]) 
        }
        
        # 2. Extraction dynamique de tous les paramètres spécifiques
        # C'est ici que la magie opère : on récupère tout ce que Falco a structuré
        output_fields = entry.get('output_fields', {})
        if isinstance(output_fields, dict):
            for key, value in output_fields.items():
                # On remplace les points par des tirets du bas pour avoir de belles colonnes (ex: k8s_pod_name)
                safe_key = key.replace('.', '_')
                row[safe_key] = value

        structured_data.append(row)

    print(f"🏗️  Transformation en tableau (DataFrame)...")
    df = pd.DataFrame(structured_data)
    
    # 3. Nettoyage et formatage du temps
    # Transforme les dates "2026-03-03T19:53:23Z" en un format standard compréhensible par l'IA

    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce').dt.strftime('%Y-%m-%d %H:%M:%S')
    df = df.sort_values('timestamp') # On trie par ordre chronologique
    
    # On remplace les valeurs vides par 'unknown' ou 0 pour éviter de faire planter l'IA
    df = df.fillna('unknown')
    
    # 4. Sauvegarde
    df.to_csv(FILE_CSV, index=False)
    
    print(f"\n✅ Succès ! Fichier généré : {FILE_CSV} ({len(df)} lignes)")
    print(f"🔎 Sources détectées : {df['source'].unique().tolist()}")
    print(f"📊 Total des colonnes créées : {len(df.columns)}")

if __name__ == "__main__":
    convert_falco_json_to_csv()