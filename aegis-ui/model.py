import joblib
import json
import pandas as pd

class AegisDetector:
    def __init__(self, rf_path="models/aegis_random_forest.joblib", 
                if_path="models/aegis_isolation_forest.joblib", 
                features_path="models/aegis_features_list.joblib"):
        try:
            self.rf_model = joblib.load(rf_path)
            self.if_model = joblib.load(if_path)
            self.features_list = joblib.load(features_path)
            self.ready = True
            print("✅ [AEGIS-IA] Modèles chargés et prêts.")
        except Exception as e:
            print(f"❌ [AEGIS-IA] Erreur chargement modèles : {e}")
            self.ready = False
            self.features_list = []

    def preprocess(self, raw_event):
        """
        On transforme le JSON en DataFrame immédiatement pour 
        réutiliser la logique du Notebook.
        """
        if not self.ready:
            return None

        # 1. On s'assure d'avoir un dictionnaire (Falcosidekick envoie déjà un dict via request.get_json())
        entry = raw_event if isinstance(raw_event, dict) else json.loads(raw_event)

        # 2. Construction de la ligne unique (Flattening)
        row = {
            'timestamp': pd.to_datetime(entry.get('time'), utc=True),
            'rule':      entry.get('rule'),
            'priority':  entry.get('priority'),
            'source':    entry.get('source'),
            'node':      entry.get('hostname') # Normalisation hostname -> node
        }

        # Gestion des tags (liste -> string) pour matcher ton dataset
        tags = entry.get('tags', '')
        row['tags'] = ','.join(tags) if isinstance(tags, list) else tags

        # 3. Aplatissement de output_fields avec remplacement du '.' par '_'
        # C'est ici que 'k8s.pod.name' devient 'k8s_pod_name'
        fields = entry.get('output_fields', {})
        if isinstance(fields, dict):
            row.update({k.replace('.', '_'): v for k, v in fields.items()})

        # 4. Création du DataFrame (1 seule ligne)
        df = pd.DataFrame([row])

        features_to_keep = [
            'time', 'node', 'source', 'rule', 'priority', 'tags',
            # Contexte Pod/Conteneur
            'container_name', 'container_image_repository', 'k8s_ns_name',
            # Comportement OS (Syscalls)
            'evt_type', 'fd_type', 'fd_l4proto', 'fd_name',
            'proc_name', 'proc_exepath', 'proc_cmdline', 'proc_tty',
            # Comportement K8s (Audit)
            'ka_verb', 'ka_target_resource', 'ka_user_name',
            'ka_response_code', 'ka_auth_decision',
        ]

        final_columns = [col for col in features_to_keep if col in df.columns]
        df_clean = df[final_columns].copy()

        # ── Features proc_cmdline ─────────────────────────────────
        cmd = df_clean.get('proc_cmdline', pd.Series(dtype=str)).fillna('')
        suspicious_patterns = {
            'network_tools':        r'(?:curl|wget|nc|netcat|nmap)',
            'reverse_shell':        r'(?:/dev/tcp|bash\s+-i|sh\s+-i)',
            'encoding_obfuscation': r'(?:base64|xxd)',
            'permissions':          r'(?:chmod|chown)',
            'sensitive_files':      r'(?:/etc/shadow|/etc/passwd|/root/\.ssh)',
        }
        for name, pattern in suspicious_patterns.items():
            df_clean[f'cmd_has_{name}'] = cmd.str.contains(
                pattern, case=False, regex=True).astype(int)
        df_clean['cmd_length'] = cmd.str.len()
        df_clean = df_clean.drop(columns=['proc_cmdline'], errors='ignore')

        print(f"✅ Taille après nettoyage : {df_clean.shape}")
        return df_clean

    #     # Initialisation du vecteur avec des zéros
    #     data = {feat: 0 for feat in self.features_list}

    #     # 1. Extraction numérique (Longueur de commande)
    #     if 'proc.cmdline' in output_fields:
    #         data['cmd_length'] = len(str(output_fields['proc.cmdline']))

    #     # 2. One-Hot Encoding (Nom du processus)
    #     proc_name = output_fields.get('proc.name', 'unknown')
    #     feature_name = f"proc_name_{proc_name}"
    #     if feature_name in data:
    #         data[feature_name] = 1

    #     # Retourne un DataFrame avec l'ordre exact des colonnes
    #     return pd.DataFrame([data])[self.features_list]

    # def get_verdict(self, df_input):
    #     """Applique la hiérarchie de décision AEGIS."""
    #     if df_input is None:
    #         return "Erreur Configuration", False

    #     # --- LOGIQUE DE PRIORITÉ ---
    #     # 1. Le Sniper (Random Forest) : Signature connue
    #     rf_pred = self.rf_model.predict(df_input)[0]
    #     if rf_pred == 1:
    #         return "CRITIQUE (Signature)", True

    #     # 2. L'Éclaireur (Isolation Forest) : Comportement anormal
    #     # if_pred = self.if_model.predict(df_input)[0]
    #     # if if_pred == -1:
    #     #     return "SUSPECT (Anomalie)", True

        return df