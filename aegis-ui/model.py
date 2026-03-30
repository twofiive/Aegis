import joblib
import json
import time
import pandas as pd


class AegisDetector:
    def __init__(
        self,
        rf_path="models/aegis_random_forest.joblib",
        if_path="models/aegis_isolation_forest.joblib",
        features_path="models/aegis_features_list.joblib",
        scaler_path="models/aegis_scaler.joblib",
        ohe_path="models/aegis_ohe.joblib",
    ):
        try:
            self.ohe = joblib.load(ohe_path)
            self.scaler = joblib.load(scaler_path)
            self.rf_model = joblib.load(rf_path)
            self.if_model = joblib.load(if_path)
            self.features_list = joblib.load(features_path)

            # Une simple liste qui va stocker les alertes des 60 dernières secondes
            self.event_buffer = []

            self.RULE_SEVERITY = {
                "Write below etc in container": 10,
                "Drop and execute new binary in container": 10,
                "Mount inside container": 10,
                "Read process memory in container": 10,
                "Terminal shell in container": 10,
                "Attach/Exec Pod": 10,
                "Create Privileged Pod": 9,
                "port-forward": 8,
                "K8s Secret Get Successfully": 7,
                "Disallowed K8s User": 6,
                "Service Account Created in Kube Namespace": 4,
                "K8s Serviceaccount Created": 3,
                "Contact K8S API Server From Container": 1,
                "Falco internal: syscall event drop": 0,
            }

            self.PRIORITY_MAP = {
                "Emergency": 7,
                "Alert": 6,
                "Critical": 5,
                "Error": 4,
                "Warning": 3,
                "Notice": 2,
                "Informational": 1,
                "Debug": 0,
            }
            self.ready = True
            print("✅ [AEGIS-IA] Modèles chargés et prêts.")
        except Exception as e:
            print(f"❌ [AEGIS-IA] Erreur chargement modèles : {e}")
            self.ready = False
            self.features_list = []

    def preprocess(self, raw_event, df_prom):
        """
        On transforme le JSON en DataFrame immédiatement pour
        réutiliser la logique du Notebook.
        """
        if not self.ready:
            return None

        # 1. On s'assure d'avoir un dictionnaire (Falcosidekick envoie déjà un dict via request.get_json())
        entry = (
            raw_event if isinstance(raw_event, dict) else json.loads(raw_event)
        )

        # 2. Construction de la ligne unique (Flattening)
        row = {
            "timestamp": pd.to_datetime(entry.get("time"), utc=True),
            "rule": entry.get("rule"),
            "priority": entry.get("priority"),
            "source": entry.get("source"),
            "node": entry.get("hostname"),  # Normalisation hostname -> node
        }

        # Gestion des tags (liste -> string) pour matcher ton dataset
        tags = entry.get("tags", "")
        row["tags"] = ",".join(tags) if isinstance(tags, list) else tags

        # 3. Aplatissement de output_fields avec remplacement du '.' par '_'
        # C'est ici que 'k8s.pod.name' devient 'k8s_pod_name'
        fields = entry.get("output_fields", {})
        if isinstance(fields, dict):
            row.update({k.replace(".", "_"): v for k, v in fields.items()})

        # 4. Création du DataFrame (1 seule ligne)
        df = pd.DataFrame([row])

        features_to_keep = [
            "time",
            "node",
            "source",
            "rule",
            "priority",
            "tags",
            # Contexte Pod/Conteneur
            "container_name",
            "container_image_repository",
            "k8s_ns_name",
            # Comportement OS (Syscalls)
            "evt_type",
            "fd_type",
            "fd_l4proto",
            "fd_name",
            "proc_name",
            "proc_exepath",
            "proc_cmdline",
            "proc_tty",
            # Comportement K8s (Audit)
            "ka_verb",
            "ka_target_resource",
            "ka_user_name",
            "ka_response_code",
            "ka_auth_decision",
        ]

        final_columns = [col for col in features_to_keep if col in df.columns]
        df_clean = df[final_columns].copy()

        # ── Features proc_cmdline ─────────────────────────────────
        cmd = df_clean.get("proc_cmdline", pd.Series(dtype=str)).fillna("")
        suspicious_patterns = {
            "network_tools": r"(?:curl|wget|nc|netcat|nmap)",
            "reverse_shell": r"(?:/dev/tcp|bash\s+-i|sh\s+-i)",
            "encoding_obfuscation": r"(?:base64|xxd)",
            "permissions": r"(?:chmod|chown)",
            "sensitive_files": r"(?:/etc/shadow|/etc/passwd|/root/\.ssh)",
        }
        for name, pattern in suspicious_patterns.items():
            df_clean[f"cmd_has_{name}"] = cmd.str.contains(
                pattern, case=False, regex=True
            ).astype(int)
        df_clean["cmd_length"] = cmd.str.len()
        df_clean = df_clean.drop(columns=["proc_cmdline"], errors="ignore")

        if isinstance(df_prom, pd.DataFrame) and not df_prom.empty:
            prom_cols = df_prom.columns.tolist()
            for col in prom_cols:
                df_clean[col] = df_prom[col].values[0]
            df_clean["has_prom_data"] = (
                df_clean[prom_cols[0]].notna().astype(int)
            )
        else:
            df_clean["has_prom_data"] = (
                df_clean[prom_cols[0]].notna().astype(int)
            )

        # print(f"✅ Taille avant nettoyage : {df_clean.shape}")
        # return df_clean

        # --- GESTION DU BUFFER TEMPOREL (SLIDING WINDOW) ---

        # 1. Extraction des infos de l'événement courant
        current_time = time.time()  # Heure exacte de l'arrivée de l'alerte
        rule_name = raw_event.get("rule", "unknown")
        source = raw_event.get("source", "unknown")
        # Sévérité par défaut à 2 si la règle n'est pas dans le dictionnaire
        severity = self.RULE_SEVERITY.get(rule_name, 2)

        # 2. Ajout de l'événement dans la mémoire
        self.event_buffer.append(
            {
                "time": current_time,
                "rule": rule_name,
                "source": source,
                "severity": severity,
            }
        )

        # 3. Nettoyage : On supprime les événements vieux de plus de 60 secondes
        self.event_buffer = [
            evt
            for evt in self.event_buffer
            if (current_time - evt["time"]) <= 60
        ]

        # 4. Calcul ultrarapide des 5 features de ton notebook
        # On extrait les listes pour faciliter le calcul
        severities = [evt["severity"] for evt in self.event_buffer]
        rules = set([evt["rule"] for evt in self.event_buffer])
        sources = set([evt["source"] for evt in self.event_buffer])

        window_event_count = len(self.event_buffer)
        window_unique_rules = len(rules)
        window_max_severity = max(severities) if severities else 0
        window_has_critical = 1 if window_max_severity >= 7 else 0
        window_multi_source = 1 if len(sources) > 1 else 0

        # 5. Injection dans le vecteur final !
        features_to_inject = {
            "window_event_count": window_event_count,
            "window_unique_rules": window_unique_rules,
            "window_max_severity": window_max_severity,
            "window_has_critical": window_has_critical,
            "window_multi_source": window_multi_source,
        }

        for col, value in features_to_inject.items():
            if col not in df_clean.columns:
                df_clean[col] = float(value)

        # Preprocssing starting here

        df_ml = df_clean.copy()

        # 1. Colonnes à exclure
        EXCLUDE = {
            "timestamp",
            "ts_window",
            "node",
            "tags",
            "is_attack",
            "container_image_repository",
            "container_name",
            "k8s_pod_name",
            "proc_exepath",
            "ka_user_name",
            "ka_response_code",
            "ka_verb",
            "ka_target_resource",
            "ka_auth_decision",
            "priority",
            "proc_tty",
            "k8s_ns_name",
        }

        # 2. Colonnes catégorielles (One-Hot Encoding)
        # Colonnes catégorielles à encoder en One-Hot (liste explicite, pas toutes les catégorielles)
        OHE_COLS = [
            "source",
            "priority",
            "evt_type",
            "fd_type",
            "fd_l4proto",
            "rule",
            "proc_name",
        ]

        # Si une colonne manque, Pandas la crée avec des NaN (qui deviendront "unknown")
        for col in OHE_COLS:
            if col not in df_ml.columns:
                df_ml[col] = "unknown"

        # 3. On transforme en utilisant la liste complète OHE_COLS (pas ohe_existing)
        # On force l'ordre des colonnes pour correspondre à l'encodeur
        ohe_array = self.ohe.transform(df_ml[OHE_COLS].fillna("unknown"))

        # 4. On reconstruit le DataFrame
        df_ohe = pd.DataFrame(
            ohe_array, columns=self.ohe.get_feature_names_out(OHE_COLS)
        )

        # 3. Colonnes numériques (Falco + Prometheus)
        num_prefixes = (
            "cmd_",
            "fd_",
            "ka_",
            "tag_",
            "window_",
            "rule_",
            "priority_num",
            "hour_",
            "is_",
            "has_prom",
        )

        if prom_cols:
            num_cols = [
                c
                for c in df_ml.columns
                if (c.startswith(num_prefixes) or c in prom_cols)
                and c not in EXCLUDE
                and pd.api.types.is_numeric_dtype(df_ml[c])
            ]

            df_num = df_ml[num_cols].fillna(0)
            existing_prom = [c for c in prom_cols if c in df_num.columns]
            if existing_prom:
                df_num[existing_prom] = self.scaler.transform(
                    df_num[existing_prom]
                )

        # Assemblage
        X = pd.concat(
            [df_num.reset_index(drop=True), df_ohe.reset_index(drop=True)],
            axis=1,
        ).astype(float)

        X = X.reindex(columns=self.features_list, fill_value=0.0)

        # print(
        #     f"🚀 Matrice prête : {X.shape[0]:,} lignes × {X.shape[1]} features"
        # )
        # print(f"✅ Taille après nettoyage : {X.shape}")
        # print(f"   Features numériques : {len(num_cols)}")
        # print(f"   Features OHE        : {df_ohe.shape[1]}")
        return X

    def get_verdict(self, df_input):
        """
        Applique la hiérarchie de décision AEGIS.
        Prend en entrée le DataFrame (1 ligne) sorti de preprocess().
        Retourne : (Verdict_Texte, Est_Une_Alerte_Booléen)
        """
        if df_input is None or df_input.empty:
            return "Erreur Preprocess", False

        try:
            # --- 1. TIER 1 : Le Sniper (Random Forest) ---
            # Il cherche une signature d'attaque connue qu'il a apprise.
            # Sortie : 1 (Attaque) ou 0 (Normal)
            rf_pred = self.rf_model.predict(df_input)[0]

            if rf_pred == 1:
                # Si le RF tire, on ne cherche même pas à demander aux autres. C'est critique.
                return "🔴 CRITIQUE (Signature ML)", True

            # --- 2. TIER 2 : L'Éclaireur (Isolation Forest) ---
            # Si le RF n'a rien vu, on demande à l'IF s'il trouve le comportement "bizarre".
            # Sortie de Scikit-Learn : -1 (Anomalie) ou 1 (Normal)
            # if hasattr(self, "if_model") and self.if_model is not None:
            #     if_pred = self.if_model.predict(df_input)[0]

            #     if if_pred == -1:
            #         return "🟡 SUSPECT (Anomalie Inconnue)", True

            # --- 3. TOUT EST NORMAL ---
            return "🟢 Normal", False

        except Exception as e:
            print(f"❌ [AEGIS-IA] Erreur lors de la prédiction : {e}")
            return "Erreur Inférence", False
