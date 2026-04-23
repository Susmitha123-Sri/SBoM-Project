import matplotlib
matplotlib.use('Agg')

import hashlib


# ============================
# DATA HASH FUNCTION
# ============================
def get_dataset_hash(file_path="sbom_dataset.csv"):
    try:
        with open(file_path, "rb") as f:
            return hashlib.md5(f.read()).hexdigest()
    except:
        return None


def run_analytics():
    try:
        import pandas as pd
        import numpy as np
        import os
        import matplotlib.pyplot as plt
        import seaborn as sns
        import json

        from sklearn.model_selection import train_test_split, cross_val_score
        from sklearn.preprocessing import StandardScaler
        from sklearn.linear_model import LogisticRegression
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.svm import SVC
        from sklearn.metrics import f1_score, confusion_matrix
        from sklearn.cluster import KMeans

        # ============================
        # LOAD DATA
        # ============================
        df = pd.read_csv("sbom_dataset.csv")

        if df.empty:
            return {}

        # ============================
        # CHANGE DETECTION
        # ============================
        current_hash = get_dataset_hash()
        hash_file = "analytics_hash.txt"

        if os.path.exists(hash_file):
            with open(hash_file, "r") as f:
                old_hash = f.read()

            if old_hash == current_hash:
                print("⚡ No data change → skipping analytics")
                return None

        # ============================
        # CLEANING
        # ============================
        df = df[df["package_name"].notna()]

        df["days_outdated"] = pd.to_numeric(df["days_outdated"], errors="coerce")
        df["days_outdated"] = df["days_outdated"].fillna(df["days_outdated"].median())

        df["outdated_flag"] = (df["status"] == "outdated").astype(int)

        # ============================
        # TARGET
        # ============================
        y = df["severity"].apply(lambda x: 1 if x == "high" else 0)

        # ============================
        # FEATURES
        # ============================
        df["repo_freq"] = df["repo_name"].map(df["repo_name"].value_counts())
        df["package_freq"] = df["package_name"].map(df["package_name"].value_counts())
        df["repo_avg_days"] = df.groupby("repo_name")["days_outdated"].transform("mean")

        X = df[["repo_freq", "package_freq", "repo_avg_days"]]

        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, stratify=y, random_state=42
        )

        # ============================
        # MODELS
        # ============================
        models = {
            "Logistic Regression": LogisticRegression(max_iter=300, class_weight='balanced'),
            "Random Forest": RandomForestClassifier(n_estimators=100, class_weight='balanced'),
            "SVM": SVC(class_weight='balanced')
        }

        full_model_table = []

        for name, model in models.items():
            model.fit(X_train, y_train)

            acc = model.score(X_test, y_test)
            cv = cross_val_score(model, X_scaled, y, cv=3).mean()

            y_pred = model.predict(X_test)
            f1 = f1_score(y_test, y_pred)

            full_model_table.append({
                "model": name,
                "accuracy": round(acc, 3),
                "cv_score": round(cv, 3),
                "f1_score": round(f1, 3)
            })

        # ============================
        # OUTDATED DATA
        # ============================
        df_ml = df[df["outdated_flag"] == 1].copy()

        if len(df_ml) < 10:
            return {}

        # ============================
        # FILE STORAGE
        # ============================
        STATIC_DIR = os.path.join(os.getcwd(), "ui", "static", "analytics")
        os.makedirs(STATIC_DIR, exist_ok=True)

        images = []

        def save_plot(name):
            path = os.path.join(STATIC_DIR, name)
            plt.tight_layout()
            plt.savefig(path, dpi=150)
            plt.close()
            return f"analytics/{name}"

        # ============================
        # GRAPHS
        # ============================

        # 1. Severity Distribution
        plt.figure(figsize=(8,5))
        counts = df_ml["severity"].value_counts()
        total = counts.sum()

        bars = plt.bar(counts.index, counts.values)

        for bar in bars:
            height = bar.get_height()
            percentage = (height / total) * 100
            plt.text(
                bar.get_x() + bar.get_width()/2,
                height,
                f"{percentage:.1f}%",
                ha='center',
                va='bottom',
                fontweight='bold'
            )

        plt.title("Severity Distribution of Outdated Components")
        plt.xlabel("Severity Level")
        plt.ylabel("Number of Packages")

        images.append(save_plot("severity.png"))

        # 2. Days Outdated
        plt.figure(figsize=(8,5))
        limit = df_ml["days_outdated"].quantile(0.98)
        filtered = df_ml[df_ml["days_outdated"] <= limit]

        plt.scatter(filtered["days_outdated"], np.ones(len(filtered)), alpha=0.6)
        plt.boxplot(filtered["days_outdated"], vert=False)

        plt.title("Distribution of Outdated Packages by Age")
        plt.xlabel("Days Since Last Update")
        plt.ylabel("Distribution")

        images.append(save_plot("days.png"))

        # 3. Severity vs Days
        plt.figure(figsize=(8,5))
        for label in df_ml["severity"].unique():
            subset = df_ml[df_ml["severity"] == label]
            plt.scatter(
                subset["days_outdated"],
                subset["repo_avg_days"],
                label=label
            )

        plt.title("Severity vs Aging")
        plt.xlabel("Days Outdated")
        plt.ylabel("Repo Avg Days")
        plt.legend()

        images.append(save_plot("severity_vs_days.png"))

        # 4. Clustering
        kmeans = KMeans(n_clusters=3, random_state=42)
        df_ml["cluster"] = kmeans.fit_predict(
            scaler.fit_transform(df_ml[["days_outdated", "repo_avg_days"]])
        )

        plt.figure(figsize=(8,5))
        df_ml["cluster"].value_counts().sort_index().plot(kind="bar")

        plt.title("Cluster Distribution")
        plt.xlabel("Cluster")
        plt.ylabel("Count")

        images.append(save_plot("clusters.png"))

        # 5. Top Repos
        if "repo_name" in df_ml.columns:
            plt.figure(figsize=(8,5))
            df_ml.groupby("repo_name")["days_outdated"].mean().sort_values().tail(10).plot(kind="barh")
            plt.title("Top Repositories by Outdated Days")
            plt.xlabel("Avg Days Outdated")

            images.append(save_plot("repos.png"))

        # 6. Confusion Matrix
        model = RandomForestClassifier(max_depth=5)
        model.fit(X_train, y_train)

        cm = confusion_matrix(y_test, model.predict(X_test))

        plt.figure(figsize=(6,5))
        sns.heatmap(cm, annot=True, fmt='d')

        plt.title("Confusion Matrix")
        plt.xlabel("Predicted")
        plt.ylabel("Actual")

        images.append(save_plot("confusion.png"))

        # ============================
        # SAVE RESULT + HASH + CACHE
        # ============================
        result = {
            "full_model_table": full_model_table,
            "images": images
        }

        with open("analytics_hash.txt", "w") as f:
            f.write(current_hash)

        with open("analytics_cache.json", "w") as f:
            json.dump(result, f)

        print("Analytics updated & cached")

        return result

    except Exception as e:
        pass
        return {}


# ============================
# LOAD CACHE FOR UI
# ============================
def load_cached_analytics():
    import os, json

    if not os.path.exists("analytics_cache.json"):
        return None

    with open("analytics_cache.json", "r") as f:
        return json.load(f)