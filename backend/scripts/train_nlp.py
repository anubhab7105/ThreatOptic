"""Train TF-IDF + LogisticRegression on curated samples + cache held-out metrics.

Run:  python backend/scripts/train_nlp.py
Saves: backend/ml_models/phishing_clf.joblib + backend/ml_models/metrics.json
"""
import json
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
import joblib

PHISH = [
    "Urgent: your account will be suspended. Verify immediately by clicking here",
    "Dear CEO, kindly wire transfer $50,000 to new vendor bank details confidentially",
    "Your mailbox is full, login to upgrade storage now",
    "Confidential payment required, do not disclose, process invoice ASAP",
    "Your bank security team: unusual login, verify password now",
    "Gift cards needed urgently, send codes ASAP, do not tell anyone",
    "Updated remittance information, change bank account for next payment",
    "You have won a prize, click here to claim with your credentials",
]
BEC = [
    "Hi, are you available? I need you to process a wire discreetly - CFO",
    "Please pay attached invoice to new account, keep confidential until done - President",
    "Kindly send me your mobile number, I need gift cards for clients - CEO",
]
CLEAN = [
    "Hi team, attached are the minutes from yesterday's standup meeting",
    "Lunch tomorrow at noon? Let me know if the cafeteria works",
    "Quarterly report draft ready for review when you have time",
    "Thanks for your help debugging the pipeline today",
    "Reminder: office closed next Friday for maintenance",
    "Can you review my pull request when you get a chance?",
]

TEST_SIZE = 0.25
RANDOM_STATE = 42


def get_data() -> tuple[list[str], list[str]]:
    X = PHISH + BEC + CLEAN
    y = (["phishing"] * len(PHISH)) + (["bec"] * len(BEC)) + (["clean"] * len(CLEAN))
    return X, y


def build_pipeline() -> Pipeline:
    return Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), max_features=5000)),
        ("clf", LogisticRegression(max_iter=1000)),
    ])


def out_paths() -> tuple[str, str]:
    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ml_models")
    os.makedirs(out_dir, exist_ok=True)
    return os.path.join(out_dir, "phishing_clf.joblib"), os.path.join(out_dir, "metrics.json")


def main() -> dict:
    X, y = get_data()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    pipe = build_pipeline()
    pipe.fit(X_train, y_train)
    pred = pipe.predict(X_test)

    labels = sorted(set(y))
    report = classification_report(y_test, pred, labels=labels, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_test, pred, labels=labels).tolist()
    metrics = {
        "accuracy": round(float(report["accuracy"]), 4),
        "macro_precision": round(float(report["macro avg"]["precision"]), 4),
        "macro_recall": round(float(report["macro avg"]["recall"]), 4),
        "macro_f1": round(float(report["macro avg"]["f1-score"]), 4),
        "per_class": {
            label: {
                "precision": round(float(report[label]["precision"]), 4),
                "recall": round(float(report[label]["recall"]), 4),
                "f1": round(float(report[label]["f1-score"]), 4),
                "support": int(report[label]["support"]),
            }
            for label in labels
        },
        "confusion_matrix": cm,
        "confusion_labels": labels,
        "n_train": len(X_train),
        "n_test": len(X_test),
        "test_size": TEST_SIZE,
        "random_state": RANDOM_STATE,
        "classes": [str(c) for c in pipe.classes_],
    }
    model_path, metrics_path = out_paths()
    joblib.dump(pipe, model_path)
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"saved model to {model_path}, classes={pipe.classes_}")
    print(f"saved metrics to {metrics_path}: accuracy={metrics['accuracy']} macro_f1={metrics['macro_f1']}")
    return metrics


if __name__ == "__main__":
    main()
