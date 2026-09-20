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
    "Security alert: someone tried to access your email from Russia, confirm identity now",
    "Your package delivery failed, click the link to reschedule and pay the fee",
    "Action required: your password expires today, reset it at this link immediately",
    "Dear customer, your tax refund is pending, submit your card details to receive it",
    "Unusual sign-in attempt blocked, verify your account to restore access",
    "Your subscription will be charged $499 unless you cancel here within 24 hours",
    "HR notice: open the attached payroll update and enable macros to view",
    "Your cloud storage quota exceeded, login to prevent file deletion",
    "Final warning: your domain will be deactivated, confirm ownership now",
    "You received a secure document, sign in with your email password to open it",
    "IT desk: mandatory mailbox migration tonight, re-authenticate via this portal",
    "Invoice overdue: pay now to avoid legal action, see attached receipt",
    "Your social account will be locked, appeal the decision through this form",
    "Congratulations employee of the month, claim your bonus gift card here",
    "Bank memo: confirm the attached wire instructions before funds are released",
    "Your voicemail could not be delivered, preview it by logging in here",
]
BEC = [
    "Hi, are you available? I need you to process a wire discreetly - CFO",
    "Please pay attached invoice to new account, keep confidential until done - President",
    "Kindly send me your mobile number, I need gift cards for clients - CEO",
    "Are you at your desk? I need a quick favor before my meeting ends - Managing Director",
    "Please review the attached acquisition payment schedule, strictly confidential - CFO",
    "Can you wire the deposit for our new office lease today? Details attached - CEO",
    "I need you to handle a sensitive vendor payment, reply only to this email - Finance Director",
    "Please buy six app store cards for our top clients and share the codes - CEO",
    "Confirm you received my earlier note about the board bonus transfers - Chairman",
    "Our auditor needs last quarter invoices paid to the updated account - CFO",
    "Kindly keep this between us and process the attached payment - President",
    "I am in back-to-back meetings, please settle this supplier invoice now - CEO",
]
CLEAN = [
    "Hi team, attached are the minutes from yesterday's standup meeting",
    "Lunch tomorrow at noon? Let me know if the cafeteria works",
    "Quarterly report draft ready for review when you have time",
    "Thanks for your help debugging the pipeline today",
    "Reminder: office closed next Friday for maintenance",
    "Can you review my pull request when you get a chance?",
    "The sprint planning session moved to Thursday at 10am in room B",
    "Welcome aboard! Your onboarding schedule is attached for next week",
    "Could you share the slides from yesterday's architecture review?",
    "Heads up, the VPN client update is available on the intranet portal",
    "Team lunch photos are in the shared drive, feel free to add yours",
    "The build is green again after reverting the flaky migration",
    "Please book your vacation days in the HR system before month end",
    "Notes from the customer call are summarized in the wiki page",
    "The design mockups for the new dashboard are ready for feedback",
    "Reminder to submit your timesheets by Friday afternoon",
    "Our team offsite is scheduled for next month, agenda to follow",
    "The database backup completed successfully overnight, no action needed",
    "Can we reschedule our 1:1 to Wednesday? Something came up",
    "Thanks for covering the support rotation last weekend",
    "The conference room projector bulb was replaced this morning",
    "Please find the updated API documentation linked in this message",
    "Happy birthday! Cake in the kitchen at 3pm for everyone",
    "The quarterly all-hands recording is posted for those who missed it",
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
