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
    "Your mailbox is full, login to upgrade storage now",
    "Your bank security team: unusual login, verify password now",
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
    "Mandatory account verification: re-authenticate via this external login portal",
    "Your social account will be locked, appeal the decision through this form",
    "Your voicemail could not be delivered, preview it by logging in here",
    "DHL tracking: Parcel delivery failed, update your delivery address online",
    "Netflix alert: Your payment method declined, click here to update your card",
    "PayPal security: We noticed suspicious purchases on your account, verify your login",
    "Microsoft 365: Unusual activity detected, click here to keep your active session",
    "Apple ID locked: Please verify your Apple credentials to restore service",
    "Amazon customer support: Order confirmation #892189, dispute transaction here",
    "DocuSign envelope pending: Sign in to view and sign the encrypted document",
    "Dropbox transfer: You have received shared files, enter your email password to download",
    "Bank of America: Security code required to prevent immediate account closure",
    "Chase Online: Suspicious card swipe detected in another country, verify credentials",
    "FedEx delivery notification: Shipment on hold, pay outstanding customs fee here",
    "Zoom notification: Missed audio recording waiting, log in to access meeting transcript",
    "LinkedIn security: New unrecognized device logged into your profile, confirm ownership",
    "Google Workspace: Your storage is 99% full, click to purchase extra storage",
    "Adobe Creative Cloud: Your payment failed, re-enter credit card details to avoid cancellation",
    "Internal Portal: Critical security patch required for your workstation, authenticate here",
    "Wells Fargo Fraud Alert: Your debit card has been frozen, click to verify transactions",
    "Coinbase notification: Withdrawal of 1.4 BTC requested, cancel transaction if unauthorized",
    "SharePoint notification: Encrypted audit document shared with you, enter domain credentials",
    "USPS Alert: Undeliverable package returned to depot, confirm recipient identity",
    "Intuit QuickBooks: Billing invoice overdue, review invoice and enter payment method",
    "E-signature required: Employment contract termination notice, sign in to read",
    "Outlook Web Access: Server certificate expired, update mailbox settings immediately",
    "Target customer care: Unauthorized order placed on your account, click here to cancel",
]
BEC = [
    "Hi, are you available? I need you to process an urgent wire transfer discreetly - CFO",
    "Please pay attached invoice to new vendor account, keep confidential until done - President",
    "Kindly send me your mobile number, I need gift cards for client appreciation - CEO",
    "Are you at your desk? I need a quick favor before my board meeting ends - Managing Director",
    "Please review the attached acquisition payment schedule, strictly confidential - CFO",
    "Can you wire the deposit for our new office lease today? Details attached - CEO",
    "I need you to handle a sensitive vendor payment, reply only to this email - Finance Director",
    "Please buy six Apple store gift cards for our top clients and share the codes - CEO",
    "Confirm you received my earlier note about the board bonus bank transfers - Chairman",
    "Our auditor needs last quarter invoices paid to the updated bank account - CFO",
    "Kindly keep this between us and process the attached wire payment - President",
    "I am in back-to-back meetings, please settle this supplier invoice right now - CEO",
    "We have changed our remittance account details, please remit payment to new account - Supplier",
    "Urgent wire required for confidential contract closing before 4 PM - Chief Executive Officer",
    "Can you arrange a wire transfer of $45,000 for emergency consulting fees today? - CFO",
    "Do not discuss with anyone, but I need an immediate wire transfer processed - VP Finance",
    "Please update vendor banking coordinates for the upcoming wire remittance - Controller",
    "Need you to send an international wire transfer to our European subsidiary account - CEO",
    "Can you process payment for the attached legal retainer invoice before end of day? - Executive VP",
    "Please purchase Google Play gift cards for the executive retreat and send me the PINs - CEO",
    "Confidential directive from the board: authorize payment for the pending acquisition - Chairman",
    "Kindly expedite the wire transfer to the attached account number right away - CFO",
    "Please issue an electronic funds transfer for the confidential settlement agreement - President",
    "I need you to wire funds to our overseas partner immediately, details in attachment - CEO",
    "Please confirm when the wire transfer to our new banking partner has cleared - Finance Director",
    "Need an urgent transfer to settle contractor balance before the weekend - Managing Director",
    "Kindly update our payment profile to the new IBAN details attached - Vendor Rep",
    "Are you in the office? Need a confidential financial transaction completed ASAP - CFO",
    "Urgent request: wire transfer needed for patent filing fee deadline - Chief Legal Officer",
    "Please arrange an off-cycle payment to the new account specified in this email - President",
    "Send me our current bank balance immediately, planning a confidential purchase - CEO",
    "Please execute the attached ACH transfer to our newly onboarded logistics provider - CFO",
    "I am traveling without phone access, please wire the funds for the commercial lease - President",
    "Can you process an urgent disbursement of $38,500 to the attached legal escrow account? - Executive VP",
    "Send over the company's full employee W-2 records and direct deposit details - Chief Human Resources",
    "Kindly purchase ten $100 Amazon gift cards for employee rewards and email the back photos - CEO",
    "We need to wire the down payment for the equipment purchase by 3 PM today - Operations Director",
    "Please change the routing instructions for tomorrow's payroll funding - Vice President Finance",
    "Need a discrete wire sent to our acquisition escrow account, do not mention to the team - Chairman",
    "Authorize the immediate release of funds for the vendor settlement invoice attached - CFO",
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
    "Friendly reminder to log your standard project hours in the company timesheet",
    "Our team offsite is scheduled for next month, agenda to follow",
    "The database backup completed successfully overnight, no action needed",
    "Can we reschedule our 1:1 to Wednesday? Something came up",
    "Thanks for covering the support rotation last weekend",
    "The conference room projector bulb was replaced this morning",
    "Please find the updated API documentation linked in this message",
    "Happy birthday! Cake in the kitchen at 3pm for everyone",
    "The quarterly all-hands recording is posted for those who missed it",
    "Here is the draft agenda for next week's team sprint retrospective",
    "Can you take a look at the updated customer interview notes in Notion?",
    "The new office monitors have arrived and are available at the front IT desk",
    "Great work on resolving that production incident quickly this morning",
    "Just sharing the slide deck from the product marketing sync earlier today",
    "Please remember to sign off on the release checklist before 5pm",
    "Coffee break at 3pm if anyone wants to step outside for 15 minutes",
    "The Q3 engineering goals document has been published to Google Drive",
    "Don't forget to submit your feedback on the quarterly peer review form",
    "The client loved the product demonstration today, awesome job team",
    "We have scheduled the code freeze for next Tuesday ahead of the major release",
    "Can you help test the new search filters on the staging environment?",
    "Attached is the summary of the quarterly vendor performance evaluations",
    "The annual company hackathon will take place during the third week of October",
    "Looking forward to our sync tomorrow morning to discuss system architecture",
    "Thanks everyone for joining today's all-hands meeting, enjoy the weekend",
]

TEST_SIZE = 0.2
RANDOM_STATE = 42
LABELS = ("phishing", "bec", "clean")


def get_data() -> tuple[list[str], list[str]]:
    X = PHISH + BEC + CLEAN
    y = (["phishing"] * len(PHISH)) + (["bec"] * len(BEC)) + (["clean"] * len(CLEAN))
    return X, y


def dataset_csv_path() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ml_models", "dataset.csv")


def load_training_data() -> tuple[list[str], list[str], str]:
    """Real corpus (fetch_datasets.py) when present, else curated fallback."""
    path = dataset_csv_path()
    if os.path.exists(path):
        import csv
        X, y = [], []
        with open(path, newline="") as f:
            for row in csv.DictReader(f):
                text, label = (row.get("text") or "").strip(), (row.get("label") or "").strip()
                if text and label in LABELS:
                    X.append(text)
                    y.append(label)
        if X:
            return X, y, f"dataset.csv ({len(X)} rows)"
    X, y = get_data()
    return X, y, f"curated fallback ({len(X)} rows)"


def build_pipeline() -> Pipeline:
    return Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), max_features=5000, sublinear_tf=True)),
        ("clf", LogisticRegression(max_iter=1000, class_weight="balanced", C=3.0)),
    ])


def out_paths() -> tuple[str, str]:
    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ml_models")
    os.makedirs(out_dir, exist_ok=True)
    return os.path.join(out_dir, "phishing_clf.joblib"), os.path.join(out_dir, "metrics.json")


def main() -> dict:
    X, y, source = load_training_data()
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
        "dataset": source,
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
