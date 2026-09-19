"""Train TF-IDF + LogisticRegression on curated samples. Run: python scripts/train_nlp.py"""
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
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

X = PHISH + BEC + CLEAN
y = (["phishing"] * len(PHISH)) + (["bec"] * len(BEC)) + (["clean"] * len(CLEAN))

pipe = Pipeline([
    ("tfidf", TfidfVectorizer(ngram_range=(1, 2), max_features=5000)),
    ("clf", LogisticRegression(max_iter=1000)),
])
pipe.fit(X, y)
out_dir = os.path.join(os.path.dirname(__file__), "..", "ml_models")
os.makedirs(out_dir, exist_ok=True)
joblib.dump(pipe, os.path.join(out_dir, "phishing_clf.joblib"))
print(f"saved to {out_dir}/phishing_clf.joblib, classes={pipe.classes_}")
