from flask import Flask, render_template, request
import pickle
import numpy as np
import re
import fitz  # PyMuPDF for PDFs
import requests
import nltk
from nltk.tokenize import word_tokenize
from nltk.stem import WordNetLemmatizer
from nltk.corpus import stopwords

nltk.download('punkt')
nltk.download('wordnet')
nltk.download('stopwords')

app = Flask(__name__)

# === API Key ===
VT_API_KEY = "b3bcf57674026967cc3e583bfab96a559ca9af16ec26edf69ed5005d35cd23be"

# === Load model and vectorizer ===
with open("model.pkl", "rb") as f:
    model = pickle.load(f)
with open("vectorizer.pkl", "rb") as f:
    vectorizer = pickle.load(f)

# === Keyword list and NLP prep ===
phishing_keywords = [
    "reset your password", "verify your account", "click below", "login to confirm",
    "update billing", "urgent", "account suspended", "invoice", "free", "claim", "congratulations",
    "limited time", "security alert", "confirm your identity", "pay now", "alert", "secure link"
]

stop_words = set(stopwords.words('english'))
lemmatizer = WordNetLemmatizer()

# === Utility Functions ===
def clean_email(text):
    if not isinstance(text, str):
        return ""
    text = re.sub(r"http\S+|www\S+|https\S+", '', text)
    text = re.sub(r'\W', ' ', text)
    text = re.sub(r'\s+', ' ', text)
    words = word_tokenize(text.lower())
    words = [lemmatizer.lemmatize(w) for w in words if w not in stop_words and len(w) > 2]
    return " ".join(words)

def keyword_flag(text):
    text = text.lower()
    return int(any(kw in text for kw in phishing_keywords))

def extract_links(text):
    return re.findall(r'http[s]?://\S+', text)

def check_virustotal(url):
    headers = {"x-apikey": VT_API_KEY}
    url_id = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
    if url_id.status_code == 200:
        analysis_id = url_id.json()["data"]["id"]
        report = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
        if report.status_code == 200:
            return report.json()["data"]["attributes"]["stats"]
    return None

def extract_text_from_pdf(uploaded_file):
    doc = fitz.open(stream=uploaded_file.read(), filetype="pdf")
    return "".join(page.get_text() for page in doc)

# === Main prediction logic ===
def predict_email(email_text):
    cleaned = clean_email(email_text)
    vector = vectorizer.transform([cleaned]).toarray()
    keyword = keyword_flag(email_text)
    final_input = np.hstack((vector, np.array([[keyword]])))
    proba = model.predict_proba(final_input)[0]
    label = model.predict(final_input)[0]
    result = "⚠️ Phishing" if label == 1 else "✅ Legitimate"
    keywords_found = [kw for kw in phishing_keywords if kw in email_text.lower()]
    
    # VirusTotal link check
    links = extract_links(email_text)
    vt_reports = {}
    for link in links:
        try:
            stats = check_virustotal(link)
            if stats:
                vt_reports[link] = stats
            else:
                vt_reports[link] = "No result from VirusTotal"
        except:
            vt_reports[link] = "Error contacting VirusTotal"

    return result, f"{max(proba)*100:.2f}%", ", ".join(keywords_found) if keywords_found else "None", vt_reports

# === Flask Routes ===
@app.route("/", methods=["GET", "POST"])
def index():
    result = confidence = keywords = ""
    vt_reports = {}
    if request.method == "POST":
        email_text = ""

        if "email_text" in request.form and request.form["email_text"].strip():
            email_text = request.form["email_text"]
        elif "file" in request.files:
            uploaded_file = request.files["file"]
            if uploaded_file.filename.endswith(".txt"):
                email_text = uploaded_file.read().decode("utf-8")
            elif uploaded_file.filename.endswith(".pdf"):
                email_text = extract_text_from_pdf(uploaded_file)

        if email_text.strip():
            result, confidence, keywords, vt_reports = predict_email(email_text)

    return render_template("index.html", result=result, confidence=confidence, keywords=keywords, vt_reports=vt_reports)

if __name__ == "__main__":
    app.run(debug=True)