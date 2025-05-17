# PhishScan – AI-Based Phishing Email Detection and URL Intelligence

PhishScan is an AI-powered phishing email detection system that leverages machine learning, natural language processing (NLP), and real-time URL threat intelligence via the VirusTotal API. It is designed as a lightweight forensic and educational tool to classify emails as phishing or legitimate and to analyze embedded URLs for malicious content.

This project was developed as part of the SIT326 – Advanced Network Analytics and Forensics (High Distinction Task).

---

## Key Features

- Email classification using a trained Random Forest model
- Text preprocessing using tokenization, lemmatization, and TF-IDF vectorization
- Keyword flagging of common phishing indicators (e.g., “verify account”, “reset password”)
- Real-time URL scanning via the VirusTotal Public API
- Supports pasted text and file uploads (.txt or .pdf)
- Clear and structured user interface built with Flask
- Confidence score, keyword tags, and optional VirusTotal scan summaries

---

## Demo Output Example

```

Scan Results
Prediction: Phishing
Confidence: 54.00%
Detected Keywords: reset your password secure link

VirusTotal Link Scans
[http://000025123.com/banks/desjardins](http://000025123.com/banks/desjardins)
{'malicious': 11, 'suspicious': 0, 'undetected': 29, 'harmless': 57, 'timeout': 0}

````

---

## Installation and Setup

### Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/PhishScan.git
cd PhishScan
````

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run the Application

```bash
python run.py
```

The application will be available locally at `http://127.0.0.1:5000/`.

---

## Project Structure

```
PhishScan/
├── app/
│   ├── templates/         # HTML interface
│   ├── static/            # Static assets (video, CSS)
│   ├── predict_email.py   # Main backend logic
│   ├── utils.py           # Preprocessing and keyword functions
│   ├── vt_utils.py        # VirusTotal API integration
│   ├── model.pkl          # Trained model
│   ├── vectorizer.pkl     # TF-IDF vectorizer
├── notebook/
│   └── phishing_model_training.ipynb
├── test_files/
│   ├── sample_legit.txt
│   └── sample_phish.pdf
├── requirements.txt
├── run.py
└── README.md
```

---

## How It Works

1. Email content is submitted via form or file upload.
2. The email is cleaned using NLP techniques: removal of HTML, tokenization, lemmatization, and stopword filtering.
3. Features are extracted using TF-IDF and a binary keyword flag is appended.
4. The email is classified using a Random Forest model trained on phishing and ham datasets.
5. URLs found in the email are scanned using the VirusTotal API and the results are returned.
6. The results, including classification, confidence score, keyword tags, and URL threat levels, are displayed on the frontend.

---

## Datasets and Resources

* [Kaggle Phishing Emails Dataset](https://www.kaggle.com/datasets/subhajournal/phishingemails)
* [Phishing.Database – GitHub](https://github.com/Phishing-Database/Phishing.Database)
* [VirusTotal API Documentation](https://docs.virustotal.com/reference/overview)

---


## Acknowledgements

* Deakin University – SIT326 unit team
* VirusTotal – for providing public API access
* Kaggle and Apache – for open-source datasets
* The maintainers of Phishing.Database for their valuable threat intelligence contribution

```

Let me know if you'd like this saved as a downloadable `.md` file or prepared for GitHub Pages formatting.
```
