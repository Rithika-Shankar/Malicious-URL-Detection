from flask import Flask, request, jsonify, render_template
import joblib
import pandas as pd
from urllib.parse import urlparse
import re
from tld import get_tld
from datetime import timedelta
import os
import subprocess

# Create Flask app
app = Flask(__name__)

# Load the trained models
lgb_model = joblib.load('lightgbm_model.pkl')
xgb_model = joblib.load('xgboost_model.pkl')
rf_model = joblib.load('random_forest_model.pkl')

# Define routes for serving HTML pages
@app.route('/')
def index():
    return render_template('index.html')

# API endpoint for URL analysis
@app.route('/api/analyze', methods=['POST'])
def analyze_urls():
    urls = request.form.get('urls')

    if not urls:
        return jsonify({'error': 'Missing URLs parameter'}), 400

    urls = [url.strip() for url in urls.split(',') if url.strip()]  # Split and clean URLs

    results = []

    for url in urls:
        features = extract_features(url)
        features_df = pd.DataFrame([features])

        # Predict probabilities using your models (e.g., LGBM, XGB, RandomForest)
        prob_lgb = lgb_model.predict_proba(features_df)[0][1]
        prob_xgb = xgb_model.predict_proba(features_df)[0][1]
        prob_rf = rf_model.predict_proba(features_df)[0][1]

        # Aggregate predictions (example: using the average)
        aggregated_prediction = (prob_lgb + prob_xgb + prob_rf) / 3

        # Determine safety assessment
        if aggregated_prediction < 0.5:
            safety = 'Safe'
        else:
            safety = 'Malicious'

        # Prepare explanation for malicious prediction
        if safety == 'Malicious':
            explanation = explain_malicious_prediction(features)
        else:
            explanation = "No specific features indicate malicious intent."

        results.append({
            'url': url,
            'prediction': safety,
            'probability': f"{aggregated_prediction:.2f}",
            'explanation': explanation,
            'features': features
        })

    # Handling feedback submission
    feedback = request.form.get('feedback')
    if feedback == 'incorrect':
        try:
            write_to_csv(url, feedback)
            subprocess.run(['python', 'retrain_model.py'], check=True)
            print("Retraining script executed successfully.")
        except subprocess.CalledProcessError as e:
            print(f"Error executing retraining script: {e}")
            # Handle the error as needed  # Call retrain_model function if feedback is 'incorrect'
    elif feedback:
        write_to_csv(url, feedback)

    return jsonify({'results': results})

def write_to_csv(url, feedback):
    feedback_data = {'URL': url, 'Feedback': feedback}
    df = pd.DataFrame([feedback_data])
    if not os.path.exists('feedback.csv'):
        df.to_csv('feedback.csv', index=False)
    else:
        df.to_csv('feedback.csv', mode='a', header=False, index=False)

@app.route('/')

@app.route('/api/analyze', methods=['POST'])
def submit_feedback():
    data = request.json

    if not data or 'url' not in data or 'feedback' not in data:
        return jsonify({'error': 'Invalid feedback data format'}), 400

    feedback_data = {
        'url': data['url'],
        'feedback': data['feedback']
    }

    try:
        if save_feedback_to_csv(feedback_data):
            return jsonify({"status": "success", "message": "Feedback received and saved"}), 200
        else:
            return jsonify({"status": "error", "message": "Failed to save feedback"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    



# Function to extract features from a URL
def extract_features(url):
    def having_ip_address(url):
        match = re.search(
            r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.'
            r'([01]?\d\d?|2[0-4]\d|25[0-5])\/)|'  # IPv4
            r'((0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\/)' # IPv4 in hexadecimal
            r'(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # IPv6
        return 1 if match else 0

    def abnormal_url(url):
        hostname = urlparse(url).hostname
        hostname = str(hostname)
        match = re.search(hostname, url)
        return 1 if match else 0

    def count_dot(url):
        return url.count('.')

    def count_www(url):
        return url.count('www')

    def count_atrate(url):
        return url.count('@')

    def no_of_dir(url):
        urldir = urlparse(url).path
        return urldir.count('/')

    def no_of_embed(url):
        urldir = urlparse(url).path
        return urldir.count('//')

    def shortening_service(url):
        match = re.search(r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                          r'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                          r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                          r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                          r'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                          r'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                          r'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                          r'tr\.im|link\.zip\.net', url)
        return 1 if match else 0

    def count_https(url):
        return url.count('https')

    def count_http(url):
        return url.count('http')

    def count_per(url):
        return url.count('%')

    def count_ques(url):
        return url.count('?')

    def count_hyphen(url):
        return url.count('-')

    def count_equal(url):
        return url.count('=')

    def url_length(url):
        return len(str(url))

    def hostname_length(url):
        return len(urlparse(url).netloc)

    def suspicious_words(url):
        match = re.search(r'PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr', url)
        return 1 if match else 0

    def digit_count(url):
        return sum(1 for i in url if i.isnumeric())

    def letter_count(url):
        return sum(1 for i in url if i.isalpha())

    def fd_length(url):
        urlpath = urlparse(url).path
        try:
            return len(urlpath.split('/')[1])
        except IndexError:
            return 0

    def tld_length(tld):
        try:
            return len(tld)
        except TypeError:
            return -1

    features = {
        'use_of_ip': having_ip_address(url),
        'abnormal_url': abnormal_url(url),
        'count.': count_dot(url),
        'count-www': count_www(url),
        'count@': count_atrate(url),
        'count_dir': no_of_dir(url),
        'count_embed_domian': no_of_embed(url),
        'short_url': shortening_service(url),
        'count-https': count_https(url),
        'count-http': count_http(url),
        'count%': count_per(url),
        'count?': count_ques(url),
        'count-': count_hyphen(url),
        'count=': count_equal(url),
        'url_length': url_length(url),
        'hostname_length': hostname_length(url),
        'sus_url': suspicious_words(url),
        'fd_length': fd_length(url),
        'tld_length': tld_length(get_tld(url, fail_silently=True)),
        'count-digits': digit_count(url),
        'count-letters': letter_count(url),
    }

    return features


# Function to explain why a URL is predicted as malicious
def explain_malicious_prediction(features):
    explanation = ""
    for feature, value in features.items():
        if value == 1:
            explanation += f"- Feature '{feature}' indicates malicious behavior.\n"
    return explanation.strip()

if __name__ == '__main__':
    app.run(debug=True)
