import re
import pandas as pd
from urllib.parse import urlparse
from tld import get_tld
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import LabelEncoder
import joblib
import xgboost as xgb
from lightgbm import LGBMClassifier
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

# Load your dataset into a DataFrame
df = pd.read_csv('malicious_phish.csv')
feedback_data = pd.read_csv('feedback.csv')


df = pd.concat([df, feedback_data])

# Feature extraction functions
def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
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
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net', url)
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
    match = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr', url)
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

feedback_data['use_of_ip'] = feedback_data['url'].apply(lambda i: having_ip_address(i))
feedback_data['abnormal_url'] = feedback_data['url'].apply(lambda i: abnormal_url(i))
feedback_data['count.'] = feedback_data['url'].apply(lambda i: count_dot(i))
feedback_data['count-www'] = feedback_data['url'].apply(lambda i: count_www(i))
feedback_data['count@'] = feedback_data['url'].apply(lambda i: count_atrate(i))
feedback_data['count_dir'] = feedback_data['url'].apply(lambda i: no_of_dir(i))
feedback_data['count_embed_domian'] = feedback_data['url'].apply(lambda i: no_of_embed(i))
feedback_data['short_url'] = feedback_data['url'].apply(lambda i: shortening_service(i))
feedback_data['count-https'] = feedback_data['url'].apply(lambda i : count_https(i))
feedback_data['count-http'] = feedback_data['url'].apply(lambda i : count_http(i))
feedback_data['count%'] = feedback_data['url'].apply(lambda i : count_per(i))
feedback_data['count?'] = feedback_data['url'].apply(lambda i: count_ques(i))
feedback_data['count-'] = feedback_data['url'].apply(lambda i: count_hyphen(i))
feedback_data['count='] = feedback_data['url'].apply(lambda i: count_equal(i))
feedback_data['url_length'] = feedback_data['url'].apply(lambda i: url_length(i))
feedback_data['hostname_length'] = feedback_data['url'].apply(lambda i: hostname_length(i))
feedback_data['sus_url'] = feedback_data['url'].apply(lambda i: suspicious_words(i))
feedback_data['count-digits'] = feedback_data['url'].apply(lambda i: digit_count(i))
feedback_data['count-letters'] = feedback_data['url'].apply(lambda i: letter_count(i))
feedback_data['fd_length'] = feedback_data['url'].apply(lambda i: fd_length(i))
feedback_data['tld'] = feedback_data['url'].apply(lambda i: get_tld(i,fail_silently=True))
feedback_data['tld_length'] = feedback_data['tld'].apply(lambda i: tld_length(i))


# Feature extraction
df['use_of_ip'] = df['url'].apply(having_ip_address)
df['abnormal_url'] = df['url'].apply(abnormal_url)
df['count.'] = df['url'].apply(count_dot)
df['count-www'] = df['url'].apply(count_www)
df['count@'] = df['url'].apply(count_atrate)
df['count_dir'] = df['url'].apply(no_of_dir)
df['count_embed_domian'] = df['url'].apply(no_of_embed)
df['short_url'] = df['url'].apply(shortening_service)
df['count-https'] = df['url'].apply(count_https)
df['count-http'] = df['url'].apply(count_http)
df['count%'] = df['url'].apply(count_per)
df['count?'] = df['url'].apply(count_ques)
df['count-'] = df['url'].apply(count_hyphen)
df['count='] = df['url'].apply(count_equal)
df['url_length'] = df['url'].apply(url_length)
df['hostname_length'] = df['url'].apply(hostname_length)
df['sus_url'] = df['url'].apply(suspicious_words)
df['count-digits'] = df['url'].apply(digit_count)
df['count-letters'] = df['url'].apply(letter_count)
df['fd_length'] = df['url'].apply(fd_length)
df['tld'] = df['url'].apply(lambda i: get_tld(i, fail_silently=True))
df['tld_length'] = df['tld'].apply(tld_length)
df = df.drop("tld", axis=1)

# Encode target labels
lb_make = LabelEncoder()
df["type_code"] = lb_make.fit_transform(df["type"])

# Define features and target
X = df[['use_of_ip', 'abnormal_url', 'count.', 'count-www', 'count@',
       'count_dir', 'count_embed_domian', 'short_url', 'count-https',
       'count-http', 'count%', 'count?', 'count-', 'count=', 'url_length',
       'hostname_length', 'sus_url', 'fd_length', 'tld_length', 'count-digits',
       'count-letters']]
y = df['type_code']

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, shuffle=True, random_state=5)

# Function to train and evaluate a model
def train_and_evaluate_model(model, model_name, X_train, y_train, X_test, y_test, target_names, labels):
    # Fit the model to the training data
    model.fit(X_train, y_train)
    
    # Predict the labels for the test set
    y_pred = model.predict(X_test)
    
    # Print the classification report with specified target names and labels
    print(f"Classification Report for {model_name}:\n")
    print(classification_report(y_test, y_pred, target_names=target_names, labels=labels))
    
    # Calculate and print the accuracy score
    score = accuracy_score(y_test, y_pred)
    print(f"Accuracy for {model_name}: {score:.3f}\n")
    print("-" * 50)
    
    # Save the trained model
    joblib.dump(model, f'{model_name.lower().replace(" ", "_")}_model.pkl')

# Define the target names and corresponding labels
target_names = ['benign', 'defacement', 'phishing', 'malware']
labels = [0, 1, 2, 3]  # Assuming 0: benign, 1: defacement, 2: phishing, 3: malware

# Train and evaluate Random Forest model
rf_model = RandomForestClassifier(n_estimators=100, max_features='sqrt')
train_and_evaluate_model(rf_model, "Random Forest", X_train, y_train, X_test, y_test, target_names, labels)

# Train and evaluate XGBoost model
xgb_model = xgb.XGBClassifier(n_estimators=100)
train_and_evaluate_model(xgb_model,"XGBoost",X_train,y_train,X_test,y_test,target_names,labels)

# Train and evaluate LightGBM model
lgb_model = LGBMClassifier(objective='multiclass', boosting_type='gbdt', n_jobs=5, silent=True, random_state=42)
train_and_evaluate_model(lgb_model, "LightGBM", X_train, y_train, X_test, y_test, target_names, labels)

# Function to extract features from a single URL
def extract_features(url):
    features = [
        having_ip_address(url),
        abnormal_url(url),
        count_dot(url),
        count_www(url),
        count_atrate(url),
        no_of_dir(url),
        no_of_embed(url),
        shortening_service(url),
        count_https(url),
        count_http(url),
        count_per(url),
        count_ques(url),
        count_hyphen(url),
        count_equal(url),
        url_length(url),
        hostname_length(url),
        suspicious_words(url),
        fd_length(url),
        tld_length(get_tld(url, fail_silently=True)),
        digit_count(url),
        letter_count(url)
    ]
    return features

# Function to get prediction from a URL using a specified model
def get_prediction_from_url(test_url, model):
    features_test = extract_features(test_url)
    features_test = np.array(features_test).reshape((1, -1))
    pred = model.predict(features_test)
    return target_names[int(pred[0])]

