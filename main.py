from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import re
import whois
import dns.resolver
import requests
from urllib.parse import urlparse
from datetime import datetime
import numpy as np
from tensorflow.keras.models import load_model
import dns.resolver
from dns.resolver import NoNameservers
from dns.resolver import NXDOMAIN, LifetimeTimeout
import time
app = Flask(__name__)
CORS(app)

@app.route('/')
def home():
    return render_template('index.html', prediction=None)

@app.route('/predict_with_features', methods=['POST'])
def predict_with_features():
    # Measure total process time
    start_total_process = time.time()

    # Receive URLs from request
    data = request.get_json()
    urls = data['urls']

    # Load model

    predictions = []
    for url in urls:
        # Measure time for extracting features
        start_feature_extraction = time.time()
        features = extract_features(url)
        end_feature_extraction = time.time()
        print(features)
        # Measure time for model prediction
        start_prediction = time.time()
        ordered_features = [features[feature] for feature in features]
        model = load_model('model.h5')
        prediction = predict_phishing(ordered_features, model)
        end_prediction = time.time()

        # Calculate times
        feature_extraction_time = end_feature_extraction - start_feature_extraction
        prediction_time = end_prediction - start_prediction

        # Print times
        print(f"Feature extraction time for {url}: {feature_extraction_time} seconds")
        print(f"Prediction time for {url}: {prediction_time} seconds")

        predictions.append({
            'url': url,
            'phishing': bool(prediction),
            'features': features,
            'feature_extraction_time': feature_extraction_time,
            'prediction_time': prediction_time
        })

    # Measure end time for total process
    end_total_process = time.time()
    total_process_time = end_total_process - start_total_process

    # Print total process time
    print(f"Total process time: {total_process_time} seconds")

    # Create and return the response
    response = jsonify(predictions)
    return response



@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Receive URLs from request
        data = request.get_json()
        urls = data['urls']

        # Extract features from the URLs
        model = load_model('model.h5')
        predictions = []
        i = 0
        for url in urls:
            print(url)
            i = i + 1
            features = extract_features(url)
            ordered_features = [features[feature] for feature in features]
            prediction = predict_phishing(ordered_features, model)
            predictions.append({'url': url, 'phishing': bool(prediction)})


        print(predictions)
        response = jsonify(predictions)
        return response

    except Exception as e:
        print('Error predicting batch:', e)
        return jsonify([])


def extract_features(url):
    # Extract features from the URL
    url_data = start_url(url)
    features = {
        "qty_slash_url": qty_slash_url(url),
        "time_domain_activation": time_domain_activation(url_data),
        "length_url": length_url(url),
        "qty_mx_servers": qty_mx_servers(url_data),
        "qty_dot_directory": qty_dot_directory(url),
        "qty_dot_domain": qty_dot_domain(url),
        "url_shortened": url_shortened(url_data, 'shorteners.txt'),
        "directory_length": directory_length(url),
        "file_length": file_length(url),
        "tls_ssl_certificate": tls_ssl_certificate(url),
        "qty_nameservers": qty_nameservers(url_data),
        "qty_at_params": count(url_data['query'], '@'),
        "qty_ip_resolved": count_ips(url_data),
        "tld_present_params": tld_present_params(url_data['query'])
    }

    # Define the order of features
    feature_order = [
        "qty_slash_url",
        "time_domain_activation",
        "length_url",
        "qty_mx_servers",
        "qty_dot_directory",
        "qty_dot_domain",
        "url_shortened",
        "directory_length",
        "file_length",
        "tls_ssl_certificate",
        "qty_nameservers",
        "qty_at_params",
        "qty_ip_resolved",
        "tld_present_params"
    ]

    # Return features in the specified order
    ordered_features = {feature: features[feature] for feature in feature_order}
    return ordered_features


import ipaddress

def valid_ip(host):
    """Return if the domain has a valid IP format (IPv4 or IPv6)."""
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False

def length_url(url):
    return len(url)

def start_url(url):
    """Split URL into: protocol, host, path, params, query and fragment."""
    try:
        if not urlparse(url.strip()).scheme:
            url = 'http://' + url
        protocol, host, path, params, query, fragment = urlparse(url.strip())

        result = {
            'url': host + path + params + query + fragment,
            'protocol': protocol,
            'host': host,
            'path': path,
            'params': params,
            'query': query,
            'fragment': fragment
        }
        return result
    except Exception:
        return -1

def qty_slash_url(url):
    """Return the count of slashes in the URL."""
    try:
        return url.count('/')
    except Exception:
        return -1

def time_domain_activation(url):
    """Return the number of days since domain activation."""
    try:
        if url['host'].startswith("www."):
            url['host'] = url['host'][4:]

        result_whois = whois.whois(url['host'].lower())
        if not result_whois:
            return -1
        creation_date = result_whois.creation_date
        if not creation_date:
            return -1
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        d1 = datetime.now()
        if isinstance(creation_date, datetime):
            d1 = creation_date
        elif isinstance(creation_date, str):
            d1 = datetime.strptime(creation_date, "%Y-%m-%d %H:%M:%S")
        d2 = datetime.now()
        return round(abs((d2 - d1).days))
    except Exception:
        return -1

def qty_mx_servers(url):
    """Return the quantity of MX servers for the domain."""
    count = 0
    try:
        if count_ips(url):
            try:
                answers = dns.resolver.resolve(url['host'], 'MX')
                return len(answers)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                split_host = url['host'].split('.')
                while len(split_host) > 0:
                    split_host.pop(0)
                    supposed_domain = '.'.join(split_host)
                    try:
                        answers = dns.resolver.resolve(supposed_domain, 'MX')
                        count = len(answers)
                        break
                    except Exception:
                        count = 0
        return count
    except Exception:
        return -1

def qty_dot_directory(url):
    """Return the quantity of dots in the directory part of the URL."""
    try:
        path = urlparse(url).path
        return path.count('.')
    except Exception:
        return -1

def qty_dot_domain(url):
    """Return the quantity of dots in the domain part of the URL."""
    try:
        domain = urlparse(url).netloc
        return domain.count('.')
    except Exception:
        return -1

def url_shortened(url, file_path):
    """Check if the URL is shortened."""
    try:
        with open(file_path, 'r') as file:
            for line in file:
                with_www = "www." + line.strip()
                if line.strip() == url['host'].lower() or with_www == url['host'].lower():
                    return 1
        return 0
    except Exception:
        return -1

def directory_length(url):
    """Return the length of the directory part of the URL."""
    try:
        path = urlparse(url).path
        return len(path.split('/'))
    except Exception:
        return -1

def file_length(url):
    """Return the length of the file in the URL."""
    try:
        path = urlparse(url).path
        filename = path.split('/')[-1]
        return len(filename)
    except Exception:
        return -1

def tls_ssl_certificate(url):
    """Check if the SSL certificate is valid."""
    try:
        requests.get(url, verify=True, timeout=3)
        return 1
    except Exception:
        return 0

def qty_nameservers(url_components):
    """Return the quantity of nameservers for the domain."""
    count = 0
    try:
        if count_ips(url_components):
            try:
                answers = dns.resolver.resolve(url_components['host'], 'NS')
                return len(answers)
            except dns.resolver.NoAnswer:
                split_host = url_components['host'].split('.')
                while len(split_host) > 0:
                    split_host.pop(0)
                    supposed_domain = '.'.join(split_host)
                    try:
                        answers = dns.resolver.resolve(supposed_domain, 'NS')
                        count = len(answers)
                        break
                    except Exception:
                        count = 0
        return count
    except Exception:
        return -1

def count(text, character):
    """Return the count of a certain character in the text."""
    try:
        return text.count(character)
    except Exception:
        return -1

def count_ips(url):
    """Return the number of resolved IPs (IPv4)."""
    try:
        if valid_ip(url['host']):
            return 1

        answers = dns.resolver.resolve(url['host'], 'A')
        return len(answers)
    except Exception:
        return -1

def tld_present_params(text):
    """Check if the TLD is present in the URL parameters."""
    try:
        # Open the TLD file locally
        file_path = "tlds.txt"
        with open(file_path, 'r') as file:
            lines = file.readlines()

        pattern = re.compile("[a-zA-Z0-9.]")

        # Process the lines from the file
        for line in lines:
            i = (text.lower().strip()).find(line.strip())
            while i > -1:
                # Check if the query part of the text is found in the TLD file
                if ((i + len(line) - 1) >= len(text)) or not pattern.match(text[i + len(line) - 1]):
                    return 1
                i = text.find(line.strip(), i + 1)

        return 0
    except Exception:
        return -1

def qty_at_url(url):
    """Return the count of '@' in the URL."""
    try:
        return url.count('@')
    except Exception:
        return -1

def count_vowels(text):
    """Return the count of vowels in the text."""
    try:
        vowels = ['a', 'e', 'i', 'o', 'u']
        count = 0
        for i in vowels:
            count += text.lower().count(i)
        return count
    except Exception:
        return -1


def predict_phishing(features, model):
    mean_values = [1.937522, 3737.372619, 44.959297, 1.630113, 0.457412, 1.799540, 0.008287, 24.551777, 7.067383,
                   0.501373, 2.829619, 0.215306, 1.250545, 0.293048]
    min_values = [0.0, 1.0, 4.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0]
    max_values = [44, 17775, 4165, 20, 19, 21, 1, 1286, 1232, 1, 16, 10, 24, 1]

    # Replace missing values with mean_values
    for idx, val in enumerate(features):
        if val == -1:
            features[idx] = mean_values[idx]

    # Scale the features using min-max scaling
    scaled_features = [(val - min_val) / (max_val - min_val) for val, min_val, max_val in zip(features, min_values, max_values)]

    # Make predictions using the loaded model
    predictions = model.predict(np.array(scaled_features).reshape(1, -1))  # Reshape to match the input shape expected by the model

    # Apply threshold for binary classification
    threshold = 0.5
    predicted_class = (predictions > threshold).astype(int)

    # Convert the prediction to boolean
    return bool(predicted_class)


if __name__ == '__main__':
    app.run(host='0.0.0.0',port=5000, debug=True)

