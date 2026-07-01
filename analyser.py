import email
import sys
import re
import requests
import time
import os
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

def load_email(filepath):
    with open(filepath, 'r', errors='ignore') as f:
        msg = email.message_from_file(f)
    return msg

def extract_basic_info(msg):
    print("=== EMAIL BASICS ===")
    print(f"From     : {msg['From']}")
    print(f"Reply-To : {msg['Reply-To']}")
    print(f"Subject  : {msg['Subject']}")
    print(f"Date     : {msg['Date']}")

def check_mismatch(msg):
    from_field = msg['From']
    replyto_field = msg['Reply-To']
    print("\n=== MISMATCH CHECK ===")
    if replyto_field is None:
        print("No Reply-To field - skipping")
        return False
    from_domain = from_field.split("@")[1].lower()
    reply_domain = replyto_field.split("@")[1].lower()
    if from_domain != reply_domain:
        print("MISMATCH DETECTED - possible phishing!")
        return True
    else:
        print("Domains match - looks okay")
        return False

def check_keywords(msg):
    subject = msg['Subject'].lower()
    suspicious = ['urgent', 'immediately', 'suspended', 'verify',
                  'security alert', 'action required', 'account compromised',
                  'invoice attached', 'confirm', 'click here', 'login',
                  'password', 'update payment']
    print("\n=== KEYWORD CHECK ===")
    found = []
    for word in suspicious:
        if word in subject:
            found.append(word)
    if found:
        print(f"Suspicious keywords found: {found}")
    else:
        print("No suspicious keywords found")
    return found

def check_subject_caps(msg):
    subject = msg['Subject']
    print("\n=== CAPS CHECK ===")
    if subject == subject.upper():
        print("Subject is ALL CAPS")
        return True
    print("Subject is not all caps")
    return False

def check_exclamations(msg):
    subject = msg['Subject']
    count = subject.count('!')
    print("\n=== EXCLAMATION CHECK ===")
    print(f"Exclamation marks in subject: {count}")
    return count

def check_attachments(msg):
    print("\n=== ATTACHMENT CHECK ===")
    dangerous = ['.exe', '.zip', '.js', '.docm', '.bat', '.ps1', '.vbs', '.scr']
    found = False
    dangerous_found = False
    for part in msg.walk():
        filename = part.get_filename()
        if filename is not None:
            found = True
            print(f"Attachment found: {filename}")
            for ext in dangerous:
                if filename.lower().endswith(ext):
                    print(f"DANGEROUS FILE TYPE DETECTED: {filename}")
                    dangerous_found = True
    if not found:
        print("No attachments found")
    return dangerous_found

def extract_urls(msg):
    print("\n=== URL EXTRACTION ===")
    urls = []
    for part in msg.walk():
        if part.get_content_type() in ['text/plain', 'text/html']:
            body = part.get_payload(decode=True)
            if body:
                body = body.decode('utf-8', errors='ignore')
                found = re.findall(r'https?://[^\s"\'<>]+', body)
                urls.extend(found)
    if urls:
        for url in urls:
            print(f"URL: {url}")
    else:
        print("No URLs found")
    return urls

def check_url_features(urls):
    print("\n=== URL FEATURE CHECK ===")
    shorteners = ['t.ly', 'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly']
    suspicious_tlds = ['.ru', '.xyz', '.top', '.tk', '.pw', '.cc']
    shortener_found = False
    http_found = False
    suspicious_tld_found = False
    for url in urls:
        if any(s in url for s in shorteners):
            print(f"URL shortener detected: {url}")
            shortener_found = True
        if url.startswith('http://'):
            print(f"HTTP (not HTTPS) URL: {url}")
            http_found = True
        if any(tld in url for tld in suspicious_tlds):
            print(f"Suspicious TLD detected: {url}")
            suspicious_tld_found = True
    if not shortener_found and not http_found and not suspicious_tld_found:
        print("No suspicious URL features found")
    return shortener_found, http_found, suspicious_tld_found

def check_message_id(msg):
    print("\n=== MESSAGE-ID CHECK ===")
    message_id = msg['Message-ID']
    if message_id is None:
        print("Missing Message-ID - red flag")
        return True
    print(f"Message-ID present: {message_id}")
    return False

def check_url_virustotal(url):
    print(f"\nChecking VT: {url}")
    headers = {"x-apikey": VT_API_KEY}
    params = {"url": url}
    response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data=params
    )
    if response.status_code == 200:
        analysis_id = response.json()['data']['id']
        time.sleep(15)
        result = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers
        )
        stats = result.json()['data']['attributes']['stats']
        malicious = stats['malicious']
        harmless = stats['harmless']
        print(f"Malicious: {malicious} | Harmless: {harmless}")
        return malicious
    else:
        print("Something went wrong with VT check")
        return 0

def check_received_headers(msg):
    print("\n=== RECEIVED HEADERS ===")
    headers = msg.get_all('Received')
    if headers is None:
        print("No Received headers found")
    else:
        for header in headers:
            print(f"  {header}")

def calculate_score(mismatch, keywords, all_caps, exclamations,
                    dangerous_attachment, shortener, http_url,
                    suspicious_tld, missing_message_id, total_malicious_urls):
    score = 0
    print("\n=== SCORE BREAKDOWN ===")

    if mismatch:
        print("Mismatch detected: +10")
        score += 10
    if len(keywords) == 1:
        print(f"1 keyword found: +5")
        score += 5
    if len(keywords) > 1:
        print(f"Multiple keywords found: +10")
        score += 10
    if all_caps:
        print("ALL CAPS subject: +5")
        score += 5
    if exclamations > 1:
        print(f"Multiple exclamation marks: +5")
        score += 5
    if dangerous_attachment:
        print("Dangerous attachment: +30")
        score += 30
    if shortener:
        print("URL shortener detected: +10")
        score += 10
    if http_url:
        print("HTTP URL detected: +5")
        score += 5
    if suspicious_tld:
        print("Suspicious TLD detected: +10")
        score += 10
    if missing_message_id:
        print("Missing Message-ID: +5")
        score += 5
    if total_malicious_urls > 0:
        pts = total_malicious_urls * 20
        print(f"Malicious URLs ({total_malicious_urls}): +{pts}")
        score += pts

    score = min(score, 100)

    print(f"\n=== PHISHING CONFIDENCE SCORE: {score}/100 ===")

    if score <= 20:
        print("Verdict: LEGITIMATE")
    elif score <= 40:
        print("Verdict: SUSPICIOUS")
    elif score <= 70:
        print("Verdict: LIKELY PHISHING")
    else:
        print("Verdict: HIGH CONFIDENCE PHISHING")

    return score

if __name__ == "__main__":
    filepath = sys.argv[1]
    msg = load_email(filepath)

    extract_basic_info(msg)
    mismatch = check_mismatch(msg)
    keywords = check_keywords(msg)
    all_caps = check_subject_caps(msg)
    exclamations = check_exclamations(msg)
    dangerous_attachment = check_attachments(msg)
    urls = extract_urls(msg)
    shortener, http_url, suspicious_tld = check_url_features(urls)
    missing_message_id = check_message_id(msg)
    check_received_headers(msg)

    total_malicious = 0
    for url in urls:
        total_malicious += check_url_virustotal(url)
        time.sleep(15)

    calculate_score(mismatch, keywords, all_caps, exclamations,
                    dangerous_attachment, shortener, http_url,
                    suspicious_tld, missing_message_id, total_malicious)
