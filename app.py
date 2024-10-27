import os
from functools import wraps
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, session
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
import openai
import base64
from cachetools import TTLCache

# Load environment variables and configure settings
load_dotenv()
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")
openai.api_key = os.getenv("OPENAI_API_KEY")

# Set up OAuth 2.0 flow
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
flow = Flow.from_client_secrets_file("credentials.json", scopes=SCOPES)
flow.redirect_uri = "http://127.0.0.1:5000/oauth2callback"

# Cache setup
email_cache = TTLCache(maxsize=100, ttl=300)  # Cache 100 emails for 5 minutes

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'credentials' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

@app.route("/")
def index():
    return render_template("login.html")

@app.route("/login")
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@app.route("/oauth2callback")
def oauth2callback():
    flow.fetch_token(authorization_response=request.url)
    session["credentials"] = credentials_to_dict(flow.credentials)
    return redirect("/emails")

@app.route("/emails")
@login_required
def display_emails():
    gmail = get_gmail_service()
    results = gmail.users().messages().list(userId="me", maxResults=10).execute()
    messages = results.get("messages", [])

    emails = []
    for message in messages:
        email_id = message["id"]
        if email_id in email_cache:
            emails.append(email_cache[email_id])
        else:
            msg = gmail.users().messages().get(userId="me", id=email_id).execute()
            email_content = get_email_content(msg)
            summary = summarize_email(email_content)
            category = categorize_email(email_content)
            sent_time = get_sent_time(msg)
            spooky = category in ["Work", "Education"]
            email_data = {
                "subject": summary,
                "from": get_header(msg, "From"),
                "id": email_id,
                "category": category,
                "sent_time": sent_time,
                "spooky": spooky,  # Add the spooky key
            }
            email_cache[email_id] = email_data
            emails.append(email_data)

    return render_template("emails.html", emails=emails)

@app.route("/email/<email_id>")
@login_required
def view_email(email_id):
    gmail = get_gmail_service()
    msg = gmail.users().messages().get(userId="me", id=email_id).execute()
    email_content = get_email_content(msg)

    email = {
        "subject": get_header(msg, "Subject"),
        "from": get_header(msg, "From"),
        "content": email_content,
    }

    return render_template("email_view.html", email=email)

def credentials_to_dict(credentials):
    return {
        "token": credentials.token,
        "refresh_token": credentials.refresh_token,
        "token_uri": credentials.token_uri,
        "client_id": credentials.client_id,
        "client_secret": credentials.client_secret,
        "scopes": credentials.scopes,
    }

def get_gmail_service():
    credentials = Credentials(**session["credentials"])
    return build("gmail", "v1", credentials=credentials)

def get_header(message, name):
    return next((header["value"] for header in message["payload"]["headers"] if header["name"] == name), "")

def get_email_content(message):
    parts = message["payload"].get("parts", [])
    
    if parts:
        for part in parts:
            if part["mimeType"] == "text/plain":
                return base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8")[:4000]
    
    return base64.urlsafe_b64decode(message["payload"]["body"]["data"]).decode("utf-8")[:4000]

def summarize_email(content, max_tokens=20):
    instruction = "Summarize the main topic of this email in 8 words or less, as if it were a concise email subject."
    content = content[:8000] + "..." if len(content) > 8000 else content

    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": instruction},
                {"role": "user", "content": f"Email content:\n\n{content}"},
            ],
            max_tokens=max_tokens,
            temperature=0.7,
        )
        return response.choices[0].message["content"].strip()
    except openai.error.InvalidRequestError as e:
        print(f"Error summarizing email: {str(e)}")
        words = content.split()
        return ' '.join(words[:8]) + "..." if len(words) > 8 else ' '.join(words)

def categorize_email(content):
    instruction = "Categorize this email as exactly one of the following: 'Advertisement', 'Work', 'Entertainment', 'Education', or 'Personal'. Use only these exact words."
    content = content[:8000] + "..." if len(content) > 8000 else content

    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": instruction},
                {"role": "user", "content": f"Email content:\n\n{content}"},
            ],
            max_tokens=15,
            temperature=0.3,
        )
        category = response.choices[0].message["content"].strip()
        
        # Ensure the category is one of the specified options
        valid_categories = ["Advertisement", "Work", "Entertainment", "Education", "Personal"]
        if category not in valid_categories:
            return "Personal"  # Default to Personal if the API returns an invalid category
        
        return category
    except openai.error.InvalidRequestError as e:
        print(f"Error categorizing email: {str(e)}")
        return "Personal"  # Default to Personal in case of an error

def get_sent_time(message):
    sent_time = get_header(message, "Date")
    return sent_time

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
