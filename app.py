import os
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # For development only

from flask import Flask, render_template, url_for, request, redirect, session
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
import openai
import base64

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")  # Use environment variable for secret key

# Set up OAuth 2.0 flow
flow = Flow.from_client_secrets_file(
    "credentials.json", scopes=["https://www.googleapis.com/auth/gmail.readonly"]
)
flow.redirect_uri = "http://127.0.0.1:5000/oauth2callback"


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
    credentials = flow.credentials
    session["credentials"] = credentials_to_dict(credentials)
    return redirect("/emails")


@app.route("/emails")
def display_emails():
    if "credentials" not in session:
        return redirect("/")

    credentials = Credentials(**session["credentials"])
    gmail = build("gmail", "v1", credentials=credentials)

    results = gmail.users().messages().list(userId="me", maxResults=10).execute()
    messages = results.get("messages", [])

    emails = []
    for message in messages:
        msg = gmail.users().messages().get(userId="me", id=message["id"]).execute()
        email_content = get_email_content(msg)
        summary = summarize_email(email_content)
        emails.append(
            {
                "subject": get_header(msg, "Subject"),
                "from": get_header(msg, "From"),
                "summary": summary,
            }
        )

    # Combine all email content
    all_email_content = "\n\n".join(
        [f"Subject: {email['subject']}\nFrom: {email['from']}" for email in emails]
    )

    # Generate a single summary for all emails
    summary = generate_summary(all_email_content)

    return render_template("emails.html", summary=summary)


def credentials_to_dict(credentials):
    return {
        "token": credentials.token,
        "refresh_token": credentials.refresh_token,
        "token_uri": credentials.token_uri,
        "client_id": credentials.client_id,
        "client_secret": credentials.client_secret,
        "scopes": credentials.scopes,
    }


def get_header(message, name):
    headers = message["payload"]["headers"]
    return next((header["value"] for header in headers if header["name"] == name), "")


def get_email_content(message):
    parts = message["payload"].get("parts", [])
    body = ""
    if parts:
        for part in parts:
            if part["mimeType"] == "text/plain":
                body = base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8")
                break
    else:
        body = base64.urlsafe_b64decode(message["payload"]["body"]["data"]).decode(
            "utf-8"
        )
    return body[:4000]  # Limit to first 4000 characters


def summarize_email(content):
    openai.api_key = os.getenv("OPENAI_API_KEY")  # Use environment variable for OpenAI API key

    # Truncate content if it's too long
    max_content_length = 12000  # Adjust this value as needed
    if len(content) > max_content_length:
        content = content[:max_content_length] + "..."

    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {
                    "role": "system",
                    "content": "Summarize the key points of this email in 2-3 sentences.",
                },
                {"role": "user", "content": f"Email content:\n\n{content}"},
            ],
            max_tokens=100,
        )
        return response.choices[0].message["content"].strip()
    except openai.error.InvalidRequestError as e:
        print(f"Error summarizing email: {str(e)}")
        return "Unable to summarize this email due to its length."


def generate_summary(content):
    # Set up OpenAI API
    openai.api_key = os.getenv("OPENAI_API_KEY")  # Use environment variable for OpenAI API key

    # Generate summary using GPT-3.5-turbo
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[
            {
                "role": "system",
                "content": "You are a helpful assistant that summarizes emails.",
            },
            {
                "role": "user",
                "content": f"Please provide a concise summary of the following emails:\n\n{content}",
            },
        ],
        max_tokens=150,  # Adjust this value to control the length of the summary
    )

    return response.choices[0].message["content"].strip()


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
