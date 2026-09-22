import base64
from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build


SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

BASE_DIR = Path(__file__).resolve().parent
CREDENTIALS_FILE = BASE_DIR / "credentials.json"
TOKEN_FILE = BASE_DIR / "token.json"


def get_gmail_service():
    creds = None

    if TOKEN_FILE.exists():
        creds = Credentials.from_authorized_user_file(
            TOKEN_FILE,
            SCOPES,
        )

    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())

    if not creds or not creds.valid:
        if not CREDENTIALS_FILE.exists():
            raise FileNotFoundError(
                "credentials.json not found. "
                "Download the OAuth Desktop App credentials "
                "from Google Cloud and place them in the project root."
            )

        flow = InstalledAppFlow.from_client_secrets_file(
            CREDENTIALS_FILE,
            SCOPES,
        )

        creds = flow.run_local_server(
            host="127.0.0.1",
            bind_addr="127.0.0.1",
            port=8080,
        )

        TOKEN_FILE.write_text(creds.to_json())

    return build("gmail", "v1", credentials=creds)


def decode_body(payload):
    """
    Extract the plain-text body from a Gmail message payload.
    """

    if "body" in payload and payload["body"].get("data"):
        data = payload["body"]["data"]

        return base64.urlsafe_b64decode(
            data.encode("UTF-8")
        ).decode("UTF-8", errors="replace")

    for part in payload.get("parts", []):
        if part.get("mimeType") == "text/plain":
            data = part.get("body", {}).get("data")

            if data:
                return base64.urlsafe_b64decode(
                    data.encode("UTF-8")
                ).decode("UTF-8", errors="replace")

        # Handle nested multipart messages
        if part.get("parts"):
            body = decode_body(part)

            if body:
                return body

    return ""


def get_message(message_id):
    """
    Fetch one Gmail message and return it in Agent Jail's format.
    """

    service = get_gmail_service()

    message = (
        service.users()
        .messages()
        .get(
            userId="me",
            id=message_id,
            format="full",
        )
        .execute()
    )

    headers = message.get("payload", {}).get("headers", [])

    sender = ""
    subject = ""

    for header in headers:
        name = header["name"].lower()

        if name == "from":
            sender = header["value"]

        elif name == "subject":
            subject = header["value"]

    body = decode_body(message.get("payload", {}))

    return {
        "id": message["id"],
        "sender": sender,
        "subject": subject,
        "body": body,
    }


def list_messages(max_results=10):
    """
    Retrieve recent Gmail messages.
    """

    service = get_gmail_service()

    response = (
        service.users()
        .messages()
        .list(
            userId="me",
            maxResults=max_results,
        )
        .execute()
    )

    return response.get("messages", [])


def get_emails(max_results=10):
    """
    Retrieve recent Gmail messages in Agent Jail's email format.
    """

    messages = list_messages(max_results=max_results)

    emails = []

    for message in messages:
        email = get_message(message["id"])
        emails.append(email)

    return emails


if __name__ == "__main__":
    print("Connecting to Gmail...")

    emails = get_emails()

    print(f"Found {len(emails)} messages.\n")

    for email in emails:
        print("=" * 60)
        print(f"ID:      {email['id']}")
        print(f"From:    {email['sender']}")
        print(f"Subject: {email['subject']}")
        print("Body:")
        print(email["body"])
        print()