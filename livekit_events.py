import json
import os
import uuid

from dotenv import load_dotenv
from livekit import api, rtc


load_dotenv()

LIVEKIT_URL = os.getenv("LIVEKIT_URL")
LIVEKIT_API_KEY = os.getenv("LIVEKIT_API_KEY")
LIVEKIT_API_SECRET = os.getenv("LIVEKIT_API_SECRET")

ROOM_NAME = "agent-jail-security"


def create_security_token(identity: str) -> str:
    """Create a LiveKit token for a backend publisher."""
    token = (
        api.AccessToken(LIVEKIT_API_KEY, LIVEKIT_API_SECRET)
        .with_identity(identity)
        .with_grants(
            api.VideoGrants(
                room_join=True,
                room=ROOM_NAME,
                can_publish=True,
                can_subscribe=True,
            )
        )
    )

    return token.to_jwt()


async def publish_security_event(event_type: str, data: dict):
    """
    Publish an Agent Jail security event to LiveKit.
    """

    if not LIVEKIT_URL:
        raise RuntimeError("LIVEKIT_URL is missing from .env")

    if not LIVEKIT_API_KEY:
        raise RuntimeError("LIVEKIT_API_KEY is missing from .env")

    if not LIVEKIT_API_SECRET:
        raise RuntimeError("LIVEKIT_API_SECRET is missing from .env")

    identity = f"agent-jail-{uuid.uuid4().hex[:8]}"

    token = create_security_token(identity)

    room = rtc.Room()

    await room.connect(LIVEKIT_URL, token)

    event = {
        "event_id": str(uuid.uuid4()),
        "event_type": event_type,
        "data": data,
    }

    payload = json.dumps(event).encode("utf-8")

    await room.local_participant.publish_data(
        payload,
        reliable=True,
        topic="agent-jail-security",
    )

    print(f"LiveKit event published: {event_type}")

    await room.disconnect()


async def main():
    await publish_security_event(
        "THREAT_DETECTED",
        {
            "source": "Gmail",
            "message_id": "email-003",
            "threat": "email_exfiltration",
            "score": 0.975,
            "risk": "HIGH",
        },
    )


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())