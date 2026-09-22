import { NextResponse } from "next/server";
import { AccessToken } from "livekit-server-sdk";

export async function GET() {
  try {
    const apiKey = process.env.LIVEKIT_API_KEY;
    const apiSecret = process.env.LIVEKIT_API_SECRET;

    if (!apiKey || !apiSecret) {
      console.error("Missing LiveKit server credentials");

      return NextResponse.json(
        {
          error: "LiveKit credentials are missing",
          hasApiKey: Boolean(apiKey),
          hasApiSecret: Boolean(apiSecret),
        },
        { status: 500 }
      );
    }

    const token = new AccessToken(apiKey, apiSecret, {
      identity: `dashboard-${Date.now()}`,
      ttl: "1h",
    });

    token.addGrant({
      roomJoin: true,
      room: "agent-jail-security",
      canSubscribe: true,
      canPublish: false,
    });

    const jwt = await token.toJwt();

    return NextResponse.json({
      token: jwt,
    });
  } catch (error) {
    console.error("LiveKit token generation error:", error);

    return NextResponse.json(
      {
        error: "Failed to generate LiveKit token",
        details: error instanceof Error ? error.message : String(error),
      },
      { status: 500 }
    );
  }
}