import os
import asyncio
from dotenv import load_dotenv
from moss import MossClient, QueryOptions, DocumentInfo

load_dotenv()

PROJECT_ID = os.getenv("MOSS_PROJECT_ID")
PROJECT_KEY = os.getenv("MOSS_PROJECT_KEY")

async def main():
    client = MossClient(
        PROJECT_ID,
        PROJECT_KEY
    )

    await client.create_index(
        "test-index",
        [
            DocumentInfo(id="1", text="Moss is a semantic search runtime for AI agents."),
            DocumentInfo(id="2", text="Python can be used to integrate Moss into an AI application."),
            DocumentInfo(id="3", text="Moss supports semantic and keyword search."),    
            
        ]
    )

    await client.load_index("test-index")

    results = await client.query(
        "test-index",
        "How can I use Moss with an AI agent?",
        QueryOptions(top_k=3)
    )

    for doc in results.docs:
        print(f"[{doc.score:.3f}] {doc.text}")


asyncio.run(main())