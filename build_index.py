import os
import asyncio
import json
from dotenv import load_dotenv
from moss import MossClient, DocumentInfo

load_dotenv()

PROJECT_ID = os.getenv("MOSS_PROJECT_ID")
PROJECT_KEY = os.getenv("MOSS_PROJECT_KEY")

INDEX_NAME = "agent-jail-threats-v2"



async def main():

    # --------------------------------------------------
    # 1. Connect to Moss
    # --------------------------------------------------

    client = MossClient(
        PROJECT_ID,
        PROJECT_KEY
    )

    print("Connected to Moss.")


    # --------------------------------------------------
    # 2. Load our threat database
    # --------------------------------------------------

    with open("threat_patterns.json", "r", encoding="utf-8") as file:
        data = json.load(file)

    threats = data["threat_patterns"]

    print(f"Loaded {len(threats)} threat patterns.")


    # --------------------------------------------------
    # 3. Convert each threat into a Moss DocumentInfo
    # --------------------------------------------------

    documents = []

    for threat in threats:

        searchable_text = (
            f"Attack category: {threat['category']}. "
            f"Threat pattern: {threat['pattern']} "
            f"Attack description: {threat['description']} "
            f"Attack intent: {threat['attack_intent']} "
            f"Target: {', '.join(threat['target'])}. "
            f"Actions: {', '.join(threat['action'])}. "
            f"Indicators: {', '.join(threat['indicators'])}."
        )

        document = DocumentInfo(
            id=threat["id"],
            text=searchable_text
        )

        documents.append(document)


    print(f"Prepared {len(documents)} documents for Moss.")


    # --------------------------------------------------
    # 4. Create the Moss index
    # --------------------------------------------------

    await client.create_index(
        INDEX_NAME,
        documents
    )

    print(f"Created Moss index: {INDEX_NAME}")


    # --------------------------------------------------
    # 5. Load the index for querying
    # --------------------------------------------------

    await client.load_index(INDEX_NAME)

    print("Index loaded successfully.")


if __name__ == "__main__":
    asyncio.run(main())