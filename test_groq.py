import os
from dotenv import load_dotenv
from langchain_groq import ChatGroq


load_dotenv()


def main():

    # Check that the key exists without printing it.
    if not os.getenv("GROQ_API_KEY"):
        raise RuntimeError("GROQ_API_KEY was not found in .env")

    llm = ChatGroq(
        model="openai/gpt-oss-120b",
        temperature=0,
    )

    response = llm.invoke(
        "In one sentence, explain what an AI agent is."
    )

    print("\n" + "=" * 60)
    print("AGENT JAIL — GROQ CONNECTIVITY TEST")
    print("=" * 60)

    print("\nResponse:")
    print(response.content)

    print("\nModel:")
    print(response.response_metadata.get("model_name"))

    print("\nUsage:")
    print(response.usage_metadata)

    print("=" * 60)
    print("\n✅ GROQ CONNECTION SUCCESSFUL")


if __name__ == "__main__":
    main()