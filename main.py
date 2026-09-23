import json
import os
from typing import Any

from dotenv import load_dotenv
from google import genai
from google.genai import types

from prompts import SYSTEM_PROMPT
from tools import scan_vulnerabilities


# Load variables from the project .env even when the command is started from a
# different working directory.
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))


def run_review(query: str, code: str, language: str | None = None) -> str:
    if not query.strip():
        return "Error: please provide a security-review question."

    if not code.strip():
        return "Error: please provide a code snippet."

    # Read Gemini API key from environment / .env
    api_key = os.getenv("GEMINI_API_KEY")

    if not api_key:
        return "Error: GEMINI_API_KEY is not set. Check your .env file."

    try:
        client = genai.Client(api_key=api_key)

        # Define the local security scanning tool
        tool = types.Tool(
            function_declarations=[
                types.FunctionDeclaration(
                    name="scan_vulnerabilities",
                    description=(
                        "Run a local heuristic security scan on source code. "
                        "Use this when the code or security question suggests "
                        "potential security risks."
                    ),
                    parameters_json_schema={
                        "type": "object",
                        "properties": {
                            "code": {
                                "type": "string",
                                "description": "Source code to scan.",
                            },
                            "language": {
                                "type": "string",
                                "description": "Optional programming language.",
                            },
                        },
                        "required": ["code"],
                    },
                )
            ]
        )

        contents = f"""
User security question:
{query}

Language:
{language or "unknown"}

Code snippet:
```text
{code}
```
"""

        chat = client.chats.create(
            model="gemini-3.6-flash",
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                tools=[scan_vulnerabilities],
            ),
        )
        response = chat.send_message(contents)

        return response.text or "Error: Gemini returned an empty response."
    except Exception as exc:
        return f"Error contacting Gemini: {exc}"


def main() -> None:
    print("CodeSentry - AI Security Code Reviewer")
    print("Type your security question (or Ctrl+C to exit).\n")

    try:
        query = input("Question: ")
        language = input("Language (optional): ").strip() or None
        print("Paste code, then enter a line containing END:")

        code_lines = []
        while True:
            line = input()
            if line == "END":
                break
            code_lines.append(line)

        print("\n" + run_review(query, "\n".join(code_lines), language))
    except (KeyboardInterrupt, EOFError):
        print("\nExiting.")


if __name__ == "__main__":
    main()