# CodeSentry

AI-assisted security code reviewer powered by Google Gemini and a local heuristic vulnerability scanner.

## Features

- Reviews code snippets in plain language using Gemini.
- Uses a local scanner to identify common risky patterns.
- Reports a verdict, severity, affected line, explanation, and suggested fix.
- Supports an optional programming-language hint.
- Keeps API credentials in environment variables instead of source code.

## Requirements

- Python 3.10 or newer
- A Google Gemini API key

## Installation

1. Create and activate a virtual environment:

	```powershell
	python -m venv .venv
	.\.venv\Scripts\Activate.ps1
	```

2. Install the dependencies:

	```powershell
	pip install -r requirements.txt
	```

3. Create a `.env` file in the project root:

	```env
	GEMINI_API_KEY=your_gemini_api_key
	```

	Do not commit this file. It is excluded by `.gitignore`.

## Usage

Run the interactive reviewer:

```powershell
python main.py
```

Then provide:

1. A security question, such as `Is this code safe from injection attacks?`
2. An optional programming language.
3. The code to review, followed by a line containing exactly `END`.

Example:

```text
Question: Is this code vulnerable?
Language (optional): Python
Paste code, then enter a line containing END:
query = "SELECT * FROM users WHERE id=" + user_id
END
```

The application sends the review request to Gemini and may call the local scanner when the code or question suggests that a scan is useful.

### Example Output

The exact wording depends on Gemini, but a response for the example above may look like this:

```text
Summary verdict: High risk

Findings:
- Category: SQL injection
- Severity: high
- Line: 1
- Explanation: SQL is built by concatenating user-controlled input into the query.
- Suggested fix: Use a parameterized query and pass user data as a bound parameter.

Plain-language explanation:
An attacker may be able to alter the SQL statement by supplying specially crafted input.
Validate the input and use prepared statements before deploying this code.
```

## Local Scanner

The `scan_vulnerabilities` function in `tools.py` returns JSON-serializable results and currently checks for:

- Hardcoded secrets and credentials
- Dynamic execution with `eval` or `exec`
- SQL queries built with concatenation or interpolation
- Command injection risks involving `shell=True`
- Unsafe `pickle` or YAML deserialization
- MD5 and SHA-1 usage
- User input without nearby validation or sanitization

The scanner is heuristic. A finding is an indicator for manual review, not proof that a vulnerability exists, and a clean result does not guarantee that code is secure.

## Assumptions

- The application is run from the project root, or the files are kept together so that `main.py` can load `prompts.py` and `tools.py`.
- The user has a valid Gemini API key and network access to the Gemini service.
- The API key is stored in `.env` as `GEMINI_API_KEY`; environment variables can also provide this value.
- Code review input is pasted interactively and ends with a line containing exactly `END`.
- The optional language field is a hint for the AI reviewer and does not change the scanner's parsing into a language-specific analysis.
- Scanner line numbers are based on the pasted snippet, starting at line 1.
- Scanner results are pattern-based indicators and may produce false positives or miss vulnerabilities.
- AI-generated recommendations require developer verification and do not replace tests, manual review, or specialized security tools.

## Project Structure

```text
.
├── main.py                 # Interactive application and Gemini integration
├── prompts.py              # System instructions for the AI reviewer
├── tools.py                # Local heuristic vulnerability scanner
├── requirements.txt        # Python dependencies
├── tests/
│   └── test_tools.py       # Scanner unit tests
└── .env                    # Local API key; do not commit
```

## Running Tests

Run the test suite from the project root:

```powershell
python -m unittest discover -s tests -p "test_*.py"
```

The scanner tests do not require a Gemini API key.

## Error Handling

The application reports a readable error when:

- The security question is empty.
- The code snippet is empty.
- `GEMINI_API_KEY` is missing.
- The Gemini request fails.

Press `Ctrl+C` or send an end-of-file signal to exit the interactive application.

## Security Notes

- Never place real secrets in code submitted for review.
- Rotate any credential that has been exposed.
- Treat AI output and heuristic findings as review assistance, not as a replacement for security testing.
- Review code manually and use dedicated security tools before deploying sensitive applications.