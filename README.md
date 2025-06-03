CVE Insight: Comprehensive CVE Analysis Tool

CVE Insight is a Python CLI tool that fetches, analyzes, and explains CVE information using public data sources (NVD, MITRE, Debian) and local LLMs via Ollama.
Prerequisites

    Python 3.7+

    Pip (Python package installer)

    An active Ollama instance.

Ollama Setup

    Install Ollama: Follow the instructions on Ollama's official website.

    Download an LLM Model:

    ollama pull gemma3:12b # Or your preferred model (e.g., llama3, mistral)

    Ensure Ollama is Running: The tool will attempt to connect to http://localhost:11434 by default.

    (Optional) Configure Ollama:

        export OLLAMA_MODEL="your_chosen_model" (e.g., gemma3:12b)

        export OLLAMA_HOST="http://your-ollama-server-ip:11434" (if not default)

GitHub API Token Setup (Optional)

For enhanced GitHub PoC search capabilities and to avoid rate-limiting:

    Create a GitHub Personal Access Token (PAT) (no specific scopes are typically needed for public search).

    Set the token as an environment variable:

    export GITHUB_TOKEN="your_github_personal_access_token"

    Add export commands to your shell's profile (e.g., .bashrc, .zshrc) for persistence.

Installation

    Clone the repository:

    git clone [https://github.com/ByteHackr/CVE_Insight.git](https://github.com/ByteHackr/CVE_Insight.git)
    cd CVE_Insight

    Install dependencies:

    pip install -r requirements.txt

    (requirements.txt should contain requests, ollama, rich)

How to Run

Execute the script with a CVE ID:

python cve_insight_tool.py CVE-YYYY-NNNNN

Example:

python cve_insight_tool.py CVE-2023-38545

Optional Flags:

    --skip-llm: Skip all LLM analysis.

    --skip-debian: Skip fetching Debian Security Tracker data.

    --skip-pocs: Skip searching GitHub for PoCs.

Disclaimer: This tool aggregates data for educational/research purposes. Always verify critical information. Exercise caution with any PoC code.
