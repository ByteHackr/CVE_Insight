# CVE Insight: Comprehensive CVE Analysis Tool

**CVE Insight** is a Python CLI tool that fetches, analyzes, and explains CVE information using public data sources (NVD, MITRE, Debian) and local LLMs via [Ollama](https://ollama.com/).

---

## 🔧 Prerequisites

- Python 3.7+
- Pip (Python package installer)
- An active Ollama instance

---

## 🧠 Ollama Setup

1. **Install Ollama**  
   Follow the instructions on [Ollama's official website](https://ollama.com/).

2. **Download an LLM Model**
   
       ollama pull gemma3:12b  # Or your preferred model (e.g., llama3, mistral)

  Ensure Ollama is Running
  Ollama should be running and accessible at: http://localhost:11434

(Optional) Configure Ollama
Set environment variables for custom model or host:

    export OLLAMA_MODEL="your_chosen_model"        # e.g., gemma3:12b
    export OLLAMA_HOST="http://your-ollama-server-ip:11434"  # If different from default

## 🔐 GitHub API Token Setup

   For enhanced GitHub PoC search capabilities and to avoid rate-limiting:

   Create a GitHub Personal Access Token (PAT)
  
   No specific scopes are typically needed for public search.

   Set the token as an environment variable

    export GITHUB_TOKEN="your_github_personal_access_token"

  Add to your shell profile for persistence
  Add the above export line to your .bashrc, .zshrc, or shell config file.

## 📦 Installation

Clone the repository

    git clone https://github.com/ByteHackr/CVE_Insight.git
    cd CVE_Insight

Install dependencies

    pip install -r requirements.txt


## 🚀 How to Run

Execute the script with a CVE ID:

    python cve_insight_tool.py CVE-YYYY-NNNNN

🔍 Example:

    python cve_insight_tool.py CVE-2023-38545

⚙️ Optional Flags

    --skip-llm: Skip all LLM-based analysis.

    --skip-debian: Skip fetching data from Debian Security Tracker.

    --skip-pocs: Skip searching GitHub for Proof-of-Concept exploits.

## ⚠️ Disclaimer

This tool aggregates publicly available data for educational and research purposes only.
Always verify any critical security information from official sources.
Use caution when handling or executing any Proof-of-Concept (PoC) code.

## 🧑‍💻 Author @ByteHackr

For questions, issues, or contributions, feel free to open an issue or pull request on GitHub.
