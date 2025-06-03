CVE Insight: Comprehensive CVE Analysis Tool

CVE Insight is a Python-based command-line tool designed to provide comprehensive information and analysis for Common Vulnerabilities and Exposures (CVEs). It leverages public data sources like the National Vulnerability Database (NVD), MITRE's CVE services, and the Debian Security Tracker, and integrates with local Large Language Models (LLMs) via Ollama for enhanced analysis, summarization, and explanation of vulnerabilities.
Features

    Multi-Source Data Aggregation:

        Fetches CVE details from NVD (descriptions, CVSS scores, CPEs).

        Retrieves information from MITRE/CVE.org (descriptions, affected products, CVSS from CNAs).

        (Optional) Gathers patch status and information from the Debian Security Tracker.

    LLM-Powered Analysis (via Ollama):

        Suggests potentially affected software components based on CVE descriptions and hints.

        Generates concise and informative titles for CVEs.

        Creates technical summaries explaining the vulnerability.

        Provides more detailed explanations of how the vulnerability works.

        Identifies potential mitigation or workaround steps from the description.

    Detailed Information Display:

        Clearly presents CVSS v3.x and v4.0 scores from multiple sources (NVD, MITRE).

        Shows identified CWE (Common Weakness Enumeration) IDs.

        Displays Debian-specific patch information and release status.

    Proof-of-Concept (PoC) Search:

        (Optional) Searches GitHub for publicly available PoCs or exploits related to a CVE.

    User-Friendly Interface:

        Uses rich for formatted and readable console output.

        Interactive prompts for confirming or editing LLM-generated suggestions.

    Configurable:

        Ollama server URL and model name can be configured via environment variables.

        Optional use of a GitHub Personal Access Token for higher API rate limits.

    Extensible: Designed with clear functions for fetching and processing data, making it easier to add new data sources or analytical capabilities.

Prerequisites

    Python 3.7+

    Ollama: A running Ollama instance with a downloaded model (e.g., gemma3:12b, llama3, etc.).

        See Ollama's official website for installation instructions.

    Pip: Python package installer.

Installation & Setup

    Clone the repository (or download the script):

    git clone [https://github.com/ByteHackr/CVE_Insight.git](https://github.com/ByteHackr/CVE_Insight.git)
    cd CVE_Insight

    Install Python dependencies:

    pip install -r requirements.txt

    (Ensure you have a requirements.txt file in your repository with the content below)

    Configure Environment Variables (Recommended):

        Ollama Model: Set the LLM model to be used by Ollama.

        export OLLAMA_MODEL="gemma3:12b" 
        # Or your preferred model, e.g., llama3:8b, mistral, etc.

        Ollama Host URL (if not running on http://localhost:11434):

        export OLLAMA_HOST="http://your-ollama-server-ip:11434"

        GitHub Token (Optional, for PoC search): To increase API rate limits when searching GitHub for PoCs, create a Personal Access Token (PAT) on GitHub with no specific scopes required (public data access is usually enough for search).

        export GITHUB_TOKEN="your_github_personal_access_token"

        You can add these export commands to your shell's configuration file (e.g., .bashrc, .zshrc) to make them persistent.

    Ensure your Ollama server is running and the specified model is downloaded:

    ollama pull gemma3:12b # Or your chosen model
    ollama list # To verify the model is available

Usage

Run the script from the command line, providing the CVE ID you want to analyze:

python cve_insight_tool.py CVE-YYYY-NNNNN

Example:

python cve_insight_tool.py CVE-2023-38545

Command-Line Arguments

    cve: (Required) The CVE ID to process (e.g., CVE-2023-12345).

    --skip-llm: (Optional) Skip all LLM-based analysis and generation steps. The tool will only fetch and display data from public sources.

    --skip-debian: (Optional) Skip fetching data from the Debian Security Tracker.

    --skip-pocs: (Optional) Skip searching for PoCs on GitHub.

Example with optional flags:

python cve_insight_tool.py CVE-2021-44228 --skip-debian --skip-pocs

Output

The tool will output information in sections:

    CVE Description: From NVD or MITRE.

    CVSS Metrics: Detailed CVSS v3.x and v4.0 scores from NVD and MITRE.

    CWE Information: Identified Common Weakness Enumeration.

    Debian Security Tracker Details (if not skipped and data is available).

    Potential PoCs/Exploits from GitHub (if not skipped and results are found).

    LLM Analysis (if not skipped and a description is available):

        Suggested Affected Component (with interactive confirmation).

        Suggested CVE Title (with interactive confirmation).

        Generated Vulnerability Summary (with interactive confirmation).

        Generated Vulnerability Explanation (with interactive confirmation).

        Suggested Mitigation/Workaround (with interactive confirmation).

How it Works

    Data Fetching: The tool makes API calls to NVD, MITRE/CVE.org, and optionally Debian Security Tracker and GitHub to gather raw data about the specified CVE.

    Information Extraction: It parses this data to extract key details like descriptions, CVSS vectors, CWEs, affected product hints, and patch statuses.

    LLM Interaction (Ollama): For tasks requiring deeper understanding or generation:

        The relevant CVE description and any extracted hints are passed to a local LLM (via Ollama).

        Specific prompts guide the LLM to:

            Identify the most likely primary affected software component.

            Generate a concise title.

            Summarize the vulnerability's technical aspects.

            Explain the vulnerability's mechanics.

            Suggest potential mitigation steps found within the description.

    User Interaction: For LLM-generated content, the user is prompted to confirm, regenerate, or manually edit the suggestions.

    Formatted Output: All collected and generated information is presented in a structured and readable format in the console using the rich library.

Contributing

Contributions are welcome! If you have ideas for improvements, new features (like integrating more data sources), or bug fixes, please feel free to:

    Fork the repository.

    Create a new branch (git checkout -b feature/your-feature-name).

    Make your changes.

    Commit your changes (git commit -am 'Add some feature').

    Push to the branch (git push origin feature/your-feature-name).

    Open a Pull Request.

Please ensure your code follows general Python best practices and includes comments where necessary.
License

This project is licensed under the MIT License - see the LICENSE.md file for details (you'll need to create this file, typically with standard MIT License text).

Disclaimer: This tool provides information aggregated from public sources and LLM analysis for educational and research purposes. Always verify critical information from authoritative sources. The PoC search results are for informational purposes only; exercise extreme caution and verify the safety and legality of any code before execution.
