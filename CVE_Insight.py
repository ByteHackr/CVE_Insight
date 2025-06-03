import os
import subprocess
import argparse
import json
import requests
import time
import sys
import ollama # For local LLM interaction
from rich.console import Console, Group
from rich.prompt import Prompt
import re
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text
from rich.table import Table
from rich.padding import Padding
from rich.markdown import Markdown
from rich.columns import Columns

# --- Ollama Configuration ---
MODEL_NAME = os.environ.get("OLLAMA_MODEL", "gemma3:4b") # User can set via environment variable
OLLAMA_URL = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
NO_WORKAROUND_FOUND_MARKER = "[[NO_WORKAROUND_FOUND_MARKER]]"
GENERIC_MITIGATION_NOT_FOUND_TEXT = "No specific mitigation or workaround actions were identified in the available description."
# --- ---

console = Console()

# --- Emojis for UI ---
EMOJI_INFO = "ℹ️"
EMOJI_SUCCESS = "✅"
EMOJI_ERROR = "❌"
EMOJI_WARNING = "⚠️"
EMOJI_FETCH = "📡"
EMOJI_AI = "🤖"
EMOJI_EDIT = "✍️"
EMOJI_TOOL = "🛠️"
EMOJI_EYES = "👀"
EMOJI_CHECK = "🔍"
EMOJI_SAVE = "💾" # Kept for conceptual "saving" of user choices, not DB
EMOJI_LIST = "📋"
EMOJI_EXPLAIN = "🧠"
EMOJI_PATCH = "🩹"
EMOJI_POC = "🧪"

# --- "CVE Insight" Banner ---
BANNER_TEXT_CONTENT = 'CVE INSIGHT'
letter_colors = [
    "bright_cyan", "cyan", "bright_blue", "blue", "dodger_blue1",
    "sky_blue1", "deep_sky_blue1", "light_sky_blue1", "steel_blue1", "slate_blue1"
]
banner_text_obj = Text(justify="center")
color_idx = 0
for char_idx, char_val in enumerate(BANNER_TEXT_CONTENT):
    if char_val == ' ': banner_text_obj.append(' ')
    else:
        style_to_apply = f"bold {letter_colors[color_idx % len(letter_colors)]}"; banner_text_obj.append(char_val, style=style_to_apply); color_idx += 1
console.print(); console.print(Rule(characters="═", style="dim cyan")); console.print(Padding(banner_text_obj, (1, 0, 1, 0))); console.print(Rule(characters="═", style="dim cyan")); console.print()
console.print(Rule(f"[bold sky_blue1]{EMOJI_TOOL} Initializing CVE Insight {EMOJI_TOOL}[/bold sky_blue1]"))
# --- End of Banner ---

def print_step_context(step_context_key, icon="➡️"):
    """Prints a formatted rule indicating the current processing step."""
    context_map = {
        "fetch_nvd": f"{EMOJI_FETCH} Fetching NVD Data",
        "fetch_cve_org": f"{EMOJI_FETCH} Fetching CVE.org (MITRE) Data",
        "fetch_debian": f"{EMOJI_FETCH} Fetching Debian Security Tracker Data",
        "fetch_github_pocs": f"{EMOJI_POC} Searching GitHub for PoCs/Exploits",
        "analyze_description": f"{EMOJI_AI} Analyzing CVE Description with LLM",
        "generate_component": f"{EMOJI_AI} Suggesting Affected Component(s)",
        "generate_title": f"{EMOJI_EDIT} Suggesting CVE Title",
        "generate_summary": f"{EMOJI_EDIT} Generating Vulnerability Summary",
        "generate_explanation": f"{EMOJI_EXPLAIN} Generating Vulnerability Explanation",
        "generate_mitigation": f"{EMOJI_AI} Suggesting Mitigation/Workaround",
        "display_cvss": f"{EMOJI_LIST} Displaying CVSS Information",
        "display_cwe": f"{EMOJI_CHECK} Displaying CWE Information",
        "display_debian": f"{EMOJI_LIST} Displaying Debian Patch Information",
        "display_pocs": f"{EMOJI_LIST} Displaying Potential PoCs/Exploits",
        "user_confirmation": f"{EMOJI_EYES} User Confirmation/Input"
    }
    message = context_map.get(step_context_key, f"{icon}  Processing Step: {step_context_key.replace('_', ' ').title()}")
    console.print(Rule(f"[bold bright_blue]{message}[/bold bright_blue]", style="blue"))

def get_cve_description_from_sources(cve_id, nvd_data, mitre_data):
    """Attempts to get the best English CVE description from NVD or MITRE data."""
    descriptions = []
    # Try NVD first
    if nvd_data and "descriptions" in nvd_data:
        for desc in nvd_data["descriptions"]:
            if desc.get("lang") == "en":
                descriptions.append({"source": "NVD", "value": desc.get("value","")})

    # Try MITRE if NVD fails or to get alternatives
    if mitre_data:
        cna_descriptions = mitre_data.get("containers", {}).get("cna", {}).get("descriptions", [])
        for desc_entry in cna_descriptions:
            if desc_entry.get("lang") == "en":
                descriptions.append({"source": "MITRE/CVE.org", "value": desc_entry.get("value","")})
    
    if descriptions:
        # Simple preference: NVD > MITRE if both exist.
        nvd_desc = next((d['value'] for d in descriptions if d['source'] == 'NVD' and d['value']), None)
        if nvd_desc:
            console.print(f"{EMOJI_INFO} Using primary description from NVD for {cve_id}.")
            return nvd_desc
        mitre_desc = next((d['value'] for d in descriptions if d['source'] == 'MITRE/CVE.org' and d['value']), None)
        if mitre_desc:
            console.print(f"{EMOJI_INFO} Using primary description from MITRE/CVE.org for {cve_id}.")
            return mitre_desc
            
    console.print(f"{EMOJI_WARNING} [yellow]No English CVE description found for {cve_id} from NVD or MITRE.[/yellow]")
    return None

def get_cve_vendor_product_mitre(cve_id, mitre_data):
    """Fetches vendor and product information from MITRE data (if already fetched)."""
    if not mitre_data: return []
    
    affected = mitre_data.get("containers", {}).get("cna", {}).get("affected", []); products = []
    for entry in affected:
        vendor = entry.get("vendor", "Unknown Vendor"); product_field = entry.get("product")
        if isinstance(product_field, list):
            for prod in product_field: products.append((vendor, prod))
        elif isinstance(product_field, str): products.append((vendor, product_field))
    return products

def fetch_nvd_data_raw(cve_id):
    """Fetches raw CVE data from NVD API."""
    NVD_API_URL = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    with console.status(f"[bold green]Fetching NVD data for {cve_id}...[/bold green]", spinner="earth"):
        try:
            time.sleep(0.7) 
            headers = {'User-Agent': 'CVE-Insight-Tool/1.0'} 
            response = requests.get(NVD_API_URL, timeout=20, headers=headers)
            response.raise_for_status()
            data = response.json()
            if "vulnerabilities" in data and data["vulnerabilities"]:
                console.print(f"{EMOJI_SUCCESS} NVD data successfully fetched for {cve_id}.")
                return data["vulnerabilities"][0]["cve"]
            else:
                console.print(f"{EMOJI_WARNING} [yellow]No vulnerability data found in NVD response for {cve_id}.[/yellow]")
                return None
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                console.print(f"{EMOJI_WARNING} [yellow]NVD API: CVE {cve_id} not found (404).[/yellow]")
            elif e.response.status_code == 403:
                console.print(f"{EMOJI_ERROR} [red]NVD API: Access forbidden (403). Rate limit or other issue?[/red]")
            else:
                console.print(f"{EMOJI_ERROR} [red]NVD API HTTP Error: {e.response.status_code} for {cve_id}.[/red]")
            return None
        except requests.exceptions.RequestException as e:
            console.print(f"{EMOJI_ERROR} [red]Error fetching NVD data for {cve_id}: {e}[/red]")
            return None
        except json.JSONDecodeError:
            console.print(f"{EMOJI_ERROR} [red]Error: Could not decode JSON response from NVD for {cve_id}.[/red]")
            return None

def fetch_mitre_data_raw(cve_id):
    """Fetches raw CVE data from MITRE's CVE Services API."""
    MITRE_API_URL = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    with console.status(f"[bold green]Fetching MITRE/CVE.org data for {cve_id}...[/bold green]", spinner="dots"):
        try:
            time.sleep(0.5) 
            headers = {'User-Agent': 'CVE-Insight-Tool/1.0'}
            response = requests.get(MITRE_API_URL, timeout=15, headers=headers)
            response.raise_for_status()
            data = response.json()
            console.print(f"{EMOJI_SUCCESS} MITRE/CVE.org data successfully fetched for {cve_id}.")
            return data
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                console.print(f"{EMOJI_WARNING} [yellow]MITRE API: CVE {cve_id} not found (404).[/yellow]")
            else:
                console.print(f"{EMOJI_ERROR} [red]MITRE API HTTP Error: {e.response.status_code} for {cve_id}.[/red]")
            return None
        except requests.exceptions.RequestException as e:
            console.print(f"{EMOJI_ERROR} [red]Error fetching MITRE/CVE.org data for {cve_id}: {e}[/red]")
            return None
        except json.JSONDecodeError:
            console.print(f"{EMOJI_ERROR} [red]Error: Could not decode JSON response from MITRE for {cve_id}.[/red]")
            return None

def fetch_debian_security_data(cve_id):
    """Fetches CVE information from the Debian Security Bug Tracker."""
    DEBIAN_API_URL = f"https://security-tracker.debian.org/tracker/data/json/{cve_id}"
    print_step_context("fetch_debian")
    with console.status(f"[bold green]Fetching Debian Security Tracker data for {cve_id}...[/bold green]", spinner="dots"):
        try:
            time.sleep(0.5) 
            headers = {'User-Agent': 'CVE-Insight-Tool/1.0'}
            response = requests.get(DEBIAN_API_URL, timeout=15, headers=headers)
            response.raise_for_status()
            data = response.json()
            console.print(f"{EMOJI_SUCCESS} Debian Security Tracker data fetched for {cve_id}.")
            return data.get(cve_id, {}) 
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                console.print(f"{EMOJI_INFO} [yellow]CVE {cve_id} not found in Debian Security Tracker (or no specific data).[/yellow]")
            else:
                console.print(f"{EMOJI_ERROR} [red]Debian Tracker HTTP Error: {e.response.status_code} for {cve_id}.[/red]")
            return None
        except requests.exceptions.RequestException as e:
            console.print(f"{EMOJI_ERROR} [red]Error fetching Debian Security Tracker data: {e}[/red]")
            return None
        except json.JSONDecodeError:
            console.print(f"{EMOJI_ERROR} [red]Error decoding JSON from Debian Security Tracker for {cve_id}.[/red]")
            return None

def display_debian_data(debian_data, cve_id):
    """Displays formatted Debian security information."""
    if not debian_data:
        console.print(f"{EMOJI_INFO} No Debian-specific information to display for {cve_id}.")
        return

    print_step_context("display_debian")
    panel_content = [Text(f"Debian Security Information for {cve_id}", style="bold bright_blue")]
    
    if "description" in debian_data and debian_data["description"]:
        panel_content.append(Text(f"\nDescription: {debian_data['description']}", style="italic"))

    if "notes" in debian_data and debian_data["notes"]:
        notes_table = Table(title="Notes", box=None, show_header=False, padding=(0,1,0,0))
        notes_table.add_column("Author"); notes_table.add_column("Note")
        for author, note_text in debian_data["notes"].items():
            notes_table.add_row(author, note_text)
        panel_content.append(Padding(notes_table, (1,0)))

    if "releases" in debian_data and debian_data["releases"]:
        releases_table = Table(title="Status in Debian Releases", show_header=True, header_style="bold magenta", expand=True)
        releases_table.add_column("Release Name", style="cyan")
        releases_table.add_column("Status", style="yellow")
        releases_table.add_column("Fixed Version", style="green")
        releases_table.add_column("Urgency", style="orange1")
        releases_table.add_column("Repositories", style="dim")

        for release_name, release_info in debian_data["releases"].items():
            fixed_version = release_info.get("fixed_version", "N/A")
            if fixed_version == "0": fixed_version = "Not applicable" 
            
            repositories_str = ""
            if "repositories" in release_info and release_info["repositories"]:
                repos = []
                for repo_name, version in release_info["repositories"].items():
                    repos.append(f"{repo_name}: {version if version else 'N/A'}")
                repositories_str = "; ".join(repos) if repos else "N/A"
            else: repositories_str = "N/A"

            releases_table.add_row(
                release_name,
                release_info.get("status", "N/A"),
                fixed_version,
                release_info.get("urgency", "N/A"),
                repositories_str
            )
        panel_content.append(Padding(releases_table, (1,0)))
    else:
        panel_content.append(Text("\nNo specific release status information found.", style="dim"))

    console.print(Panel(Group(*panel_content), title=f"{EMOJI_LIST} Debian Security Tracker Details", border_style="blue", expand=False))


def fetch_github_pocs(cve_id):
    """Searches GitHub for potential Proof-of-Concept code or exploits related to the CVE."""
    print_step_context("fetch_github_pocs")
    search_query = f"{cve_id} PoC OR exploit"
    search_url_code = f"https://api.github.com/search/code?q={requests.utils.quote(search_query)}&sort=updated&order=desc"
    search_url_repos = f"https://api.github.com/search/repositories?q={requests.utils.quote(search_query)}&sort=updated&order=desc"
    
    pocs = []
    headers = {'Accept': 'application/vnd.github.v3+json', 'User-Agent': 'CVE-Insight-Tool/1.0'}
    
    GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
    if GITHUB_TOKEN:
        headers['Authorization'] = f"Bearer {GITHUB_TOKEN}" # Use Bearer for PATs as well, it's more standard
        console.print(f"{EMOJI_INFO} Using GITHUB_TOKEN for GitHub API requests.")
    else:
        console.print(f"{EMOJI_WARNING} [yellow]GITHUB_TOKEN environment variable not set. GitHub API requests will be unauthenticated and heavily rate-limited. This might lead to errors or incomplete results.[/yellow]")

    with console.status(f"[bold green]Searching GitHub for PoCs related to {cve_id}...[/bold green]", spinner="dots"):
        for url_type, search_url in [("Code", search_url_code), ("Repositories", search_url_repos)]:
            try:
                time.sleep(1) # Politeness, even with a token, helps avoid hitting secondary rate limits
                response = requests.get(search_url, headers=headers, timeout=20)
                
                if response.status_code == 401:
                    console.print(f"{EMOJI_ERROR} [bold red]GitHub API Error ({url_type}): 401 Unauthorized.[/bold red]")
                    if not GITHUB_TOKEN:
                        console.print(f"{EMOJI_WARNING} [yellow]This is likely due to a missing or invalid GITHUB_TOKEN. Please set the GITHUB_TOKEN environment variable with a valid Personal Access Token.[/yellow]")
                    else:
                        console.print(f"{EMOJI_WARNING} [yellow]Your GITHUB_TOKEN might be invalid or lack necessary permissions for search.[/yellow]")
                    continue # Skip this search type if unauthorized

                response.raise_for_status() # Raise HTTPError for other bad responses (4xx or 5xx)
                results = response.json()
                
                if results.get("items"):
                    for item in results["items"][:5]: 
                        name = item.get("name") if url_type == "Repositories" else item.get("path")
                        repo_name = item.get("full_name") if url_type == "Repositories" else item.get("repository", {}).get("full_name")
                        html_url = item.get("html_url")
                        description = item.get("description", "") if url_type == "Repositories" else "" 
                        
                        poc_info = {
                            "name": name,
                            "url": html_url,
                            "repository": repo_name,
                            "description": description if description else "N/A",
                            "type": url_type
                        }
                        pocs.append(poc_info)
                elif results.get("message") and "API rate limit exceeded" in results["message"]:
                    console.print(f"{EMOJI_WARNING} [yellow]GitHub API rate limit exceeded for {url_type} search. Results may be incomplete.[/yellow]")
                    if not GITHUB_TOKEN:
                         console.print(f"{EMOJI_WARNING} [yellow]Consider setting a GITHUB_TOKEN environment variable for higher rate limits.[/yellow]")
                    break 

            except requests.exceptions.HTTPError as e:
                # Catching other HTTP errors that are not 401 (already handled)
                console.print(f"{EMOJI_ERROR} [red]GitHub API HTTP Error ({url_type}): {e.response.status_code}. Message: {e.response.text[:200]}[/red]")
            except requests.exceptions.RequestException as e:
                console.print(f"{EMOJI_ERROR} [red]Error searching GitHub ({url_type}): {e}[/red]")
            except json.JSONDecodeError:
                console.print(f"{EMOJI_ERROR} [red]Error decoding JSON from GitHub search ({url_type}).[/red]")

    if pocs:
        console.print(f"{EMOJI_SUCCESS} Found {len(pocs)} potential PoC(s)/exploit(s) on GitHub for {cve_id}.")
    else:
        console.print(f"{EMOJI_INFO} No direct PoCs/exploits found on GitHub via initial search for {cve_id}.")
    return pocs

def display_github_pocs(pocs, cve_id):
    """Displays potential PoCs found on GitHub."""
    if not pocs:
        return

    print_step_context("display_pocs")
    table = Table(title=f"{EMOJI_POC} Potential PoCs/Exploits for {cve_id} (from GitHub)", expand=True)
    table.add_column("Name/Path", style="cyan", overflow="fold")
    table.add_column("Repository", style="magenta", overflow="fold")
    table.add_column("URL", style="green", overflow="fold")
    table.add_column("Type", style="dim")

    for poc in pocs:
        table.add_row(
            poc.get("name", "N/A"),
            poc.get("repository", "N/A"),
            poc.get("url", "N/A"),
            poc.get("type", "N/A")
        )
    console.print(table)
    console.print(f"{EMOJI_WARNING} [italic yellow]Note: These are search results. Manual verification of relevance and safety is crucial before using any PoC.[/italic yellow]")


def extract_cwe_id(nvd_data, mitre_data):
    """Extracts CWE ID, preferring NVD then MITRE."""
    if nvd_data and "weaknesses" in nvd_data:
        cwe_pattern = re.compile(r"^(CWE-\d+)$")
        for weakness in nvd_data.get("weaknesses", []):
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en":
                    value = desc.get("value", "").strip()
                    if cwe_pattern.match(value):
                        return value 

    if mitre_data:
        problem_types = mitre_data.get("containers", {}).get("cna", {}).get("problemTypes", [])
        for pt_entry in problem_types:
            for desc_entry in pt_entry.get("descriptions", []):
                if desc_entry.get("lang") == "en" and desc_entry.get("type") == "CWE":
                    cwe_id_match = re.search(r"(CWE-\d+)", desc_entry.get("description", ""))
                    if cwe_id_match:
                        return cwe_id_match.group(1) 
    return None

def format_cvss_block_for_display(cvss_data_obj, source_str, metric_type_str, version_label_prefix="CVSS"):
    """Formats a single CVSS metric object for rich display."""
    if not cvss_data_obj: return Group()
    
    actual_version = str(cvss_data_obj.get("version", "N/A")); vector_string = cvss_data_obj.get("vectorString", "N/A")
    base_score = cvss_data_obj.get("baseScore"); severity = cvss_data_obj.get("baseSeverity", ""); renderables_for_entry = []

    table_title = f"[bold]{version_label_prefix} v{actual_version} Metrics[/bold]\n(Src: {source_str} - {metric_type_str})"
    table = Table(box=None, show_header=False, padding=(0,1,0,0), title=table_title, title_style="bright_blue", expand=False)
    table.add_column("Metric Component", style="cyan", width=28, no_wrap=True); table.add_column("Value", no_wrap=False, overflow="fold")

    table.add_row("Attack Vector", cvss_data_obj.get("attackVector","N/A")); table.add_row("Attack Complexity", cvss_data_obj.get("attackComplexity","N/A"))
    if actual_version.startswith("4"): table.add_row("Attack Requirements", cvss_data_obj.get("attackRequirements", "N/A"))
    table.add_row("Privileges Required", cvss_data_obj.get("privilegesRequired","N/A")); table.add_row("User Interaction", cvss_data_obj.get("userInteraction","N/A"))
    if actual_version.startswith("3"): table.add_row("Scope", cvss_data_obj.get("scope", "N/A"))
    
    if actual_version.startswith("4"):
        table.add_row("Vulnerable System Confidentiality", cvss_data_obj.get("vulnConfidentialityImpact", cvss_data_obj.get("confidentialityImpact", "N/A")))
        table.add_row("Vulnerable System Integrity", cvss_data_obj.get("vulnIntegrityImpact", cvss_data_obj.get("integrityImpact", "N/A")))
        table.add_row("Vulnerable System Availability", cvss_data_obj.get("vulnAvailabilityImpact", cvss_data_obj.get("availabilityImpact", "N/A")))
        table.add_row("Subsequent System Confidentiality", cvss_data_obj.get("subsequentSystemConfidentialityImpact", "N/A"))
        table.add_row("Subsequent System Integrity", cvss_data_obj.get("subsequentSystemIntegrityImpact", "N/A"))
        table.add_row("Subsequent System Availability", cvss_data_obj.get("subsequentSystemAvailabilityImpact", "N/A"))
    else:
        table.add_row("Confidentiality Impact", cvss_data_obj.get("confidentialityImpact","N/A")); table.add_row("Integrity Impact", cvss_data_obj.get("integrityImpact","N/A")); table.add_row("Availability Impact", cvss_data_obj.get("availabilityImpact","N/A"))
    
    renderables_for_entry.append(Padding(table, (0,0,0,0)))

    if base_score is not None and vector_string != "N/A":
        severity_color = "white"
        if severity == "CRITICAL": severity_color = "bold red"
        elif severity == "HIGH": severity_color = "orange3"
        elif severity == "MEDIUM": severity_color = "yellow"
        elif severity == "LOW": severity_color = "green"
        score_vector_text = Text(); score_vector_text.append(f"{base_score} ", style=severity_color); score_vector_text.append(vector_string, style="default"); score_vector_text.append(f" ({severity})", style=severity_color)
        renderables_for_entry.append(Padding(score_vector_text, (1,0,0,0)))
    else: renderables_for_entry.append(Padding(f"[dim]Score/Vector N/A for {version_label_prefix} v{actual_version}[/dim]", (1,0,0,0)))
    
    return Group(*renderables_for_entry)

def get_primary_cvss_metric(metric_list, preferred_source="nvd@nist.gov"):
    """Selects the primary CVSS metric from a list."""
    if not metric_list: return None
    for item in metric_list:
        if item.get("source") == preferred_source and item.get("type") == "Primary": return item
    for item in metric_list:
        if item.get("type") == "Primary": return item
    if metric_list: return metric_list[0]
    return None

def display_cvss_metrics(nvd_data, mitre_data, cve_id):
    """Displays CVSS metrics from NVD and MITRE data."""
    print_step_context("display_cvss")
    
    nvd_cvss_v3x_items = []; nvd_cvss_v40_items = []
    if nvd_data and "metrics" in nvd_data:
        nvd_cvss_v3x_items.extend(nvd_data.get("metrics", {}).get("cvssMetricV31", []))
        nvd_cvss_v3x_items.extend(nvd_data.get("metrics", {}).get("cvssMetricV30", []))
        nvd_cvss_v40_items.extend(nvd_data.get("metrics", {}).get("cvssMetricV40", []))

    mitre_cvss_v3x_items = []; mitre_cvss_v40_items = []
    if mitre_data:
        cna_metrics = mitre_data.get("containers", {}).get("cna", {}).get("metrics", [])
        assigner = mitre_data.get("cveMetadata", {}).get("assignerShortName", "MITRE/CNA")
        for metric_set in cna_metrics:
            if metric_set.get("format", "").upper() == "CVSS":
                if "cvssV3_1" in metric_set: mitre_cvss_v3x_items.append({"source": assigner, "type": metric_set.get("type", "Published"), "cvssData": metric_set["cvssV3_1"]})
                elif "cvssV3_0" in metric_set: mitre_cvss_v3x_items.append({"source": assigner, "type": metric_set.get("type", "Published"), "cvssData": metric_set["cvssV3_0"]})
                if "cvssV4_0" in metric_set: mitre_cvss_v40_items.append({"source": assigner, "type": metric_set.get("type", "Published"), "cvssData": metric_set["cvssV4_0"]})

    nvd_primary_v3x = get_primary_cvss_metric(nvd_cvss_v3x_items)
    nvd_primary_v40 = get_primary_cvss_metric(nvd_cvss_v40_items)
    
    nvd_displayed_something = False
    if nvd_primary_v3x or nvd_primary_v40:
        console.print(Rule(f"[bold dim]{EMOJI_LIST} NVD CVSS Details for {cve_id}[/bold dim]", style="dim blue"))
        nvd_cols = []
        if nvd_primary_v3x: nvd_cols.append(format_cvss_block_for_display(nvd_primary_v3x.get("cvssData"), nvd_primary_v3x.get("source", "N/A"), nvd_primary_v3x.get("type", "N/A")))
        if nvd_primary_v40: nvd_cols.append(format_cvss_block_for_display(nvd_primary_v40.get("cvssData"), nvd_primary_v40.get("source", "N/A"), nvd_primary_v40.get("type", "N/A")))
        if nvd_cols: console.print(Padding(Columns(nvd_cols, expand=True, equal=True, padding=(0,1)),(1,0,1,0))); nvd_displayed_something = True
        
        nvd_other_scores = [item for item_list in [nvd_cvss_v3x_items, nvd_cvss_v40_items] if item_list for item in item_list if item not in [nvd_primary_v3x, nvd_primary_v40] and item is not None]
        if nvd_other_scores:
            console.print(Rule("[dim]Other NVD CVSS Scores (Sequential)[/dim]", style="dim"))
            for item in nvd_other_scores: console.print(Padding(format_cvss_block_for_display(item.get("cvssData"), item.get("source", "N/A"), item.get("type", "N/A")), (1,0,1,2)))
            nvd_displayed_something = True
        if nvd_displayed_something: console.print(Rule(style="dim blue"))

    elif nvd_cvss_v3x_items or nvd_cvss_v40_items: 
        console.print(Padding(f"{EMOJI_INFO} [dim]No 'Primary' CVSS metrics from NVD. Listing available NVD scores sequentially.[/dim]", (0,0,1,2)))
        console.print(Rule(f"[bold dim]{EMOJI_LIST} NVD CVSS Details for {cve_id} (All Available)[/bold dim]", style="dim blue"))
        all_nvd_scores = nvd_cvss_v3x_items + nvd_cvss_v40_items
        for item in all_nvd_scores: console.print(Padding(format_cvss_block_for_display(item.get("cvssData"), item.get("source", "N/A"), item.get("type", "N/A")), (1,0,1,2)))
        nvd_displayed_something = True
        if nvd_displayed_something: console.print(Rule(style="dim blue"))
    else:
        console.print(f"{EMOJI_INFO} No CVSS data found in NVD for {cve_id}.")

    mitre_primary_v3x = get_primary_cvss_metric(mitre_cvss_v3x_items, preferred_source=assigner if 'assigner' in locals() else "MITRE/CNA")
    mitre_primary_v40 = get_primary_cvss_metric(mitre_cvss_v40_items, preferred_source=assigner if 'assigner' in locals() else "MITRE/CNA")

    mitre_displayed_something = False
    if mitre_primary_v3x or mitre_primary_v40:
        console.print(Rule(f"[bold dim]{EMOJI_LIST} MITRE/CVE.org CVSS Details for {cve_id}[/bold dim]", style="dim purple"))
        mitre_cols = []
        if mitre_primary_v3x: mitre_cols.append(format_cvss_block_for_display(mitre_primary_v3x.get("cvssData"), mitre_primary_v3x.get("source", "N/A"), mitre_primary_v3x.get("type", "N/A")))
        if mitre_primary_v40: mitre_cols.append(format_cvss_block_for_display(mitre_primary_v40.get("cvssData"), mitre_primary_v40.get("source", "N/A"), mitre_primary_v40.get("type", "N/A")))
        if mitre_cols: console.print(Padding(Columns(mitre_cols, expand=True, equal=True, padding=(0,1)),(1,0,1,0))); mitre_displayed_something = True

        mitre_other_scores = [item for item_list in [mitre_cvss_v3x_items, mitre_cvss_v40_items] if item_list for item in item_list if item not in [mitre_primary_v3x, mitre_primary_v40] and item is not None]
        if mitre_other_scores:
            console.print(Rule("[dim]Other MITRE/CVE.org CVSS Scores (Sequential)[/dim]", style="dim"))
            for item in mitre_other_scores: console.print(Padding(format_cvss_block_for_display(item.get("cvssData"), item.get("source", "N/A"), item.get("type", "N/A")), (1,0,1,2)))
            mitre_displayed_something = True
        if mitre_displayed_something: console.print(Rule(style="dim purple"))
        
    elif mitre_cvss_v3x_items or mitre_cvss_v40_items: 
        console.print(Padding(f"{EMOJI_INFO} [dim]No 'Primary' CVSS metrics from MITRE/CVE.org. Listing available MITRE scores sequentially.[/dim]", (0,0,1,2)))
        console.print(Rule(f"[bold dim]{EMOJI_LIST} MITRE/CVE.org CVSS Details for {cve_id} (All Available)[/bold dim]", style="dim purple"))
        all_mitre_scores = mitre_cvss_v3x_items + mitre_cvss_v40_items
        for item in all_mitre_scores: console.print(Padding(format_cvss_block_for_display(item.get("cvssData"), item.get("source", "N/A"), item.get("type", "N/A")), (1,0,1,2)))
        mitre_displayed_something = True
        if mitre_displayed_something: console.print(Rule(style="dim purple"))
    elif nvd_displayed_something: 
        pass 
    else: 
        console.print(f"{EMOJI_INFO} No CVSS data found in MITRE/CVE.org for {cve_id}.")


    if not nvd_displayed_something and not mitre_displayed_something:
        console.print(f"{EMOJI_WARNING} [yellow]No CVSS metrics could be displayed for {cve_id} from NVD or MITRE.[/yellow]")

def parse_cpe_uri(cpe_uri):
    """Parses a CPE URI to extract a human-readable component name."""
    try:
        parts = cpe_uri.split(':')
        if len(parts) >= 5 and parts[1] in ['a', 'o', 'h']:
            vendor = parts[3].replace('_', ' ').strip(); product = parts[4].replace('_', ' ').strip()
            if vendor == '*' or product == '*' or not vendor or not product: return None
            return f"{vendor.title()} {product.title()}"
    except Exception: return None
    return None

def extract_components_from_nvd_cpes(nvd_data):
    """Extracts potential component names from NVD CPE configurations."""
    cpe_derived_components = set()
    if nvd_data and "configurations" in nvd_data:
        for config_node_outer in nvd_data.get("configurations", []):
            nodes_to_process = []
            if "nodes" in config_node_outer: nodes_to_process.extend(config_node_outer.get("nodes", []))
            for node in nodes_to_process:
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable"):
                        cpe_uri = cpe_match.get("criteria"); component_name = parse_cpe_uri(cpe_uri)
                        if component_name: cpe_derived_components.add(component_name)
    return list(cpe_derived_components)

def call_llm(prompt, temperature=0.3):
    """Calls the Ollama LLM with a given prompt and temperature."""
    try:
        response = ollama.generate(model=MODEL_NAME, prompt=prompt, stream=False, options={'temperature': temperature})
        text = response['response'].strip()
        if text.startswith('"') and text.endswith('"'): text = text[1:-1]
        if text.startswith("'") and text.endswith("'"): text = text[1:-1]
        return text
    except ollama.ResponseError as e: message = f"Model '{MODEL_NAME}' not found or error." if e.status_code == 404 else f"Ollama error: {e.error} (Status: {e.status_code})"; console.print(f"{EMOJI_ERROR} [bold red]LLM Error:[/bold red] {message}"); return None
    except requests.exceptions.ConnectionError: console.print(f"{EMOJI_ERROR} [bold red]LLM Connection Error:[/bold red] Could not connect to Ollama at {OLLAMA_URL}. Is it running?"); return None
    except Exception as e: console.print(f"{EMOJI_ERROR} [bold red]LLM Error:[/bold red] An unexpected error occurred: {e}"); return None

def llm_suggest_component(description, vendor_products_hint=None, cpe_components_hint=None):
    """Uses LLM to suggest a component name based on description and hints."""
    print_step_context("generate_component")
    cpe_hint_str = ""; mitre_product_hint = ""
    if cpe_components_hint: cpe_hint_str = ("\n\nHint from NVD CPE data (potentially affected software):\n" + "\n".join([f"- {name}" for name in cpe_components_hint]))
    if vendor_products_hint: formatted_mitre = "\n".join([f"- {vendor} / {product}" for vendor, product in vendor_products_hint]); mitre_product_hint = ("\n\nHint from MITRE (other listed products/vendors):\n" + f"{formatted_mitre}")
    
    prompt = ( "Analyze the CVE description and hints to identify the **primary affected software product or library**. "
               "If a specific utility or sub-module of a larger product is mentioned (e.g., 'utility_x in ProductSuite'), identify the **larger parent product** (e.g., 'ProductSuite').\n"
               "Use NVD CPE hints as strong indicators. Prioritize the CVE description to confirm context.\n"
               "Avoid generic terms, file paths, or overly specific function names if a broader product context is clear.\n"
               "Output only the short, precise name of this primary product/library, formatted as lowercase and hyphenated if multiple words (e.g., 'apache-http-server' or 'openssl').\n"
               f"{cpe_hint_str}{mitre_product_hint}"
               f"\n\nCVE Description to analyze:\n{description}\n\nPrimary affected product/library name:" )
    response = None
    with console.status(f"[bold green]{EMOJI_AI} LLM ({MODEL_NAME}) suggesting component name...[/bold green]", spinner="aesthetic"): response = call_llm(prompt)
    if response: return response.replace("**", "").strip().lower().replace(" ", "-")
    return None

def confirm_or_edit_via_prompt(prompt_text, current_value, default_value="", item_name="value"):
    """Generic function to confirm or edit a value via user prompt."""
    print_step_context("user_confirmation")
    while True:
        console.print(f"\n{EMOJI_AI} Current {item_name}: '[bold red]{current_value or 'Not set'}[/bold red]'")
        console.print(f"\n{prompt_text}")
        console.print(f"  [b]1[/b]: Proceed with current {item_name}")
        console.print(f"  [b]2[/b]: Regenerate {item_name} (using LLM, if applicable for this item)")
        console.print(f"  [b]3[/b]: Edit {item_name} manually")
        choice = Prompt.ask(f"{EMOJI_EDIT} Enter your choice for {item_name}", choices=["1", "2", "3"], default="1", console=console)

        if choice == "1":
            if not current_value and item_name != "mitigation": 
                 console.print(f"{EMOJI_ERROR} [red]{item_name.capitalize()} is not set. Please regenerate or edit manually.[/red]"); continue
            console.print(Padding(f"{EMOJI_SUCCESS} {item_name.capitalize()} confirmed as: '[bold green]{current_value if current_value is not None else 'None/Empty'}[/bold green]'",(1,0)));
            return current_value, "confirmed"
        elif choice == "2":
            return None, "regenerate" 
        elif choice == "3":
            edited_value = Prompt.ask(f"{EMOJI_EDIT} Enter {item_name} manually", default=current_value if current_value is not None else default_value, console=console).strip()
            if not edited_value and item_name != "mitigation": 
                console.print(f"{EMOJI_WARNING} [yellow]{item_name.capitalize()} cannot be empty. Keeping previous: '{current_value}'[/yellow]")
            else:
                console.print(Padding(f"{EMOJI_SUCCESS} {item_name.capitalize()} manually set to: '[bold green]{edited_value}[/bold green]'",(1,0)))
                return edited_value, "manual_edit"

def llm_generate_title(description, component_name):
    """Generates a CVE title using LLM."""
    if not description or description == "N/A": return "[Title generation skipped: missing description]"
    print_step_context("generate_title")
    prompt = ( "Generate a concise and informative title for a CVE. The title should ideally include the affected component and the type of vulnerability.\n"
        "Avoid generic phrases like 'A vulnerability exists'. Focus on specifics if clear from the description.\n"
        "Target length: 5-10 words.\n"
        f"Affected Component (if known): {component_name if component_name else 'Unknown'}\n"
        f"CVE Description:\n{description}\n\nSuggested CVE Title:" )
    response = None
    with console.status(f"[bold green]{EMOJI_AI} LLM ({MODEL_NAME}) suggesting title...[/bold green]", spinner="dots"): response = call_llm(prompt)
    return response if response else "[LLM failed to generate title]"

def llm_generate_summary(description, component_name, cwe_id=None, cvss_vector=None):
    """Generates a brief CVE summary using LLM."""
    if not description or description == "N/A": return "[Summary generation skipped: missing description]"
    print_step_context("generate_summary")
    
    context_str = f"- Affected Component: {component_name if component_name else 'Unknown'}\n"
    if cwe_id: context_str += f"- CWE: {cwe_id}\n"
    if cvss_vector: context_str += f"- CVSS Vector Hint: {cvss_vector}\n"
    context_str += f"- Full Description:\n{description}"

    prompt = ( "You are a security analyst. Based *only* on the provided information, write a concise technical summary of the vulnerability (2-4 sentences).\n"
        "The summary should clearly state:\n"
        "1. The affected component/software.\n"
        "2. The type of vulnerability (e.g., buffer overflow, XSS, SQL injection, use-after-free, etc.).\n"
        "3. The potential impact or consequence if exploited (e.g., remote code execution, denial of service, information disclosure).\n"
        "4. Optionally, the attack vector if clearly identifiable (e.g., 'via a crafted request', 'by a local authenticated user').\n"
        "DO NOT invent details not present in the input. DO NOT include mitigation advice or CVSS scores in this summary.\n"
        "Start the summary directly (e.g., '{Component} is vulnerable to a {type of vulnerability}...').\n\n"
        f"**Input Information:**\n{context_str}\n\n**Concise Technical Summary:**" )
    response = None
    with console.status(f"[bold green]{EMOJI_AI} LLM ({MODEL_NAME}) generating summary...[/bold green]", spinner="dots"): response = call_llm(prompt, temperature=0.4) 
    return response if response else "[LLM failed to generate summary]"

def llm_generate_explanation(description, component_name, cwe_id=None):
    """Generates a more detailed explanation of how the vulnerability works."""
    if not description or description == "N/A": return "[Explanation generation skipped: missing description]"
    print_step_context("generate_explanation")

    context_str = f"- Affected Component: {component_name if component_name else 'Unknown'}\n"
    if cwe_id: context_str += f"- CWE: {cwe_id}\n"
    context_str += f"- Full Description:\n{description}"

    prompt = ( "Explain the technical workings of the vulnerability described below in a way that is understandable to a developer or security enthusiast. \n"
        "Focus on:\n"
        "1. The root cause of the flaw (e.g., lack of input sanitization, improper memory management, flawed logic).\n"
        "2. How an attacker might trigger or exploit this flaw (a conceptual exploitation path).\n"
        "3. The direct technical consequence of a successful exploit (e.g., overwriting memory, executing arbitrary commands, bypassing security checks).\n"
        "Avoid simply restating the impact; explain the 'how'. Use analogies if helpful for complex concepts.\n"
        "Be detailed but stick to information inferable from the provided description.\n\n"
        f"**Input Information:**\n{context_str}\n\n**Technical Explanation of the Vulnerability:**"
    )
    response = None
    with console.status(f"[bold green]{EMOJI_AI} LLM ({MODEL_NAME}) generating explanation...[/bold green]", spinner="dots"): response = call_llm(prompt, temperature=0.5)
    return response if response else "[LLM failed to generate explanation]"


def llm_suggest_mitigation(description):
    """Uses LLM to extract potential mitigation actions from a CVE description."""
    if not description or description == "N/A": return None
    print_step_context("generate_mitigation")
    prompt = f"""Analyze the following CVE description to identify and extract specific, actionable workaround or temporary mitigation steps.

Rules:
1.  Focus ONLY on temporary mitigations or workarounds (e.g., "disable feature X", "filter input Y", "change configuration Z").
2.  EXCLUDE any mention of permanent fixes like "upgrade to version X.Y.Z" or "apply patch ABC".
3.  If a workaround is found, state the action concisely (e.g., "disable the vulnerable module", "restrict access to the affected endpoint").
4.  If multiple distinct workarounds (not patches) are listed, try to combine them or list the most prominent ones.
5.  If no such workaround (distinct from patching/upgrading) is found, output the exact phrase: {NO_WORKAROUND_FOUND_MARKER}

CVE Description:
'''
{description}
'''

Extracted Workaround/Mitigation Action(s) (or {NO_WORKAROUND_FOUND_MARKER}):"""
    response = None
    with console.status(f"[bold green]{EMOJI_AI} LLM ({MODEL_NAME}) analyzing for mitigations...[/bold green]", spinner="dots"): response = call_llm(prompt)
    
    if response:
        response_stripped = response.strip()
        if response_stripped == NO_WORKAROUND_FOUND_MARKER: return NO_WORKAROUND_FOUND_MARKER
        elif response_stripped:
            if response_stripped and response_stripped[0].isupper() and len(response_stripped.split()) > 1 and not response_stripped.split()[0].isupper():
                response_stripped = response_stripped[0].lower() + response_stripped[1:]
            return response_stripped
        else: console.print(f"{EMOJI_WARNING} [yellow]LLM returned an empty response for mitigation analysis.[/yellow]"); return None
    else: return None

def manage_llm_generated_item(item_name, generation_func, *args, display_hints_func=None, hints_args=None):
    """Manages the generation, display, and confirmation of an LLM-generated item."""
    current_value = None
    
    while True:
        if display_hints_func and hints_args:
            display_hints_func(*hints_args)

        if current_value is None: 
            current_value = generation_func(*args)
            if item_name == "mitigation" and current_value == NO_WORKAROUND_FOUND_MARKER:
                current_value = GENERIC_MITIGATION_NOT_FOUND_TEXT 
            elif item_name == "mitigation" and current_value is None: 
                 current_value = GENERIC_MITIGATION_NOT_FOUND_TEXT 

        prompt_text = f"Review the suggested {item_name}."
        
        if item_name == "mitigation" and current_value == GENERIC_MITIGATION_NOT_FOUND_TEXT:
            console.print(f"\n{EMOJI_AI} Current {item_name}: '[bold yellow]{current_value}[/bold yellow]'")
            console.print(f"\n  [b]1[/b]: Accept (no specific mitigation found)")
            console.print(f"  [b]2[/b]: Try to regenerate {item_name} (using LLM)") 
            console.print(f"  [b]3[/b]: Enter {item_name} manually")
            choice = Prompt.ask(f"{EMOJI_EDIT} Enter your choice for {item_name}", choices=["1", "2", "3"], default="1", console=console)
            
            if choice == "1":
                console.print(Padding(f"{EMOJI_SUCCESS} {item_name.capitalize()} confirmed as: '[bold green]{current_value}[/bold green]'",(1,0)))
                return current_value
            elif choice == "2":
                current_value = None 
                continue
            elif choice == "3":
                edited_value = Prompt.ask(f"{EMOJI_EDIT} Enter {item_name} manually (can be left blank if none)", default="", console=console).strip()
                console.print(Padding(f"{EMOJI_SUCCESS} {item_name.capitalize()} manually set to: '[bold green]{edited_value if edited_value else 'None/Empty'}[/bold green]'",(1,0)))
                return edited_value
        else: 
            confirmed_value, action = confirm_or_edit_via_prompt(prompt_text, current_value, item_name=item_name)
            if action == "regenerate":
                current_value = None 
                continue
            else: 
                return confirmed_value


# --- Main Script Execution (`main` function) ---
def main():
    parser = argparse.ArgumentParser(
        description="CVE Insight: Fetches, analyzes, and explains CVE information using public sources and local LLMs.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("cve", help="CVE ID to process (e.g., CVE-2023-12345)")
    parser.add_argument("--skip-llm", action="store_true", help="Skip all LLM-based analysis and generation steps.")
    parser.add_argument("--skip-debian", action="store_true", help="Skip fetching data from Debian Security Tracker.")
    parser.add_argument("--skip-pocs", action="store_true", help="Skip searching for PoCs on GitHub.")


    args = parser.parse_args()
    cve_id = args.cve.strip().upper()

    console.print(Rule(f"[bold sky_blue1]{EMOJI_TOOL} Processing {cve_id} {EMOJI_TOOL}[/bold sky_blue1]"))

    print_step_context("fetch_nvd")
    nvd_data = fetch_nvd_data_raw(cve_id)
    
    print_step_context("fetch_cve_org")
    mitre_data = fetch_mitre_data_raw(cve_id)

    debian_data = None
    if not args.skip_debian:
        debian_data = fetch_debian_security_data(cve_id)

    github_pocs = []
    if not args.skip_pocs:
        github_pocs = fetch_github_pocs(cve_id)

    cve_description = get_cve_description_from_sources(cve_id, nvd_data, mitre_data)
    if cve_description:
        console.print(Panel(Markdown(cve_description), title=f"{EMOJI_LIST} CVE Description ({cve_id})", border_style="green", expand=True))
    else:
        console.print(f"{EMOJI_WARNING} [yellow]Could not retrieve a description for {cve_id}. LLM analysis will be limited.[/yellow]")
        if args.skip_llm: 
            console.print(f"{EMOJI_ERROR} [red]No description and LLM skipped. Exiting.[/red]")
            return

    display_cvss_metrics(nvd_data, mitre_data, cve_id)

    print_step_context("display_cwe")
    cwe_id = extract_cwe_id(nvd_data, mitre_data)
    if cwe_id:
        console.print(Panel(f"Identified CWE: [bold cyan]{cwe_id}[/bold cyan]", title=f"{EMOJI_CHECK} CWE Information", border_style="cyan", expand=False))
    else:
        console.print(f"{EMOJI_INFO} No CWE ID found in NVD or MITRE data for {cve_id}.")

    if debian_data:
        display_debian_data(debian_data, cve_id)
    
    if github_pocs:
        display_github_pocs(github_pocs, cve_id)

    if not args.skip_llm:
        if not cve_description: 
            console.print(f"{EMOJI_WARNING} [bold yellow]Skipping LLM analysis as no CVE description is available.[/bold yellow]")
        else:
            mitre_vendor_products = get_cve_vendor_product_mitre(cve_id, mitre_data)
            nvd_cpe_components = extract_components_from_nvd_cpes(nvd_data)
            
            def display_component_hints(m_vp, n_cpe): 
                if m_vp or n_cpe:
                    console.print(Rule("[dim]Hints for Component Identification[/dim]", style="dim"))
                    if m_vp: console.print(f"[italic]MITRE Products:[/italic] {', '.join([f'{v}/{p}' for v,p in m_vp[:3]])}{'...' if len(m_vp) > 3 else ''}")
                    if n_cpe: console.print(f"[italic]NVD CPEs:[/italic] {', '.join(n_cpe[:3])}{'...' if len(n_cpe) > 3 else ''}")

            suggested_component = manage_llm_generated_item(
                "component",
                llm_suggest_component,
                cve_description, mitre_vendor_products, nvd_cpe_components,
                display_hints_func=display_component_hints,
                hints_args=(mitre_vendor_products, nvd_cpe_components)
            )
            console.print(Panel(f"Final Component: [bold green]{suggested_component if suggested_component else 'Not specified'}[/bold green]", title=f"{EMOJI_SAVE} Selected Component", border_style="green", expand=False))

            suggested_title = manage_llm_generated_item(
                "title",
                llm_generate_title,
                cve_description, suggested_component
            )
            console.print(Panel(f"Final Title: [bold green]{suggested_title}[/bold green]", title=f"{EMOJI_SAVE} Selected Title", border_style="green", expand=False))

            primary_cvss_obj = None
            if nvd_data and nvd_data.get("metrics"): 
                all_nvd_metrics = (nvd_data["metrics"].get("cvssMetricV31", []) + 
                                   nvd_data["metrics"].get("cvssMetricV30", []) +
                                   nvd_data["metrics"].get("cvssMetricV40", []))
                primary_nvd_metric = get_primary_cvss_metric(all_nvd_metrics)
                if primary_nvd_metric: primary_cvss_obj = primary_nvd_metric.get("cvssData")

            suggested_summary = manage_llm_generated_item(
                "summary",
                llm_generate_summary,
                cve_description, suggested_component, cwe_id, primary_cvss_obj.get("vectorString") if primary_cvss_obj else None
            )
            console.print(Panel(Markdown(suggested_summary), title=f"{EMOJI_SAVE} Selected Vulnerability Summary", border_style="green", expand=True))
            
            suggested_explanation = manage_llm_generated_item(
                "explanation",
                llm_generate_explanation,
                cve_description, suggested_component, cwe_id
            )
            console.print(Panel(Markdown(suggested_explanation), title=f"{EMOJI_SAVE} Selected Vulnerability Explanation", border_style="green", expand=True))

            suggested_mitigation = manage_llm_generated_item(
                "mitigation",
                llm_suggest_mitigation,
                cve_description
            )
            mitigation_display_text = suggested_mitigation if suggested_mitigation and suggested_mitigation != GENERIC_MITIGATION_NOT_FOUND_TEXT else GENERIC_MITIGATION_NOT_FOUND_TEXT
            console.print(Panel(f"Final Mitigation Advice: [bold green]{mitigation_display_text}[/bold green]", title=f"{EMOJI_SAVE} Selected Mitigation", border_style="green", expand=False))

    console.print(Rule(f"[bold sky_blue1]{EMOJI_SUCCESS} CVE Insight processing complete for {cve_id} {EMOJI_SUCCESS}[/bold sky_blue1]"))

if __name__ == "__main__":
    main()
