
import json
import pandas as pd
import requests
from time import sleep
import logging

# Logging setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def load_config(file_path="config.json"):
    """Load configuration from a JSON file."""
    try:
        with open(file_path, "r") as config_file:
            return json.load(config_file)
    except FileNotFoundError:
        logging.error(f"Config file '{file_path}' not found.")
        exit(1)
    except json.JSONDecodeError:
        logging.error(f"Error decoding JSON in config file '{file_path}'.")
        exit(1)


def pushScan(apiKey, theFile):
    """Upload a binary file to the Quokka API for analysis."""
    try:
        with open(theFile, "rb") as app_file:
            app_file_payload = {"app": app_file}
            thePlatform = "android" if theFile.lower().endswith(".apk") else "ios"
            params = {"key": apiKey, "platform": thePlatform}

            r = requests.post("https://emm.kryptowire.com/api/submit", data=params, files=app_file_payload)
            r.raise_for_status()
            logging.info(f"Quokka scan initiated: {r.json()}")
            return r.json(), thePlatform
    except requests.exceptions.RequestException as e:
        logging.error(f"Error uploading to Quokka: {e}")
        exit(1)


def downloadQuokkaJSON(apiKey, uuid):
    """Download analysis results from Quokka API."""
    status = "processing"
    while status == "processing":
        logging.info("Waiting for analysis to complete.")
        params = {"key": apiKey, "uuid": uuid}

        try:
            r = requests.get("https://emm.kryptowire.com/api/status", params=params, timeout=30)
            r.raise_for_status()
            status = r.json()["status"]
            logging.info(f"Current status: {status}")
            sleep(15)
        except requests.exceptions.RequestException as e:
            logging.error(f"Error checking Quokka status: {e}")
            exit(1)

    try:
        download_r = requests.get("https://emm.kryptowire.com/api/results/json", params=params, timeout=30)
        download_r.raise_for_status()
        return download_r.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Issue retrieving Quokka JSON: {e}")
        exit(1)


def retrieveSnykJSON(apiKey, orgID, projectID):
    """Retrieve all issues from Snyk API, handling pagination, and filter by project ID."""
    try:
        base_url = f"https://api.snyk.io/rest/orgs/{orgID}/issues?version=2023-11-27~beta&limit=50"
        headers = {
            "Accept": "application/vnd.api+json",
            "Authorization": f"token {apiKey}",
            "User-Agent": 'quokka-snyk-0.0.0'
        }

        all_issues = []
        next_url = base_url

        while next_url:
            response = requests.get(next_url, headers=headers, timeout=30)
            response.raise_for_status()
            response_json = response.json()

            # Collect issues from the current page and filter by project ID
            filtered_issues = [
                issue for issue in response_json.get("data", [])
                if issue.get("relationships", {}).get("scan_item", {}).get("data", {}).get("id") == projectID
            ]
            all_issues.extend(filtered_issues)

            # Break the loop if the data object is empty
            if not response_json.get("data"):
                break

            # Check for the next page link
            next_url_path = response_json.get("links", {}).get("next")
            if next_url_path:
                next_url = f"https://api.snyk.io{next_url_path}"
            else:
                next_url = None

        return {"data": all_issues}

    except requests.exceptions.RequestException as e:
        logging.error(f"Network error while retrieving Snyk JSON: {e}")
        return {"data": []}
    except json.JSONDecodeError:
        logging.error("Error decoding JSON response from Snyk")
        return {"data": []}


def merge_issues_and_save(quokka_issues, snyk_issues, platform_name, uuid, snyk_org_id, output_file="combined.csv"):
    """Merge Quokka and Snyk issues and save to a CSV file."""
    joint_dict_list = []

    for issue in snyk_issues["data"]:
        # Safely access nested keys with default values
        risk_score = issue.get("attributes", {}).get("risk", {}).get("score", {}).get("value", "NA")
        effective_severity_level = issue.get("attributes", {}).get("effective_severity_level", "NA")
        title = issue.get("attributes", {}).get("title", "NA")
        cwe = issue.get("attributes", {}).get("classes", [{}])[0].get("id", "NA")
        status = issue.get("attributes", {}).get("status", "NA")
        issue_type = issue.get("attributes", {}).get("problems", [{}])[0].get("type", "NA")
        project_id = issue.get("relationships", {}).get("scan_item", {}).get("data", {}).get("id", "NA")
        key = issue.get("attributes", {}).get("key", "NA")

        row_dict = {
            "id": issue["id"],
            "Found by": "Snyk",
            "Issue Severity": effective_severity_level,
            "Score": risk_score,
            "Problem title": title,
            "CWE": cwe,
            "CVSS Score": "NA",
            "Project URL": f"{snyk_org_url}/project/{project_id}#issue-{key}",
            "Issue status": status,
            "Issue type": issue_type,
        }
        joint_dict_list.append(row_dict)

    for issue in quokka_issues["app_issues"]:
        if issue["found"]:
            row_dict = {
                "id": issue["id"],
                "Found by": "Quokka",
                "Issue Severity": issue.get("risk", "NA"),
                "Score": "NA",
                "Problem title": issue.get("positive_finding_text", "NA"),
                "CWE": issue.get("cwe", "NA"),
                "CVSS Score": issue.get("cvss_score", "NA"),
                "Project URL": f"https://emm.krwr.net/#/{platform_name}-report/{uuid}",
                "Issue status": "open",
                "Issue type": "vulnerability",
            }
            joint_dict_list.append(row_dict)

    df = pd.DataFrame(joint_dict_list)

    try:
        df.to_csv(output_file, index=False)
        logging.info(f"Combined CSV file '{output_file}' has been created successfully.")
    except Exception as e:
        logging.error(f"Error writing to CSV file: {e}")


# Load configuration
config = load_config()

# Extract configuration parameters
quokka_api_key = config["quokka_api_key"]
snyk_api_key = config["snyk_api_key"]
binary = config["binary"]
snyk_org_id = config["snyk_org_id"]
snyk_project_id = config["snyk_project_id"]
quokka_uuid = config.get("quokka_uuid")
platform = config.get("platform")
snyk_org_url = config.get("snyk_org_url")

# Ensure API keys are present
if not quokka_api_key or not snyk_api_key:
    logging.error("API keys for Quokka and/or Snyk are missing in the configuration.")
    exit(1)

# Upload App Binary and Download Quokka JSON
if not quokka_uuid:
    scan_response, platform_name = pushScan(quokka_api_key, binary)
    uuid = scan_response["uuid"]
else:
    uuid = quokka_uuid
    platform_name = platform

quokka_issue_data = downloadQuokkaJSON(quokka_api_key, uuid)

# Download the issues from Snyk with filtering
snyk_issue_data = retrieveSnykJSON(snyk_api_key, snyk_org_id, snyk_project_id)

# Merge issues and save to CSV
merge_issues_and_save(quokka_issue_data, snyk_issue_data, platform_name, uuid, snyk_org_id)
