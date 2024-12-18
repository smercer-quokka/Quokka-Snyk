
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
    """Retrieve issues from Snyk API and filter by project ID."""
    try:
        url = f"https://api.snyk.io/rest/orgs/{orgID}/issues?version=2023-11-27~beta"
        headers = {
            "Accept": "application/vnd.api+json",
            "Authorization": f"token {apiKey}",
            "User-Agent": 'quokka-snyk-0.0.0'
        }

        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()

        response_json = response.json()
        filtered_issues = [
            issue for issue in response_json.get("data", [])
            if issue.get("relationships", {}).get("scan_item", {}).get("data", {}).get("id") == projectID
        ]

        return {"data": filtered_issues}
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
        row_dict = {
            "id": issue["id"],
            "Found by": "Snyk",
            "Issue Severity": issue["attributes"]["effective_severity_level"],
            "Score": issue["attributes"]["risk"]["score"]["value"],
            "Problem title": issue["attributes"]["title"],
            "CWE": issue["attributes"]["classes"][0]["id"],
            "CVSS Score": "NA",
            "Project URL": f"https://app.snyk.io/org/{snyk_org_id}/project/{issue['relationships']['scan_item']['data']['id']}",
            "Issue status": issue["attributes"]["status"],
            "Issue type": issue["attributes"]["problems"][0]["type"],
        }
        joint_dict_list.append(row_dict)

    for issue in quokka_issues["app_issues"]:
        if issue["found"]:
            row_dict = {
                "id": issue["id"],
                "Found by": "Quokka",
                "Issue Severity": issue["risk"],
                "Score": "NA",
                "Problem title": issue["positive_finding_text"],
                "CWE": issue["cwe"],
                "CVSS Score": issue["cvss_score"],
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
    platform_name = "android"

quokka_issue_data = downloadQuokkaJSON(quokka_api_key, uuid)

# Download the issues from Snyk with filtering
snyk_issue_data = retrieveSnykJSON(snyk_api_key, snyk_org_id, snyk_project_id)

# Merge issues and save to CSV
merge_issues_and_save(quokka_issue_data, snyk_issue_data, platform_name, uuid, snyk_org_id)
