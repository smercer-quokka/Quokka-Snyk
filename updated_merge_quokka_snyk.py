import json
import pandas as pd
import requests
from time import sleep

def pushScan(apiKey, theFile):
    app_file = {"app": open(theFile, "rb")}
    thePlatform = "android"
    if theFile[-3:].lower() == "ipa":
        thePlatform = "ios"
    params = {"key": apiKey, "platform": thePlatform}
    r = requests.post(
        "https://emm.kryptowire.com/api/submit", data=params, files=app_file
    )
    print(r.json())
    return r.json(), thePlatform

def downloadQuokkaJSON(apiKey, uuid):
    status = "processing"
    while status == "processing":
        print("Waiting for analysis to complete.\n")
        params = {"key": apiKey, "uuid": uuid}

        r = requests.get("https://emm.kryptowire.com/api/status", params=params)
        status = r.json()["status"]
        print(status)
        sleep(15)

    try:
        download_r = requests.get(
            "https://emm.kryptowire.com/api/results/json", params=params
        )
        return download_r.json()
    except Exception as err:
        print("Issue retrieving Quokka JSON, please download manually")

def retrieveSnykJSON(apiKey, orgID, projectID):
    try:
        url = f"https://api.snyk.io/rest/orgs/{orgID}/issues?version=2023-11-27~beta"
        headers = {
            "Accept": "application/vnd.api+json",
            "Authorization": f"token {apiKey}",
            "User-Agent": 'quokka-snyk-0.0.0'
        }

        response = requests.get(url, headers=headers)
        response_json = response.json()

        # Filter issues by projectID
        filtered_issues = [
            issue for issue in response_json.get("data", [])
            if issue.get("relationships", {}).get("scan_item", {}).get("data", {}).get("id") == projectID
        ]

        return {"data": filtered_issues}
    except Exception as err:
        print("Issue downloading JSON from Snyk:", err)
        return {"data": []}

# Load configuration from config.json
with open("config.json", "r") as config_file:
    config = json.load(config_file)

quokka_api_key = config["quokka_api_key"]
snyk_api_key = config["snyk_api_key"]
binary = config["binary"]
snyk_org_id = config["snyk_org_id"]
snyk_project_id = config["snyk_project_id"]
quokka_uuid = config.get("quokka_uuid")

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

# Merge issues and output to CSV
joint_dict_list = []

for issue in snyk_issue_data["data"]:
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

for issue in quokka_issue_data["app_issues"]:
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

combined_df = pd.DataFrame(joint_dict_list)

combined_df.to_csv("combined.csv", index=False)