import json
import pandas as pd
import argparse
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


def retrieveSnykJSON(apiKey, orgID):
    try:
        url = f"https://api.snyk.io/rest/orgs/{orgID}/issues?version=2023-11-27~beta"
        payload = {}
        headers = {
            "Accept": "application/vnd.api+json",
            "Authorization": f"token {apiKey}",
        }

        response = requests.request("GET", url, headers=headers, data=payload)
        return response.json()
    except Exception as err:
        print("Issue downloading JSON from Snyk")

# Arguments
parser = argparse.ArgumentParser(
    prog="QuokkaSnyk",
    description="Takes an app binary for analysis with Quokka and compares any found issues to those found by Snyk by org ID",
    epilog="Quokka Inc. 2023",
)

parser.add_argument("quokkaapikey", type=str, help="The Quokka API key")
parser.add_argument("snykapikey", type=str, help="The Snyk API key")
parser.add_argument(
    "binary", type=str, help="Filename of APK or IPA for Quokka Analysis"
)
parser.add_argument("snykorgid", type=str, help="Org ID of Snyk for analysed code")
parser.add_argument("--quokkauuid", type=str, help="UUID of already processed Quokka app")
args = parser.parse_args()

# Upload App Binary and Download Quokka JSON
if not args.quokkauuid:
    scan_response, platform_name = pushScan(args.quokkaapikey, args.binary)
    uuid = scan_response["uuid"]
else:
    uuid = args.quokkauuid
    platform_name = "android"

quokka_issue_data = downloadQuokkaJSON(args.quokkaapikey, uuid)

# Download the issues from Snyk
snyk_issue_data = retrieveSnykJSON(args.snykapikey, args.snykorgid)


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
        "Project URL": f"https://app.snyk.io/org/quokka-nfr-shared/project/{issue['relationships']['scan_item']['data']['id']}",
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

combined_df.to_csv("combined.csv")
