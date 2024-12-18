
# Quokka-Snyk Analysis Script

This script analyzes a mobile application binary using the Quokka API and retrieves vulnerabilities found by Snyk for a specified project. It then merges the results from both sources and saves them into a combined CSV file.

## Features

- **Uploads a mobile binary** (APK or IPA) to Quokka for analysis.
- **Retrieves vulnerabilities** from the Snyk API for a specified organization and project.
- **Handles pagination** to fetch all available issues from Snyk.
- **Filters Snyk issues** by project ID.
- **Combines the results** from Quokka and Snyk into a CSV file.

## Prerequisites

1. **Python 3.x**
2. Required Python libraries:
    - `requests`
    - `pandas`

   Install them using pip:

   ```bash
   pip install requests pandas
   ```

3. **API Keys**:
    - **Quokka API Key**: Needed to interact with the Quokka API.
    - **Snyk API Key**: Needed to fetch issues from Snyk.

## Configuration File

Create a `config.json` file in the same directory as the script with the following structure:

```json
{
  "quokka_api_key": "your-quokka-api-key",
  "snyk_api_key": "your-snyk-api-key",
  "binary": "path/to/your/binary.apk",
  "snyk_org_id": "your-snyk-org-id",
  "snyk_project_id": "your-snyk-project-id",
  "quokka_uuid": null,
  "platform": "mobile-os (android/ios)",
  "snyk_org_url": "org_url"
}
```

- **`quokka_api_key`**: Your Quokka API key.
- **`snyk_api_key`**: Your Snyk API key.
- **`binary`**: Path to the APK or IPA file for analysis.
- **`snyk_org_id`**: The Snyk organization ID.
- **`snyk_project_id`**: The Snyk project ID to filter the issues.
- **`quokka_uuid`**: (Optional) If you already have a Quokka UUID, you can provide it to skip the upload process.
- **`platform`**: Mobile operationg system for the application you are scanning
- **`snyk_org_url`**: URL in your snyk org to combile issue links i.e. https://app.snyk.io/org/quokka-nfr-shared

## How to Run the Script

1. Ensure your `config.json` file is correctly set up.
2. Run the script:

   ```bash
   python quokka_snyk_analysis.py
   ```

3. The combined results will be saved in a CSV file named `combined.csv` in the current directory.

## Output

The output CSV file contains the following columns:

- **id**: Issue ID.
- **Found by**: Indicates whether the issue was found by Quokka or Snyk.
- **Issue Severity**: The severity level of the issue.
- **Score**: The risk score (for Snyk issues).
- **Problem title**: A brief description of the issue.
- **CWE**: The CWE ID associated with the issue.
- **CVSS Score**: The CVSS score (for Quokka issues).
- **Project URL**: A link to the project or analysis report.
- **Issue status**: The status of the issue (e.g., open, closed).
- **Issue type**: The type of issue (e.g., vulnerability).

## Logging

The script uses the `logging` module for better debugging and tracking. Logs will be printed to the console.

## Troubleshooting

- **Config File Not Found**: Ensure `config.json` exists in the same directory as the script.
- **API Errors**: Verify that your API keys are correct and have the necessary permissions.
- **Network Issues**: Ensure you have a stable internet connection.

## License

This script is provided under the MIT License.
