# QuokkaSnyk

Merges Snyk and Quokka security product results for comprehensive vulnerability assessment.

## Overview

This script streamlines the comparison of security vulnerabilities identified by Snyk (code analysis) and Quokka (mobile app analysis). It retrieves results from both platforms, merges them into a unified CSV report, and highlights potential discrepancies for further investigation. This enhanced visibility empowers you to make informed decisions and prioritize remediation efforts effectively.

## Usage

Install Dependencies:

```
pip install pandas requests argparse
```

Execute the Script:

```
python QuokkaSnyk.py <quokkaapikey> <snykapikey> <binary> <snykorgid> [--quokkauuid <uuid>]
```

## Arguments

`quokkaapikey`: Your Quokka API key.

`snykapikey`: Your Snyk API key.

`binary`: The filename of the APK or IPA file to be analyzed by Quokka.

`snykorgid`: The Snyk organization ID for the analyzed code.

`--quokkauuid` (optional): The UUID of an already processed Quokka app, for direct results retrieval.

## Output

Generates a CSV file named combined.csv, containing merged vulnerability data from both Snyk and Quokka.

## Key Features

Combines insights from two leading security platforms.
Unifies issue reporting for clarity and efficiency.
Facilitates comprehensive vulnerability assessment.
Helps prioritize remediation efforts effectively.
## Developed by: Quokka Inc., 2024