# vah-DependencyChecker
Analyzes a project's requirements.txt or equivalent file and reports known vulnerabilities in the specified versions of the dependencies. - Focused on Assists in vulnerability assessment by providing utilities to parse common vulnerability data formats (e.g., NVD XML, CVRF), identify vulnerable software based on version strings, and generate basic reports summarizing potential risks. Enables users to quickly identify and prioritize vulnerabilities in their software stack based on CVE data and version information.

## Install
`git clone https://github.com/ShadowStrikeHQ/vah-dependencychecker`

## Usage
`./vah-dependencychecker [params]`

## Parameters
- `-h`: Show help message and exit
- `--nvd_data_dir`: No description provided
- `--update_nvd`: Update the NVD data feeds before analysis.
- `--log_level`: No description provided

## License
Copyright (c) ShadowStrikeHQ
