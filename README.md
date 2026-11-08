# vah-DependencyChecker

Analyzes a project's requirements.txt file against locally stored NVD 1.1 XML feeds (nvdcve-1.1-<year>.xml.gz) and reports dependencies whose version specifier matches a vulnerable CPE product version in the feed. Exact pins are compared as real versions, so `==2.0` matches a CPE version of 2.0.0 and a wildcard pin such as `==2.31.*` matches 2.31.0. Severity is read from the CVSS v2 baseMetricV2 element by local name, so it is found whether the feed places those elements in the CVSS v2 namespace or the feed default namespace. The tool refuses to print a clean verdict when no CVE entries were loaded. With `--update_nvd` it first tries to download the feeds for the last six years from nvd.nist.gov and reports partial or total download failure honestly.

## Install
`git clone https://github.com/ShadowGuard-AI/vah-dependencychecker.git`

## Usage
`python3 main.py requirements.txt [--nvd_data_dir DIR] [--update_nvd] [--log_level LEVEL]`

## Parameters
- `-h`: Show help message and exit
- `requirements_file`: Path to the requirements.txt file (positional, required).
- `--nvd_data_dir`: Directory to store NVD data feeds (default: nvd_data).
- `--update_nvd`: Update the NVD data feeds before analysis.
- `--log_level`: Set the logging level: DEBUG, INFO, WARNING, ERROR, or CRITICAL (default: INFO).

## License
MIT License. See LICENSE.
