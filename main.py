import argparse
import logging
import os
import sys
import requests
import lxml.etree as ET
from packaging import version
from packaging.requirements import Requirement
from typing import List, Dict, Tuple

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
NVD_DATA_FEED_URL = "https://nvd.nist.gov/feeds/xml/cve/nvdcve-1.1-{year}.xml.gz"
NVD_DATA_DIR = "nvd_data"


def setup_argparse() -> argparse.ArgumentParser:
    """
    Sets up the argument parser for the CLI.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(description="vah-DependencyChecker: Analyzes project dependencies for known vulnerabilities.")
    parser.add_argument("requirements_file", help="Path to the requirements.txt file.")
    parser.add_argument("--nvd_data_dir", default="nvd_data", help="Directory to store NVD data feeds (default: nvd_data)")
    parser.add_argument("--update_nvd", action="store_true", help="Update the NVD data feeds before analysis.")
    parser.add_argument("--log_level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Set the logging level (default: INFO)")
    return parser


def download_nvd_feed(year: int, data_dir: str) -> None:
    """
    Downloads the NVD data feed for a given year.

    Args:
        year (int): The year for which to download the NVD data feed.
        data_dir (str): The directory to store the downloaded data.
    """
    url = NVD_DATA_FEED_URL.format(year=year)
    filename = os.path.join(data_dir, f"nvdcve-1.1-{year}.xml.gz")
    logging.info(f"Downloading NVD data feed for {year} from {url} to {filename}")
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

        os.makedirs(data_dir, exist_ok=True)
        with open(filename, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        logging.info(f"Successfully downloaded NVD data feed for {year}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error downloading NVD data feed for {year}: {e}")
        raise


def update_nvd_data(data_dir: str) -> None:
    """
    Updates the NVD data feeds for the last 5 years.

    Args:
        data_dir (str): The directory to store the NVD data feeds.
    """
    current_year = datetime.datetime.now().year
    for year in range(current_year - 5, current_year + 1):
        try:
            download_nvd_feed(year, data_dir)
        except Exception as e:
            logging.error(f"Failed to download data for year {year}: {e}")


def parse_requirements_file(requirements_file: str) -> List[Tuple[str, str]]:
    """
    Parses a requirements.txt file and extracts package names and versions.

    Args:
        requirements_file (str): The path to the requirements.txt file.

    Returns:
        List[Tuple[str, str]]: A list of tuples containing package name and version string.
    """
    dependencies = []
    try:
        with open(requirements_file, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    try:
                        req = Requirement(line)
                        name = req.name
                        version_specifier = ""
                        for spec in req.specifier:
                             version_specifier += str(spec)


                        dependencies.append((name, version_specifier))
                    except Exception as e:
                        logging.warning(f"Could not parse requirement line: {line}.  Error: {e}")
    except FileNotFoundError:
        logging.error(f"Requirements file not found: {requirements_file}")
        raise
    return dependencies


def load_nvd_data(data_dir: str) -> Dict[str, Dict]:
    """
    Loads NVD data from XML files in the specified directory.

    Args:
        data_dir (str): The directory containing the NVD data files.

    Returns:
        Dict[str, Dict]: A dictionary mapping CVE IDs to vulnerability information.
    """
    vulnerabilities = {}
    for filename in os.listdir(data_dir):
        if filename.endswith(".xml.gz"):
            filepath = os.path.join(data_dir, filename)
            try:
                 #gunzip the file before parsing since lxml doesn't handle it directly
                 import gzip
                 with gzip.open(filepath, 'rb') as f:
                     xml_content = f.read()

                 tree = ET.fromstring(xml_content) #parse from string since we ungzipped it.
                 for entry in tree.findall(".//{http://nvd.nist.gov/feeds/xml/cve/1.1}entry"):
                     cve_id = entry.find(".//{http://nvd.nist.gov/feeds/xml/cve/1.1}cve-id").text
                     vulnerabilities[cve_id] = {}
                     cvss_v2 = entry.find(".//{http://nvd.nist.gov/feeds/xml/cve/1.1}cvss/baseMetricV2/severity")
                     if cvss_v2 is not None:
                        vulnerabilities[cve_id]["severity"] = cvss_v2.text
                     else:
                         vulnerabilities[cve_id]["severity"] = "N/A"

                     # Extract affected products and versions (simplified for example)
                     affected_products = []
                     for product in entry.findall(".//{http://nvd.nist.gov/feeds/xml/cve/1.1}product"):
                        affected_products.append(product.text) #Add the CPE string
                     vulnerabilities[cve_id]["affected_products"] = affected_products

            except ET.XMLSyntaxError as e:
                logging.error(f"Error parsing XML file {filepath}: {e}")
            except gzip.BadGzipFile as e:
                 logging.error(f"Error decompressing gzip file {filepath}: {e}")
            except Exception as e:
                logging.error(f"Error loading NVD data from {filepath}: {e}")
    return vulnerabilities


def check_dependencies_for_vulnerabilities(dependencies: List[Tuple[str, str]], vulnerabilities: Dict[str, Dict]) -> List[Dict]:
    """
    Checks the given dependencies against the loaded NVD data for vulnerabilities.

    Args:
        dependencies (List[Tuple[str, str]]): A list of tuples containing package name and version.
        vulnerabilities (Dict[str, Dict]): A dictionary mapping CVE IDs to vulnerability information.

    Returns:
        List[Dict]: A list of dictionaries, each containing vulnerability information for a dependency.
    """
    vulnerable_dependencies = []
    for package_name, package_version_specifier in dependencies:
        for cve_id, vulnerability_data in vulnerabilities.items():
            if "affected_products" in vulnerability_data:

                for product in vulnerability_data["affected_products"]:
                    if package_name.lower() in product.lower():
                            vulnerable_dependencies.append({
                                "package": package_name,
                                "version_specifier": package_version_specifier,
                                "cve_id": cve_id,
                                "severity": vulnerability_data["severity"],
                                "affected_product": product
                            })

    return vulnerable_dependencies


def generate_report(vulnerable_dependencies: List[Dict]) -> None:
    """
    Generates a report of vulnerable dependencies.

    Args:
        vulnerable_dependencies (List[Dict]): A list of dictionaries, each containing vulnerability information.
    """
    if vulnerable_dependencies:
        print("Vulnerable Dependencies Found:")
        for vulnerability in vulnerable_dependencies:
            print(f"  Package: {vulnerability['package']}")
            print(f"  Version specifier: {vulnerability['version_specifier']}")
            print(f"  CVE ID: {vulnerability['cve_id']}")
            print(f"  Severity: {vulnerability['severity']}")
            print(f"  Affected Product: {vulnerability['affected_product']}")
            print("-" * 30)
    else:
        print("No known vulnerabilities found in the specified dependencies.")


def main() -> None:
    """
    Main function to execute the vulnerability checker.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Set logging level
    logging.getLogger().setLevel(args.log_level)

    # Validate input
    if not os.path.exists(args.requirements_file):
        logging.error(f"Requirements file not found: {args.requirements_file}")
        sys.exit(1)

    # Update NVD data if requested
    if args.update_nvd:
        try:
            update_nvd_data(args.nvd_data_dir)
        except Exception as e:
            logging.error(f"Failed to update NVD data: {e}")
            sys.exit(1)

    # Load NVD data
    try:
        vulnerabilities = load_nvd_data(args.nvd_data_dir)
    except Exception as e:
        logging.error(f"Failed to load NVD data: {e}")
        sys.exit(1)


    # Parse requirements file
    try:
        dependencies = parse_requirements_file(args.requirements_file)
    except Exception as e:
        logging.error(f"Failed to parse requirements file: {e}")
        sys.exit(1)



    # Check dependencies for vulnerabilities
    vulnerable_dependencies = check_dependencies_for_vulnerabilities(dependencies, vulnerabilities)

    # Generate report
    generate_report(vulnerable_dependencies)


if __name__ == "__main__":
    import datetime
    main()


# Usage Examples:
# 1. Analyze a requirements.txt file:
#    python vah-DependencyChecker.py requirements.txt
#
# 2. Update the NVD data before analysis:
#    python vah-DependencyChecker.py requirements.txt --update_nvd
#
# 3. Specify a different directory for NVD data:
#    python vah-DependencyChecker.py requirements.txt --nvd_data_dir nvd_data_custom
#
# 4. Set the logging level to DEBUG:
#    python vah-DependencyChecker.py requirements.txt --log_level DEBUG