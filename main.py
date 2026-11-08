import argparse
import datetime
import logging
import os
import sys
import requests
import lxml.etree as ET
from packaging.specifiers import SpecifierSet
from packaging.version import Version, InvalidVersion
from packaging.requirements import Requirement
from typing import List, Dict, Tuple

MAX_DECOMPRESSED_BYTES = 100 * 1024 * 1024
DOWNLOAD_TIMEOUT = 30

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
        response = requests.get(url, stream=True, timeout=DOWNLOAD_TIMEOUT)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

        os.makedirs(data_dir, exist_ok=True)
        with open(filename, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        logging.info(f"Successfully downloaded NVD data feed for {year}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error downloading NVD data feed for {year}: {e}")
        raise


def update_nvd_data(data_dir: str):
    """Update feeds for the last 6 years. Returns (attempted, failed, failed_years)."""
    current_year = datetime.datetime.now().year
    attempted = 0
    failed_years = []
    for year in range(current_year - 5, current_year + 1):
        attempted += 1
        try:
            download_nvd_feed(year, data_dir)
        except Exception as e:
            failed_years.append(year)
            logging.error(f"Failed to download data for year {year}: {e}")
    return attempted, len(failed_years), failed_years


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


def _safe_parser():
    return ET.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)


def parse_cpe(product_str):
    """Parse a CPE string into (vendor, product, version) or None."""
    if not product_str:
        return None
    text = product_str.strip()
    if text.startswith("cpe:2.3:"):
        parts = text.split(":")
        if len(parts) >= 7:
            return parts[3].lower(), parts[4].lower(), parts[5]
        return None
    if text.startswith("cpe:/"):
        parts = text[5:].split(":")
        if len(parts) >= 4:
            return parts[1].lower(), parts[2].lower(), parts[3]
        if len(parts) == 3:
            return parts[1].lower(), parts[2].lower(), ""
        return None
    return None, text.lower(), ""


def load_nvd_data_with_stats(data_dir: str):
    vulnerabilities = load_nvd_data(data_dir)
    stats = getattr(load_nvd_data, "_last_stats", {"feeds_loaded": 0, "entries_loaded": len(vulnerabilities)})
    return vulnerabilities, stats


def load_nvd_data(data_dir: str) -> Dict[str, Dict]:
    """
    Loads NVD data from XML files in the specified directory.

    Args:
        data_dir (str): The directory containing the NVD data files.

    Returns:
        Dict[str, Dict]: A dictionary mapping CVE IDs to vulnerability information.
    """
    vulnerabilities = {}
    feeds_loaded = 0
    load_nvd_data._last_stats = {"feeds_loaded": 0, "entries_loaded": 0}
    for filename in os.listdir(data_dir):
        if filename.endswith(".xml.gz"):
            filepath = os.path.join(data_dir, filename)
            try:
                 import gzip
                 with gzip.open(filepath, 'rb') as f:
                     xml_content = f.read(MAX_DECOMPRESSED_BYTES + 1)
                 if len(xml_content) > MAX_DECOMPRESSED_BYTES:
                     logging.error(f"Feed {filepath} exceeds the decompressed size cap of {MAX_DECOMPRESSED_BYTES} bytes; skipped")
                     continue
                 tree = ET.fromstring(xml_content, parser=_safe_parser())
                 feeds_loaded += 1
                 for entry in tree.findall(".//{http://nvd.nist.gov/feeds/xml/cve/1.1}entry"):
                     cve_id = entry.find(".//{http://nvd.nist.gov/feeds/xml/cve/1.1}cve-id").text
                     vulnerabilities[cve_id] = {}
                     # Severity lives under baseMetricV2, whose child
                     # elements sit in the separate CVSS v2 namespace in
                     # real NVD 1.1 feeds, so match by local name instead
                     # of a namespace qualified path.
                     severity_nodes = entry.xpath(".//*[local-name()='baseMetricV2']/*[local-name()='severity']")
                     if severity_nodes and severity_nodes[0].text:
                        vulnerabilities[cve_id]["severity"] = severity_nodes[0].text
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
    load_nvd_data._last_stats = {"feeds_loaded": feeds_loaded, "entries_loaded": len(vulnerabilities)}
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
    seen = set()
    for package_name, package_version_specifier in dependencies:
        spec_set = None
        try:
            spec_set = SpecifierSet(package_version_specifier or "")
        except Exception:
            spec_set = None
        for cve_id, vulnerability_data in vulnerabilities.items():
            if "affected_products" not in vulnerability_data:
                continue
            for product in vulnerability_data["affected_products"]:
                parsed = parse_cpe(product)
                if not parsed:
                    continue
                _vendor, cpe_product, cpe_version = parsed
                if not cpe_product or cpe_product != package_name.lower().replace("-", "_"):
                    if not cpe_product or cpe_product != package_name.lower():
                        continue
                matched = False
                if cpe_version in ("", "*", "-"):
                    matched = True
                else:
                    try:
                        entry_v = Version(cpe_version)
                    except InvalidVersion:
                        continue
                    if spec_set is not None and len(spec_set) > 0:
                        # SpecifierSet.contains compares real Version
                        # objects, so ==2.0 matches CPE version 2.0.0 and
                        # ==2.31.* matches 2.31.0. Comparing version
                        # strings instead missed both of those.
                        matched = spec_set.contains(entry_v, prereleases=True)
                    else:
                        matched = False
                if matched:
                    key = (package_name, cve_id, product)
                    if key in seen:
                        continue
                    seen.add(key)
                    vulnerable_dependencies.append({
                        "package": package_name,
                        "version_specifier": package_version_specifier,
                        "cve_id": cve_id,
                        "severity": vulnerability_data["severity"],
                        "affected_product": product
                    })
    return vulnerable_dependencies


def generate_report(vulnerable_dependencies: List[Dict], stats=None) -> None:
    counts = ""
    if stats:
        counts = f" (feeds loaded: {stats.get('feeds_loaded', 0)}, CVE entries loaded: {stats.get('entries_loaded', 0)}, downloads failed: {stats.get('downloads_failed', 0)})"
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
        print(f"No known vulnerabilities found in the specified dependencies.{counts}")


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

    downloads_failed = 0
    attempted = 0
    failed_years = []
    if args.update_nvd:
        try:
            attempted, downloads_failed, failed_years = update_nvd_data(args.nvd_data_dir)
        except Exception as e:
            logging.error(f"Failed to update NVD data: {e}")
            sys.exit(1)
        if attempted and downloads_failed == attempted:
            logging.error(f"All {attempted} NVD feed downloads failed (years: {failed_years}); no data was loaded, so no clean verdict is possible.")
            sys.exit(1)
        if downloads_failed:
            logging.warning(f"Partial update: {downloads_failed} of {attempted} feed downloads failed (years: {failed_years}); report rests only on the feeds that loaded.")

    try:
        vulnerabilities, load_stats = load_nvd_data_with_stats(args.nvd_data_dir)
    except Exception as e:
        logging.error(f"Failed to load NVD data: {e}")
        sys.exit(1)
    stats = {"feeds_loaded": load_stats.get("feeds_loaded", 0), "entries_loaded": load_stats.get("entries_loaded", len(vulnerabilities)), "downloads_failed": downloads_failed}
    if len(vulnerabilities) == 0:
        logging.error(f"No CVE entries were loaded (feeds loaded: {stats['feeds_loaded']}, downloads failed: {downloads_failed}); refusing to print a clean verdict.")
        sys.exit(1)


    # Parse requirements file
    try:
        dependencies = parse_requirements_file(args.requirements_file)
    except Exception as e:
        logging.error(f"Failed to parse requirements file: {e}")
        sys.exit(1)



    # Check dependencies for vulnerabilities
    vulnerable_dependencies = check_dependencies_for_vulnerabilities(dependencies, vulnerabilities)

    generate_report(vulnerable_dependencies, stats)


if __name__ == "__main__":
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