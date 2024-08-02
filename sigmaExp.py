import os
import subprocess
import yaml
import logging
import sqlite3
import argparse
from time import sleep
from dotenv import load_dotenv
from sigma.collection import SigmaCollection
from sigma.parser.collection import SigmaCollectionParser
from sigma.backends.crowdstrike import CrowdStrikeBackend
from insightidr import InsightIDRBackend  # Assuming this is the correct import from pySigma-backend-insightidr
from falconpy import CustomIOA, OAuth2

# Load environment variables from a .env file
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Set up environment variables for CrowdStrike
CROWDSTRIKE_CLIENT_ID = os.getenv("CROWDSTRIKE_CLIENT_ID")
CROWDSTRIKE_CLIENT_SECRET = os.getenv("CROWDSTRIKE_CLIENT_SECRET")
CROWDSTRIKE_BASE_URL = "https://api.us-2.crowdstrike.com"

# Authenticate with CrowdStrike API
oauth2 = OAuth2(client_id=CROWDSTRIKE_CLIENT_ID,
                client_secret=CROWDSTRIKE_CLIENT_SECRET,
                base_url=CROWDSTRIKE_BASE_URL)
custom_ioa = CustomIOA(auth_object=oauth2)

# Define paths
SIGMA_RULES_PATH = "path/to/sigma/rules"
SIGMA_RULES_GIT_URL = "https://github.com/SigmaHQ/sigma.git"
DB_PATH = "uploaded_rules.db"
EXPORT_DIR = "exported_queries"

# Clone or update the Sigma rules repository
def clone_or_update_sigma_repo(repo_url, repo_path):
    if not os.path.exists(repo_path):
        subprocess.run(["git", "clone", repo_url, repo_path], check=True)
    else:
        subprocess.run(["git", "-C", repo_path, "pull"], check=True)

# Function to load Sigma rules from the cloned repository
def load_sigma_rules(path):
    rules = []
    for root, _, files in os.walk(path):
        for file in files:
            if file.endswith(".yml"):
                full_path = os.path.join(root, file)
                platform = determine_platform(full_path)
                rules.append((full_path, platform))
    return rules

# Function to determine platform based on file path
def determine_platform(file_path):
    if "windows" in file_path.lower():
        return "windows"
    elif "linux" in file_path.lower():
        return "linux"
    elif "macos" in file_path.lower():
        return "mac"
    else:
        return "unknown"

# Initialize SQLite database
def init_db(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS uploaded_rules (
            id TEXT PRIMARY KEY,
            title TEXT,
            rule_content TEXT,
            backend TEXT
        )
    ''')
    conn.commit()
    return conn

# Check if rule exists in the database
def rule_exists_in_db(cursor, rule_id, backend):
    cursor.execute("SELECT 1 FROM uploaded_rules WHERE id = ? AND backend = ?", (rule_id, backend))
    return cursor.fetchone() is not None

# Get rule content from the database
def get_rule_content_from_db(cursor, rule_id, backend):
    cursor.execute("SELECT rule_content FROM uploaded_rules WHERE id = ? AND backend = ?", (rule_id, backend))
    row = cursor.fetchone()
    return row[0] if row else None

# Save rule to the database
def save_rule_to_db(cursor, rule_id, rule_title, rule_content, backend):
    cursor.execute("REPLACE INTO uploaded_rules (id, title, rule_content, backend) VALUES (?, ?, ?, ?)",
                   (rule_id, rule_title, rule_content, backend))

# Parse and convert Sigma rules to backend queries
def parse_and_convert_rules(sigma_rules, backend):
    collection = SigmaCollection()
    parser = SigmaCollectionParser(collection, None, backend)
    parsed_rules = []
    for file_path, platform in sigma_rules:
        with open(file_path, 'r') as rule_file:
            rule_content = rule_file.read()
        parsed_rule = parser.parse(rule_content)
        parsed_rules.append((parsed_rule, platform))
    return parsed_rules

# Create rule group if it doesn't exist and return its ID (CrowdStrike specific)
def create_or_get_rule_group_crowdstrike(custom_ioa, platform, rule_group_name):
    response = custom_ioa.create_rule_group(
        platform_name=platform,
        name=rule_group_name,
        description="Custom IOA rule group created from Sigma rules",
        comments="Automatically generated"
    )
    return response['resources'][0]['id']

# Process and upload Sigma rules to CrowdStrike
def process_rules_crowdstrike(parsed_rules, custom_ioa, cursor, test_mode):
    created_rule_groups = {}
    for parsed_rule, platform in parsed_rules:
        rule_id = parsed_rule.id
        rule_name = parsed_rule.title
        rule_content = yaml.dump(parsed_rule)
        cs_query = parsed_rule.queries[0]

        if rule_exists_in_db(cursor, rule_id, 'crowdstrike'):
            existing_content = get_rule_content_from_db(cursor, rule_id, 'crowdstrike')
            if existing_content == rule_content:
                logging.info(f"Rule {rule_name} already exists and is up to date.")
                continue

        rule_group_name = f"Sigma Rule Group - {rule_name} ({platform})"
        if rule_group_name not in created_rule_groups:
            rule_group_id = create_or_get_rule_group_crowdstrike(custom_ioa, platform, rule_group_name)
            created_rule_groups[rule_group_name] = rule_group_id
        else:
            rule_group_id = created_rule_groups[rule_group_name]

        # Adjust parameters for test mode
        pattern_severity = 2 if not test_mode else 1
        pattern_disposition = 100 if not test_mode else 200

        # Create the IOA rule
        response = custom_ioa.create_rule(
            name=f"Sigma Rule - {rule_name}",
            description=f"Converted Sigma rule: {rule_name}",
            rule_group_id=rule_group_id,
            pattern_severity=pattern_severity,  # Set severity
            pattern_disposition=pattern_disposition,  # Set disposition
            field_values=[
                {"field": "CommandLine", "type": "string", "value": cs_query}
            ]
        )
        if response['meta']['rc'] == 'SUCCESS':
            logging.info(f"Successfully created rule: {rule_name}")
            save_rule_to_db(cursor, rule_id, rule_name, rule_content, 'crowdstrike')
        else:
            logging.error(f"Failed to create rule: {rule_name}, Error: {response}")

        sleep(1)  # Add a short delay to handle rate limiting

# Process and export Sigma rules to Rapid7 InsightIDR
def process_rules_rapid7(parsed_rules, cursor, test_mode, export_dir):
    if not os.path.exists(export_dir):
        os.makedirs(export_dir)

    for parsed_rule, platform in parsed_rules:
        rule_id = parsed_rule.id
        rule_name = parsed_rule.title
        rule_content = yaml.dump(parsed_rule)
        r7_query = parsed_rule.queries[0]

        if rule_exists_in_db(cursor, rule_id, 'rapid7'):
            existing_content = get_rule_content_from_db(cursor, rule_id, 'rapid7')
            if existing_content == rule_content:
                logging.info(f"Rule {rule_name} already exists and is up to date.")
                continue

        # Export the query to a file
        query_filename = os.path.join(export_dir, f"{rule_name}.txt")
        with open(query_filename, 'w') as query_file:
            query_file.write(r7_query)

        logging.info(f"Exported rule {rule_name} to {query_filename}")
        save_rule_to_db(cursor, rule_id, rule_name, rule_content, 'rapid7')

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Process Sigma rules and upload to CrowdStrike or export to Rapid7.")
    parser.add_argument('--test', action='store_true', help="Run in test mode")
    parser.add_argument('--backend', choices=['crowdstrike', 'rapid7'], required=True, help="Choose the backend to use: 'crowdstrike' or 'rapid7'")
    args = parser.parse_args()

    print("Welcome to the Sigma Rule Processor!")
    print("You can use the following arguments:")
    print("  --test: Run in test mode")
    print("  --backend: Choose the backend to use: 'crowdstrike' or 'rapid7'")
    print("\nNote: For Rapid7, this script will only create and export search queries.")

    # Initialize the database
    conn = init_db(DB_PATH)
    cursor = conn.cursor()

    try:
        clone_or_update_sigma_repo(SIGMA_RULES_GIT_URL, SIGMA_RULES_PATH)
        sigma_rules = load_sigma_rules(SIGMA_RULES_PATH)

        if args.backend == 'crowdstrike':
            backend = CrowdStrikeBackend()
            parsed_rules = parse_and_convert_rules(sigma_rules, backend)
            process_rules_crowdstrike(parsed_rules, custom_ioa, cursor, args.test)
        elif args.backend == 'rapid7':
            backend = InsightIDRBackend()  # Replace with actual Rapid7 backend if available
            parsed_rules = parse_and_convert_rules(sigma_rules, backend)
            process_rules_rapid7(parsed_rules, cursor, args.test, EXPORT_DIR)

    except Exception as e:
        logging.error(f"An error occurred: {e}")
    finally:
        conn.commit()
        conn.close()

if __name__ == "__main__":
    main()
