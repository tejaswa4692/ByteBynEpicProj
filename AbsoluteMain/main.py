from osvscraper import fetch_vulns
from userreposcraper import get_repo_dependencies
import json


if __name__ == "__main__":
    url = input("Enter GitHub repo URL: ")
    deps = get_repo_dependencies(url)

    for name, version in deps.items():
        print(f"\nChecking vulnerabilities for: {name} @ {version}")

        vulns = fetch_vulns(name)

        print(json.dumps(vulns, indent=4))