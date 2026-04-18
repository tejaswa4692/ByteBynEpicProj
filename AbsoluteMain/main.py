from osvscraper import fetch_vulns
from userreposcraper import get_repo_dependencies
import json


def normalize_version(version: str):
    if not version:
        return None

    for prefix in ["^", "~", ">=", "<=", ">", "<", "="]:
        if version.startswith(prefix):
            return version[len(prefix):]

    return version


if __name__ == "__main__":
    url = input("Enter GitHub repo URL: ")
    deps = get_repo_dependencies(url)

    for name, version in deps.items():
        print(f"\nChecking vulnerabilities for: {name} @ {version}")

        clean_version = normalize_version(version)

        vulns = fetch_vulns(name, version=clean_version)

        print(json.dumps(vulns, indent=4))