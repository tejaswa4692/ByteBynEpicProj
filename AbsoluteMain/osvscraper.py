import requests
from json import dumps


def fetch_vulns(package_name, version=None):
    url = "https://api.osv.dev/v1/query"

    payload = {
        "package": {
            "name": package_name,
            "ecosystem": "npm"
        }
    }

    # add version directly (this is the key change)
    if version:
        payload["version"] = version.lstrip("^~<>=")

    response = requests.post(url, json=payload)
    return response.json()


if __name__ == "__main__":
    package_name = input("Enter the npm package name: ")
    version = input("Enter version: ").strip()

    vulns = fetch_vulns(package_name, version if version else None)

    # vulns = fetch_vulns("react", "0.5.0")
    print(dumps(vulns, indent=4))