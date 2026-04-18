import requests
from json import dumps

def fetch_vulns(package_name):
    url = "https://api.osv.dev/v1/query"

    payload = {
        "package": {
            "name": package_name,
            "ecosystem": "npm"
        }
    }

    response = requests.post(url, json=payload)
    return response.json()


if __name__ == "__main__":
    package_name = input("Enter the npm package name: ")
    vulns = fetch_vulns(package_name)
    print(dumps(vulns, indent=4))