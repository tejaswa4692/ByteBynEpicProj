import requests
from dotenv import load_dotenv
import os

# load env
load_dotenv()
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

url = "https://api.github.com/graphql"

query = """
{
  securityAdvisories(first: 50, orderBy: {field: PUBLISHED_AT, direction: DESC}) {
    nodes {
      ghsaId
      summary
      publishedAt
      severity
      vulnerabilities(first: 20) {
        nodes {
          package {
            name
            ecosystem
          }
        }
      }
    }
  }
}
"""

headers = {
    "Authorization": f"Bearer {GITHUB_TOKEN}"
}

res = requests.post(url, json={"query": query}, headers=headers)
data = res.json()

seen = set()

for adv in data["data"]["securityAdvisories"]["nodes"]:
    for vuln in adv["vulnerabilities"]["nodes"]:
        pkg = vuln.get("package")

        if pkg and pkg.get("ecosystem", "").lower() == "npm":
            key = (adv["ghsaId"], pkg["name"])

            if key not in seen:
                seen.add(key)
                print(
                    f"{adv['ghsaId']} | {adv['publishedAt']} | {pkg['name']}"
                )