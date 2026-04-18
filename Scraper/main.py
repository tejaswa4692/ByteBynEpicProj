import requests
from dotenv import load_dotenv
import os
load_dotenv()

GITHUB_TOKEN = str(os.getenv("GITHUB_TOKEN"))

url = "https://api.github.com/graphql"

query = """
{
  securityAdvisories(first: 10, orderBy: {field: PUBLISHED_AT, direction: DESC}) {
    nodes {
      ghsaId
      summary
      publishedAt
      severity
      identifiers {
        type
        value
      }
      vulnerabilities(first: 5) {
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

for adv in data["data"]["securityAdvisories"]["nodes"]:
    for vuln in adv["vulnerabilities"]["nodes"]:
        pkg = vuln.get("package")

        if pkg:
            print(pkg["ecosystem"])