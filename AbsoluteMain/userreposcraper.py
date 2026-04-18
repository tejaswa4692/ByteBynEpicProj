import requests
from json import dumps


def parse_repo_url(url: str):
    parts = url.strip("/").split("/")

    owner = parts[3]
    repo = parts[4]

    # default values
    branch = "main"
    path = ""

    if "tree" in parts:
        idx = parts.index("tree")
        branch = parts[idx + 1]
        path = "/".join(parts[idx + 2:])

    return owner, repo, branch, path


def fetch_package_json(owner, repo, branch, path):
    if path:
        file_path = f"{path}/package.json"
    else:
        file_path = "package.json"

    url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{file_path}"

    res = requests.get(url)

    if res.status_code != 200:
        return None

    return res.json()


def extract_dependencies(pkg_json):
    deps = {}

    deps.update(pkg_json.get("dependencies", {}))
    
    
    return deps


def get_repo_dependencies(repo_url: str):
    owner, repo, branch, path = parse_repo_url(repo_url)

    pkg_json = fetch_package_json(owner, repo, branch, path)

    if not pkg_json:
        print("No package.json found at given path")
        return {}

    return extract_dependencies(pkg_json)


# ---- run ----
if __name__ == "__main__":
    url = input("Enter GitHub repo URL: ")

    deps = get_repo_dependencies(url)
    print(dumps(deps, indent=2))