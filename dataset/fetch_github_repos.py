import requests
import csv
import time

OUTPUT_FILE = "dataset/github_repos.csv"

def fetch_repos():

    repos = []
    page = 1

    print("Fetching top GitHub repositories...")

    while len(repos) < 500:

        url = f"https://api.github.com/search/repositories?q=stars:>10000&sort=stars&order=desc&page={page}&per_page=100"

        response = requests.get(url)

        if response.status_code != 200:
            print("Error:", response.json())
            break

        data = response.json()

        for repo in data.get("items", []):
            repos.append(repo["html_url"])

            if len(repos) >= 500:
                break

        print(f"Collected: {len(repos)} repos")

        page += 1
        time.sleep(2)

    return repos


def save_to_csv(repos):

    with open(OUTPUT_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["repo_url"])

        for repo in repos:
            writer.writerow([repo])

    print(f"\nSaved {len(repos)} repositories!")


if __name__ == "__main__":
    repos = fetch_repos()
    save_to_csv(repos)