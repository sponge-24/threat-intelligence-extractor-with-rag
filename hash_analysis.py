import requests
import random

def analyze_hashes(iocs, api_key):
    
    results = []

    for hash_type in ["md5s", "sha1s", "sha256s", "sha512s"]:
        if hash_type in iocs["IoCs"]:
            for hash_value in iocs["IoCs"][hash_type]: 
                print(f"Analyzing {hash_type.upper()} hash: {hash_value}")

                url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
                headers = {"x-apikey": api_key}
                response = requests.get(url, headers=headers)

                if response.status_code == 200:
                    data = response.json()
                    attributes = data.get("data", {}).get("attributes", {})
                    last_analysis_stats = attributes.get("last_analysis_stats", {})

                    result = {
                        "hash": hash_value,
                        "hash_type": hash_type,
                        "malicious": last_analysis_stats.get("malicious", 0),
                        "tags": random.sample(attributes.get("tags", []), min(4, len(attributes.get("tags", [])))),
                        "tlsh": attributes.get("tlsh"),
                        "file_type": attributes.get("type_description")
                    }
                    print(result)
                    results.append(result)

    return results
