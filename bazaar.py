import requests

BAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"

def lookup_hash(sha256):
    headers = {"User-Agent": "MagicDetector/1.0"}
    data = {"query": "get_info", "hash": sha256}

    try:
        res = requests.post(BAZAAR_URL, data=data, headers=headers, timeout=10)

        if res.status_code != 200:
            return {'error': f"HTTP Error {res.status_code}"}

        result = res.json()
        status = result.get("query_status")

        if status == "ok" and "data" in result:
            info = result["data"][0]
            return {
                'found': True,
                'malware_family': info.get('signature', 'Unknown'),
                'file_type': info.get('file_type', 'Unknown'),
                'first_seen': info.get('first_seen', 'Unknown'),
                'tags': info.get('tags', []),
                'reporter': info.get('reporter', 'Unknown'),
            }
        elif status in ("hash_not_found", "no_results"):
            return {'found': False}
        else:
            return {'error': f"API returned: {status}"}

    except requests.exceptions.Timeout:
        return {'error': "Request timed out"}
    except requests.exceptions.RequestException as e:
        return {'error': f"Request failed: {str(e)}"}
    except Exception as e:
        return {'error': f"Unexpected error: {str(e)}"}

def print_bazaar_result(sha256, result):
    if result is None:
        return
    if 'error' in result:
        print(f"    [BAZAAR] Error: {result['error']}")
    elif result.get('found'):
        print(f"    [BAZAAR] ⚠ KNOWN MALWARE")
        print(f"             Family     : {result['malware_family']}")
        print(f"             Type       : {result['file_type']}")
        print(f"             First seen : {result['first_seen']}")
        print(f"             Tags       : {', '.join(result['tags']) if result['tags'] else 'none'}")
        print(f"             Reported by: {result['reporter']}")
    else:
        print(f"    [BAZAAR] Not in database — unknown, not necessarily clean")
