import requests
import os

VT_URL = "https://www.virustotal.com/api/v3/files/"

def lookup_hash(sha256):
    api_key = os.getenv("VT_KEY", "")
    if not api_key:
        return {'error': "VT_KEY not set"}

    headers = {"x-apikey": api_key}

    try:
        res = requests.get(VT_URL + sha256, headers=headers, timeout=10)

        if res.status_code == 404:
            return {'found': False}
        if res.status_code == 401:
            return {'error': "Invalid API key"}
        if res.status_code != 200:
            return {'error': f"HTTP {res.status_code}"}

        data = res.json()['data']['attributes']
        stats = data.get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0)
        total = sum(stats.values())

        return {
            'found': True,
            'malicious': malicious,
            'total': total,
            'name': data.get('meaningful_name', 'Unknown'),
            'type': data.get('type_description', 'Unknown'),
            'first_seen': data.get('first_submission_date', 'Unknown'),
        }

    except requests.exceptions.Timeout:
        return {'error': "Request timed out"}
    except Exception as e:
        return {'error': str(e)}


def print_bazaar_result(sha256, result):
    if result is None:
        return
    if 'error' in result:
        print(f"    [VT] Error: {result['error']}")
    elif not result.get('found'):
        print(f"    [VT] Not in database — unknown hash")
    else:
        flag = "⚠ MALICIOUS" if result['malicious'] > 0 else "✓ CLEAN"
        print(f"    [VT] {flag} — {result['malicious']}/{result['total']} engines flagged")
        print(f"         Name : {result['name']}")
        print(f"         Type : {result['type']}")
