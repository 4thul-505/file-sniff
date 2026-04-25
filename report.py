# report.py
# Exports scan results to JSON — filter by verdict for triage focus

import json
from datetime import datetime


def save_report(results, output_file='report.json', flagged_only=False):
    """
    Save results to JSON.
    flagged_only=True → only write SUSPICIOUS and INVESTIGATE entries.
    """
    clean = [r for r in results if r is not None]

    if flagged_only:
        clean = [r for r in clean if r['verdict'] != 'CLEAN']

    report = {
        'generated': datetime.now().isoformat(),
        'total_scanned': len(results),
        'flagged': len([r for r in clean if r and r['verdict'] != 'CLEAN']),
        'results': clean,
    }

    with open(output_file, 'w') as f:
        json.dump(report, f, indent=4)

    return output_file
