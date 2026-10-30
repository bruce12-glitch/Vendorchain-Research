"""Execute OPA fail-closed; callers supply measured worker outcomes, not uploads."""
import json
from pathlib import Path
import subprocess
from .crypto import canonical

REFERENCE_POLICY = Path(__file__).resolve().parents[1] / 'policies/reference.rego'

def evaluate(facts, path=REFERENCE_POLICY):
    result = subprocess.run(['opa', 'eval', '--stdin-input', '--format=json',
                             '--data', str(path), 'data.vendorchain.allow'],
                            input=canonical(facts), capture_output=True, timeout=10, check=True)
    values = json.loads(result.stdout).get('result', [])
    if len(values) != 1 or len(values[0].get('expressions', [])) != 1:
        raise ValueError('OPA did not return exactly one decision')
    decision = values[0]['expressions'][0]['value']
    if not isinstance(decision, bool):
        raise ValueError('OPA decision must be boolean')
    return decision
