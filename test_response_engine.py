import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from response_engine import decide_response, generate_incident_report, INCIDENTS_DIR

tests = [
    ('DDoS',      0.30, 1, 'MONITOR'),
    ('DDoS',      0.55, 2, 'THROTTLE'),
    ('DDoS',      0.80, 3, 'BLOCK_IP'),
    ('DDoS',      0.95, 4, 'ISOLATE_HOST'),
    ('Normal',    0.99, 0, 'ALLOW'),
    ('DDoS',      0.50, 2, 'THROTTLE'),      # boundary exactly 0.50
    ('PortScan',  0.75, 3, 'BLOCK_IP'),      # boundary exactly 0.75
    ('BruteForce',0.90, 4, 'ISOLATE_HOST'),  # boundary exactly 0.90
    ('Unknown',   0.95, 0, 'ALLOW'),         # Unknown treated as normal
]

all_ok = True
for label, conf, exp_tier, exp_action in tests:
    r = decide_response(label, conf)
    ok = r['tier'] == exp_tier and r['action'] == exp_action
    marker = 'PASS' if ok else 'FAIL'
    if not ok:
        all_ok = False
    print(marker, 'label=%s conf=%.2f -> tier=%d action=%s (expected tier=%d action=%s)' % (
        label, conf, r['tier'], r['action'], exp_tier, exp_action))

# Test incident report for TIER 4
evt = {
    'source_ip': '10.0.0.5', 'destination_ip': '192.168.1.1',
    'threat_type': 'DDoS', 'confidence': 0.95, 'protocol': 'TCP',
    'packets': 500, 'bytes': 1000, 'duration': 30.0,
    'failed_logins': 0, 'timestamp': '03:00:00'
}
resp = decide_response('DDoS', 0.95)
path = generate_incident_report(evt, resp, explanation={'summary': 'test'})
if path:
    file_ok = os.path.exists(path)
    print('PASS' if file_ok else 'FAIL', 'Incident file exists:', path)
else:
    print('FAIL Incident report returned None')
    all_ok = False

# TIER 4 should NOT generate a report for tier 3
path_none = generate_incident_report(evt, decide_response('DDoS', 0.80))
print('PASS' if path_none is None else 'FAIL', 'No incident for TIER 3 (got None):', path_none)

print()
print('ALL PASSED' if all_ok else 'SOME TESTS FAILED')
