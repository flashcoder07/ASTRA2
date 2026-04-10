import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from response_engine import decide_response, TIERS

checks = [
    # TIER 4 now at 0.85
    ('TIER 4 at 0.85', decide_response('DDoS', 0.85)['tier'] == 4),
    ('TIER 4 at 0.90', decide_response('DDoS', 0.90)['tier'] == 4),
    # TIER 3 still works up to 0.849
    ('TIER 3 at 0.84', decide_response('DDoS', 0.84)['tier'] == 3),
    ('TIER 3 at 0.75', decide_response('DDoS', 0.75)['tier'] == 3),
    # TIER 2 unchanged
    ('TIER 2 at 0.50', decide_response('DDoS', 0.50)['tier'] == 2),
    ('TIER 2 at 0.74', decide_response('DDoS', 0.74)['tier'] == 2),
    # Normal still TIER 0
    ('TIER 0 Normal',  decide_response('Normal', 0.99)['tier'] == 0),
    # Check TIER 4 threshold value
    ('TIER 4 threshold is 0.85', TIERS[4]['threshold'] == 0.85),
]

all_ok = True
for name, ok in checks:
    if not ok: all_ok = False
    print('PASS' if ok else 'FAIL', name)

print()
print('ALL PASSED' if all_ok else 'SOME FAILED')
