import urllib.request, json

r = urllib.request.urlopen('http://127.0.0.1:5000')
html = r.read().decode()

checks = [
    ('Orbitron font',       'Orbitron' in html),
    ('JetBrains Mono font', 'JetBrains+Mono' in html),
    ('Nav logo text',       'ASTRA' in html),
    ('statsRow',            'id="statsRow"' in html),
    ('normalTraffic',       'id="normalTraffic"' in html),
    ('activeThreats',       'id="activeThreats"' in html),
    ('eventsTableBody',     'eventsTableBody' in html),
    ('threatReports',       'id="threatReports"' in html),
    ('blockedIPs',          'id="blockedIPs"' in html),
    ('feedbackStatusBar',   'feedbackStatusBar' in html),
    ('retrainToast',        'retrainToast' in html),
    ('app.js included',     'app.js' in html),
    ('tier CSS t-badge',    't-badge' in html),
    ('crit-banner class',   'crit-banner' in html),
    ('shap-wrap class',     'shap-wrap' in html),
    ('live-dot class',      'live-dot' in html),
    ('clockTime',           'id="clockTime"' in html),
    ('clockDate',           'id="clockDate"' in html),
]

all_ok = True
for name, ok in checks:
    if not ok:
        all_ok = False
    print('PASS' if ok else 'FAIL', name)

print()

# Verify /api/reports has tier metadata
r2 = urllib.request.urlopen('http://127.0.0.1:5000/api/reports')
reports = json.loads(r2.read())
if reports:
    last = reports[-1]
    tier_ok = 'tier' in last and 'tier_color' in last
    print('PASS' if tier_ok else 'FAIL', 'Reports have tier metadata, action =', last.get('action'), 'tier =', last.get('tier'))

# Verify /api/stats
r3 = urllib.request.urlopen('http://127.0.0.1:5000/api/stats')
stats = json.loads(r3.read())
print('PASS /api/stats keys:', list(stats.keys())[:6])

print()
print('ALL PASSED' if all_ok else 'SOME FAILED')
