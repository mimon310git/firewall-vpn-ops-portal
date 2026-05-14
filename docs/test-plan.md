# Test Plan

## Manual Smoke Test

1. Start the app:

```powershell
python -m uvicorn backend.main:app --reload
```

2. Open `http://127.0.0.1:8000`.
3. Confirm the dashboard loads with metrics.
4. Select the `Requester` role.
5. Go to `Firewall Rules`.
6. Create a valid rule:

```text
source: 10.10.50.0/24
destination: 10.10.20.50
protocol: TCP
port: 8443
reason: Test access for web application
owner: qa.ops
```

7. Confirm the rule appears as `pending`.
8. Select the `Approver` role.
9. Open `Approvals`.
10. Approve the rule.
11. Return to `Firewall Rules`.
12. Generate a command for the approved rule.
13. Select the `Operator` role.
14. Deploy the rule.
15. Open `Health Checks`.
16. Run all checks.
17. Open `Lab Tools`.
18. Generate an `OPNsense` snippet and confirm the preview contains `<filter>` and manual review text.
19. Run lab checks with default backend settings.
20. Confirm enabled lab targets show `skipped` because controlled lab mode is off.
21. Add a new lab target as `Operator`.
22. Export the JSON data.
23. Reset demo data.

## Controlled Lab Smoke Test

Only use this against a lab host you control.

1. Stop the backend.
2. Start it with lab mode enabled:

```powershell
$env:OPS_PORTAL_LAB_MODE = "enabled"
python -m uvicorn backend.main:app --reload
```

3. Open `Lab Tools`.
4. Add a lab target with a host and TCP port from your lab.
5. Run lab checks.
6. Confirm the result is `ok` or `fail` based only on TCP reachability.
7. Confirm no config is imported and no deployment command is executed.

## API Tests

Run:

```powershell
python -m pytest
```

Covered API scenarios:

- seeded state loads from SQLite
- requester can create a firewall rule
- duplicate active rules are blocked
- invalid source IP returns a validation error
- requester cannot approve
- approver can approve
- operator can deploy
- only operator can run health checks
- operator can generate OPNsense/pfSense snippets
- lab checks are skipped unless controlled lab mode is enabled
- only operator can create lab targets

## Legacy V1 Smoke Test

For reference, the original static flow was:

1. Open `index.html`.
2. Confirm the dashboard loads with metrics.
3. Go to `Firewall Rules`.
4. Create a valid rule:

```text
source: 10.10.10.0/24
destination: 10.10.20.10
protocol: TCP
port: 443
reason: Test access for web application
owner: qa.ops
```

5. Confirm the rule appears as `pending`.
6. Open `Approvals`.
7. Approve the rule.
8. Return to `Firewall Rules`.
9. Generate a command for the approved rule.
10. Deploy the rule.
11. Open `Health Checks`.
12. Run all checks.
13. Export the JSON data.
14. Reset demo data.

## Negative Tests

### Invalid Source

Use:

```text
source: 999.10.10.1
```

Expected result:

```text
Source must be a valid IP address or CIDR range.
```

### Invalid Port

Use:

```text
port: 99999
```

Expected result:

```text
Port must be a number between 1 and 65535.
```

### Duplicate Rule

Create the same active rule twice.

Expected result:

```text
A matching active rule already exists.
```

### High-Risk Rule

Use:

```text
source: 0.0.0.0/0
destination: 10.10.40.10
port: 443
```

Expected result:

```text
The request is accepted but marked as high risk.
```

## Playwright Ideas

Good automated tests for version 3:

- dashboard renders metrics
- valid firewall request can be created
- invalid IP shows an error
- duplicate rule shows an error
- pending rule can be approved
- approved rule can generate a command
- VPN tunnel can be added
- health checks can be run
- OPNsense snippet can be generated
- lab checks show skipped when lab mode is off
- lab target can be added by operator
- reset returns app to demo state
