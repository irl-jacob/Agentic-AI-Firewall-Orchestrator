# AFO Test Examples for OPNsense

## Quick Test Scenarios

### Test 1: Simple Block Rule (Beginner)

**What to type in AFO:**
```
block port 9999 from 192.0.2.1
```

**What this does:**
- Blocks TCP port 9999 from IP 192.0.2.1 (a documentation/test IP)
- Creates a permanent rule
- Safe - won't affect your network (192.0.2.0/24 is reserved for documentation)

**How to verify:**
1. In OPNsense Web UI: Go to **Firewall → Automation → Filter**
2. Look for a rule blocking port 9999 from 192.0.2.1
3. Should show as enabled with green checkmark

**How to clean up:**
```
delete rule blocking port 9999 from 192.0.2.1
```

---

### Test 2: Temporary Block Rule (Intermediate)

**What to type in AFO:**
```
block SSH from 203.0.113.50 for 5 minutes
```

**What this does:**
- Blocks SSH (port 22) from IP 203.0.113.50
- Rule automatically expires after 5 minutes
- Demonstrates TTL (Time-To-Live) functionality

**How to verify:**
1. Check OPNsense: **Firewall → Automation → Filter**
2. Rule should have "[TEMP]" in the description
3. Wait 5 minutes - rule should disappear automatically

**Alternative durations:**
```
block port 80 from 198.51.100.10 for 30 seconds
block port 443 from 198.51.100.20 for 2 hours
block port 3389 from 198.51.100.30 for 1 day
```

---

### Test 3: Allow Rule (Intermediate)

**What to type in AFO:**
```
allow HTTPS from 192.168.1.100
```

**What this does:**
- Allows HTTPS (port 443) from specific internal IP
- Creates an ACCEPT rule instead of DROP

**How to verify:**
1. Check OPNsense: **Firewall → Automation → Filter**
2. Look for rule with action "pass" (OPNsense term for allow)

---

### Test 4: Multiple Ports (Advanced)

**What to type in AFO:**
```
block ports 445 and 139 from 203.0.113.0/24
```

**What this does:**
- Blocks SMB ports from entire test subnet
- Demonstrates network range handling

---

### Test 5: Protocol-Specific Rule (Advanced)

**What to type in AFO:**
```
block UDP port 53 to 8.8.8.8
```

**What this does:**
- Blocks outbound DNS queries to Google DNS
- Demonstrates outbound rules and protocol specification

---

## Complete Walkthrough: Safe Test Scenario

### Scenario: Block a Test IP Temporarily

**Step 1: Start AFO TUI**
```bash
cd /mnt/Projects/AFO
afo-ui
```

**Step 2: Type Your Command**
In the chat interface, type:
```
block all traffic from 192.0.2.100 for 3 minutes
```

**Step 3: Review the Rule**
AFO will show you:
- The generated nftables command
- Conflict detection results
- Explanation of what the rule does

**Step 4: Approve the Rule**
- Press the approve button or key
- AFO will deploy to OPNsense

**Step 5: Verify in OPNsense**
1. Open browser: https://10.10.10.80
2. Navigate: **Firewall → Automation → Filter**
3. Look for: Rule blocking 192.0.2.100
4. Should show: "[TEMP]" in description with expiration time

**Step 6: Watch It Expire**
- Wait 3 minutes
- Refresh the OPNsense page
- Rule should be gone (auto-deleted)

---

## Natural Language Examples

AFO understands various phrasings:

### Blocking:
```
block SSH from 10.0.0.5
deny port 22 from 10.0.0.5
drop traffic on port 22 from 10.0.0.5
reject SSH connections from 10.0.0.5
```

### Allowing:
```
allow HTTPS from 192.168.1.50
permit port 443 from 192.168.1.50
accept HTTPS traffic from 192.168.1.50
```

### Temporary Rules:
```
block port 80 from 10.0.0.5 for 5 minutes
block port 80 from 10.0.0.5 for 2 hours
block port 80 from 10.0.0.5 for 1 day
```

### Direction:
```
block SSH from 10.0.0.5          # Inbound (from source)
block SSH to 10.0.0.5            # Outbound (to destination)
block incoming SSH from 10.0.0.5 # Explicit inbound
block outgoing SSH to 10.0.0.5   # Explicit outbound
```

---

## Recommended Test Sequence

Try these in order to learn AFO:

1. **Simple block:**
   ```
   block port 9999 from 192.0.2.1
   ```

2. **Verify in OPNsense UI** (Firewall → Automation → Filter)

3. **Delete the rule:**
   ```
   delete rule blocking port 9999
   ```

4. **Temporary rule:**
   ```
   block port 8080 from 192.0.2.2 for 2 minutes
   ```

5. **Watch it auto-expire** (wait 2 minutes, check OPNsense)

6. **Allow rule:**
   ```
   allow HTTP from 192.168.1.100
   ```

7. **Clean up:**
   ```
   delete rule allowing HTTP
   ```

---

## Common Ports Reference

Use these in your tests:

| Service | Port | Protocol |
|---------|------|----------|
| SSH | 22 | TCP |
| HTTP | 80 | TCP |
| HTTPS | 443 | TCP |
| DNS | 53 | UDP |
| SMTP | 25 | TCP |
| RDP | 3389 | TCP |
| MySQL | 3306 | TCP |
| PostgreSQL | 5432 | TCP |

---

## Safe Test IPs (Won't Affect Your Network)

These IP ranges are reserved for documentation/testing:

- `192.0.2.0/24` (TEST-NET-1)
- `198.51.100.0/24` (TEST-NET-2)
- `203.0.113.0/24` (TEST-NET-3)

Use these for testing without risk!

---

## Troubleshooting

### Rule doesn't appear in OPNsense?
1. Check you're looking in **Firewall → Automation → Filter**
2. NOT in Firewall → Rules → WAN/LAN
3. Refresh the page

### Rule creation fails?
1. Check AFO logs for errors
2. Verify OPNsense connection: `python debug_opnsense_connection.py`
3. Ensure interface is set to "wan" in .env

### Can't delete rule?
1. Note the rule ID from OPNsense UI
2. Use: `delete rule <rule-id>`
3. Or delete manually in OPNsense UI

---

## Advanced: Real-World Scenarios

Once comfortable, try these realistic scenarios:

### Block Brute Force Attacker:
```
block SSH from 203.0.113.50 for 1 hour
```

### Allow Internal Web Server:
```
allow HTTPS from 192.168.1.0/24
```

### Block Outbound to Suspicious IP:
```
block all traffic to 203.0.113.100
```

### Temporary Allow for Maintenance:
```
allow RDP from 192.168.1.50 for 30 minutes
```

---

## Pro Tips

1. **Start with temporary rules** - They auto-clean up if you forget
2. **Use test IPs first** - 192.0.2.x, 198.51.100.x, 203.0.113.x
3. **Check OPNsense logs** - System → Log Files → Firewall
4. **Test before production** - Verify rules work as expected
5. **Document your rules** - AFO adds descriptions automatically

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────────┐
│ AFO Quick Commands                                  │
├─────────────────────────────────────────────────────┤
│ Block:   block [service] from [IP]                 │
│ Allow:   allow [service] from [IP]                 │
│ Temp:    ... for [duration]                        │
│ Delete:  delete rule [description]                 │
│                                                     │
│ Services: SSH, HTTP, HTTPS, DNS, RDP, etc.         │
│ Duration: 30s, 5m, 2h, 1d                          │
│                                                     │
│ View Rules: Firewall → Automation → Filter         │
└─────────────────────────────────────────────────────┘
```

Happy testing! 🚀
