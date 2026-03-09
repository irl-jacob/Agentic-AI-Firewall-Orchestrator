# AFO User Guide - Quick Start

## Welcome to AFO (Autonomous Firewall Orchestrator)

AFO is a natural language firewall management system that lets you control your firewall using plain English or slash commands.

---

## 🚀 Two Ways to Control AFO

### 1. Slash Commands (Recommended for Advanced Features)
Fast, deterministic commands that execute instantly without AI inference.

```bash
/geoip block Russia China
/domain block category social_media
/bulk delete port 22
```

### 2. Natural Language
Conversational commands processed by AI.

```bash
block SSH from 10.0.0.5
block social media during business hours
what rules are blocking port 22?
```

---

## 📋 Basic Commands

### Block an IP Address
```bash
# Natural language
block 192.168.1.100
block SSH from 10.0.0.5
drop all traffic from 203.0.113.0/24

# Result: Creates firewall rule to block the IP
```

### Allow Traffic
```bash
# Natural language
allow port 443
allow HTTPS traffic
open port 80

# Result: Creates firewall rule to allow traffic
```

### Delete Rules
```bash
# Natural language
delete rule for 10.0.0.5
remove SSH block

# Slash command
/bulk delete port 22
/bulk delete ip 10.0.0.5

# Result: Removes matching firewall rules
```

---

## 🌍 GeoIP Filtering

### Block Countries
```bash
# Slash command (recommended)
/geoip block Russia China Iran

# Natural language
block all traffic from Russia and China

# Result: Blocks all traffic from specified countries
```

### Allow Only Specific Countries
```bash
# Slash command
/geoip allow US India UK

# Result: Allows only traffic from US, India, UK
#         Blocks all other countries
```

### Supported Countries
Over 50 countries supported including:
- United States (US)
- Russia (RU)
- China (CN)
- India (IN)
- United Kingdom (UK)
- And many more...

---

## 🌐 Domain Blocking

### Block Single Domain
```bash
# Slash command
/domain block facebook.com

# Natural language
block facebook.com

# Result: Blocks DNS queries for facebook.com
```

### Block Domain Categories
```bash
# Slash command
/domain block category social_media

# Available categories:
- social_media (Facebook, Twitter, Instagram, TikTok, etc.)
- streaming (YouTube, Netflix, Hulu, Twitch, etc.)
- gaming (Steam, Epic Games, Roblox, etc.)
- gambling (Betting and casino sites)
- adult (Adult content sites)
- ads (Advertising and tracking domains)

# Result: Blocks all domains in the category
```

### Unblock Domain
```bash
# Slash command
/domain unblock twitter.com

# Result: Removes block for twitter.com
```

---

## ⏰ Time-Based Rules

### Block During Business Hours
```bash
# Natural language
block social media during business hours
block gaming sites from 9am to 5pm
allow SSH only on weekdays

# Result: Rule active only during specified times
```

### Supported Time Expressions
- "business hours" / "office hours" → 9am-5pm
- "9am to 5pm" → Specific time range
- "weekends" → Saturday + Sunday
- "weekdays" → Monday-Friday
- "after 11pm" → 11pm-11:59pm
- "on Mondays" → Specific day

---

## 📦 Bulk Operations

### Delete All Rules for a Port
```bash
# Slash command
/bulk delete port 22

# Result: Deletes all rules affecting port 22
```

### Delete All Rules for an IP
```bash
# Slash command
/bulk delete ip 10.0.0.5

# Result: Deletes all rules affecting 10.0.0.5
```

### Delete Temporary Rules
```bash
# Slash command
/bulk delete temp

# Result: Deletes all temporary/TTL rules
```

### Enable/Disable Rules
```bash
# Slash command
/bulk enable port 80
/bulk disable port 443

# Result: Enables or disables all rules for the port
```

---

## 🚫 Rate Limiting

### View Statistics
```bash
# Slash command
/rate stats

# Result: Shows rate limiter statistics
#   - IPs tracked
#   - Blocked IPs
#   - Whitelist size
#   - Thresholds
```

### Whitelist an IP
```bash
# Slash command
/rate whitelist add 192.168.1.100

# Result: IP will never be auto-blocked
```

### Remove from Whitelist
```bash
# Slash command
/rate whitelist remove 192.168.1.100

# Result: IP can be auto-blocked again
```

### How Auto-Blocking Works
AFO automatically monitors connection attempts and blocks IPs that exceed:
- 100 requests per minute (default)
- 1000 requests per hour (default)

Blocked IPs are automatically unblocked after 1 hour.

---

## 🔍 Query Rules

### Find Rules Blocking a Port
```bash
# Natural language
what rules are blocking port 22?
show me all SSH rules

# Result: Lists all rules affecting port 22
```

### Find Rules for an IP
```bash
# Natural language
why is 10.0.0.5 blocked?
what rules affect 192.168.1.100?

# Result: Lists all rules affecting the IP
```

### List All Rules
```bash
# Natural language
show all rules
list all firewall rules

# Result: Displays all active rules
```

---

## 💬 Typo Handling

AFO automatically corrects common typos:

```bash
# You type:
plz blok shh from 10.0.0.5 asap

# AFO understands:
please block ssh from 10.0.0.5 immediately

# Result: Creates the rule correctly
```

Supported typo corrections:
- plz → please
- blok → block
- shh → ssh
- asap → immediately
- And 40+ more...

---

## ⚡ Urgency Detection

AFO detects urgent commands and fast-tracks them:

```bash
# High urgency (ALL CAPS or keywords)
BLOCK 1.2.3.4 NOW WE'RE UNDER ATTACK

# Result: Immediate deployment, minimal confirmations
```

Urgency levels:
- **High**: attack, ddos, breach, compromised, ALL CAPS
- **Medium**: now, immediately, asap, urgent
- **Low**: Normal commands

---

## 🔄 Rollback

### Undo Last Change
```bash
# Natural language
undo last change
rollback

# Result: Restores firewall to previous state
```

---

## ❓ Getting Help

### Show All Slash Commands
```bash
/help

# Result: Displays all available slash commands
```

### Ask Questions
```bash
# Natural language
what can you do?
how do I block a country?
what is my IP address?

# Result: AFO explains and helps
```

---

## 🎯 Best Practices

### 1. Use Slash Commands for Phase 3 Features
Slash commands are faster and more reliable for:
- GeoIP filtering
- Domain blocking
- Bulk operations
- Rate limiting

### 2. Use Natural Language for Basic Rules
Natural language works great for:
- Blocking/allowing IPs
- Port-based rules
- Time-based rules
- Queries

### 3. Review Before Confirming
AFO shows you what it will do before executing. Always review:
- The rule details
- Risk assessment
- Affected systems

### 4. Use Rollback if Needed
If something goes wrong:
```bash
undo last change
```

### 5. Check Rate Limiter Stats Regularly
```bash
/rate stats
```

---

## 🔒 Safety Features

### Risk Assessment
AFO analyzes every command for risk:
- **LOW**: Safe operations
- **MEDIUM**: Requires attention
- **HIGH**: Potentially dangerous
- **CRITICAL**: Very dangerous, requires explicit confirmation

### Confirmation Prompts
High-risk operations require confirmation:
```bash
> block all traffic

⚠️ WARNING: This will block ALL traffic
Risk Level: CRITICAL
Confirm? (yes/no)
```

### Snapshots
AFO creates snapshots before changes:
- Automatic rollback on errors
- Manual rollback with "undo last change"
- Full audit trail

---

## 📊 Examples

### Example 1: Block Malicious IP
```bash
> block 203.0.113.50

AFO: Creating rule to block 203.0.113.50
     Risk Level: LOW
     Confirm? (yes/no)

> yes

AFO: ✓ Rule created successfully
     ✓ 203.0.113.50 is now blocked
```

### Example 2: Block Social Media at Work
```bash
> /domain block category social_media

AFO: Ready to block domain category: social_media
     This will block 16 domains including:
     - facebook.com
     - twitter.com
     - instagram.com
     Confirm? (yes/no)

> yes

AFO: ✓ Blocked 16 social media domains
     ✓ DNS queries will be blocked
```

### Example 3: Emergency Block
```bash
> BLOCK 1.2.3.4 NOW UNDER ATTACK

AFO: ⚡ High urgency detected
     ✓ Creating emergency block rule
     ✓ 1.2.3.4 blocked immediately
```

### Example 4: Bulk Cleanup
```bash
> /bulk delete port 22

AFO: Found 5 rules affecting port 22:
     - ssh_rule_1
     - ssh_rule_2
     - ssh_rule_3
     - ssh_rule_4
     - ssh_rule_5
     Delete all? (yes/no)

> yes

AFO: ✓ Deleted 5 rules
     ✓ Port 22 rules cleared
```

---

## 🆘 Troubleshooting

### Command Not Working?
1. Check syntax with `/help`
2. Try natural language instead
3. Check for typos (AFO auto-corrects most)

### Rule Not Blocking?
1. Check if rule is enabled
2. Verify rule priority
3. Check for conflicting rules

### Need to Undo?
```bash
undo last change
```

### Still Need Help?
```bash
what can you do?
how do I [your question]?
```

---

## 📚 Additional Resources

- Full command reference: `/help`
- Slash commands: `docs/SLASH_COMMANDS.md`
- Phase summaries: `docs/PHASE*_SUMMARY.md`
- Technical docs: Source code inline documentation

---

**AFO Version:** 1.0
**Last Updated:** 2026-02-23
**Status:** Production Ready

---

*Happy Firewalling! 🔥🛡️*
