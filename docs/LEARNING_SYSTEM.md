# AFO Learning System Documentation

## Overview

The AFO Learning System adds memory and adaptive learning capabilities to the firewall. It automatically:
- Discovers patterns from historical logs and security events
- Learns from attack patterns, false positives, and legitimate traffic
- Generates configuration recommendations using LLM analysis
- Safely applies learned configurations with multiple safety checks

## Architecture

### Components

1. **MemoryStore** (`afo_daemon/learning/memory_store.py`)
   - Persistent storage for patterns and insights
   - In-memory caching for performance
   - Pattern performance tracking

2. **PatternLearner** (`afo_daemon/learning/pattern_learner.py`)
   - Analyzes deployment history for repeat offenders
   - Detects false positives (rules deleted within 1 hour)
   - Identifies legitimate traffic from user approvals
   - Requires minimum 3 observations to establish a pattern

3. **InsightEngine** (`afo_daemon/learning/insight_engine.py`)
   - Uses Ollama LLM to analyze pattern clusters
   - Generates rule suggestions from attack patterns
   - Recommends signature updates
   - Suggests preset adjustments

4. **ConfigAdvisor** (`afo_daemon/learning/config_advisor.py`)
   - Validates insights against safety policies
   - Applies configurations based on operating mode
   - Integrates with SafetyEnforcer
   - Supports manual approval workflow

5. **LearningService** (`services/learning_service.py`)
   - Orchestrates all learning components
   - Runs periodic learning cycles (default: 1 hour)
   - Manages background execution
   - Provides status monitoring

## Operating Modes

Configure via `LEARNING_MODE` environment variable:

### 1. Monitor Mode (Default - Safest)
```bash
LEARNING_MODE=monitor
```
- Only logs insights, never applies automatically
- Use this to observe what the system would do
- Recommended for initial deployment

### 2. Cautious Mode
```bash
LEARNING_MODE=cautious
LEARNING_AUTO_APPLY_THRESHOLD=0.9
```
- Applies only very high confidence insights (>0.9)
- All insights pass safety validation
- Good for production after monitoring period

### 3. Aggressive Mode
```bash
LEARNING_MODE=aggressive
LEARNING_CONFIDENCE_THRESHOLD=0.7
```
- Applies high confidence insights (>0.7)
- More proactive but still safe
- Use when you trust the system's judgment

### 4. Manual Mode
```bash
LEARNING_MODE=manual
```
- Requires explicit approval for every insight
- Use MCP tools to review and approve
- Maximum control, minimum automation

## Configuration

Add to `.env` file:

```bash
# Learning System Configuration
LEARNING_MODE=monitor                    # monitor/cautious/aggressive/manual
LEARNING_CYCLE_INTERVAL=3600            # Seconds between cycles (1 hour)
LEARNING_AUTO_APPLY_THRESHOLD=0.9       # Confidence for auto-apply (cautious mode)
LEARNING_CONFIDENCE_THRESHOLD=0.7       # Minimum confidence for insights
LEARNING_MIN_OBSERVATIONS=3             # Minimum pattern occurrences
LEARNING_TIME_WINDOW=3600               # Pattern detection window (1 hour)
LEARNING_HISTORY_DAYS=7                 # Days of history to analyze
```

## Database Schema

### LearnedPattern
Stores discovered patterns from log analysis:
- `pattern_type`: attack, false_positive, legitimate, anomaly
- `signature`: Unique pattern identifier
- `confidence`: 0.0-1.0 confidence score
- `evidence_count`: Number of observations
- `source_ips`, `ports`, `protocols`: Pattern characteristics
- `validated`: User validation status
- `active`: Whether pattern is active

### ConfigInsight
Configuration recommendations based on patterns:
- `insight_type`: rule_suggestion, preset_adjustment, signature_update
- `description`: Human-readable description
- `recommendation`: JSON recommendation details
- `confidence`: 0.0-1.0 confidence score
- `applied`: Whether recommendation was applied
- `user_approved`: Manual approval status
- `safety_validated`: Passed safety checks

### LearningMetric
Tracks learning system performance:
- `metric_type`: pattern_detected, config_applied, etc.
- `value`: Metric value
- `context`: Additional context as JSON

### PatternFeedback
User feedback on patterns and insights:
- `feedback_type`: correct, incorrect, partial, dangerous
- `user`: User who provided feedback
- `comment`: Optional explanation

## MCP Tools

Use these tools via the MCP server to interact with the learning system:

### list_learned_patterns
```python
list_learned_patterns(
    pattern_type="attack",      # Optional: filter by type
    min_confidence=0.7,         # Optional: minimum confidence
    limit=50                    # Optional: max results
)
```
Returns discovered patterns with details.

### get_pattern_details
```python
get_pattern_details(pattern_id=1)
```
Returns full pattern information including performance metrics.

### validate_pattern
```python
validate_pattern(
    pattern_id=1,
    is_correct=True,
    user="admin",
    comment="Confirmed attack pattern"
)
```
Provide feedback on pattern accuracy. Incorrect patterns are deactivated.

### list_insights
```python
list_insights(
    insight_type="rule_suggestion",  # Optional: filter by type
    min_confidence=0.7,              # Optional: minimum confidence
    pending_only=True,               # Optional: only unapplied
    limit=50
)
```
Returns configuration recommendations.

### approve_insight
```python
approve_insight(
    insight_id=1,
    user="admin"
)
```
Approve an insight for application. In manual mode, applies immediately.

### reject_insight
```python
reject_insight(
    insight_id=1,
    user="admin",
    reason="Would block legitimate traffic"
)
```
Reject an insight and provide feedback.

### get_learning_metrics
```python
get_learning_metrics(days=7)
```
Returns learning system performance metrics.

## Usage Examples

### Example 1: Monitor Mode (Observe)

1. Set mode to monitor:
```bash
echo "LEARNING_MODE=monitor" >> .env
```

2. Start the daemon:
```bash
python -m afo_daemon.main
```

3. Check logs for detected patterns:
```bash
tail -f /var/log/afo/daemon.log | grep pattern_detected
```

4. Review insights via MCP:
```python
insights = await list_insights(pending_only=True)
print(f"Found {len(insights['insights'])} pending insights")
```

### Example 2: Cautious Mode (Auto-Apply High Confidence)

1. After monitoring period, enable cautious mode:
```bash
LEARNING_MODE=cautious
LEARNING_AUTO_APPLY_THRESHOLD=0.95  # Very high confidence only
```

2. System will automatically apply insights with confidence >0.95

3. Monitor applied insights:
```python
metrics = await get_learning_metrics(days=7)
print(f"Applied {metrics['insights_applied']} insights")
```

### Example 3: Manual Approval Workflow

1. Set manual mode:
```bash
LEARNING_MODE=manual
```

2. List pending insights:
```python
insights = await list_insights(pending_only=True)
for insight in insights['insights']:
    print(f"ID: {insight['id']}")
    print(f"Description: {insight['description']}")
    print(f"Confidence: {insight['confidence']}")
    print(f"Recommendation: {insight['recommendation']}")
```

3. Review and approve:
```python
# Approve good insight
await approve_insight(insight_id=1, user="admin")

# Reject bad insight
await reject_insight(
    insight_id=2,
    user="admin",
    reason="Too broad, would block legitimate traffic"
)
```

### Example 4: Pattern Validation

1. List attack patterns:
```python
patterns = await list_learned_patterns(
    pattern_type="attack",
    min_confidence=0.7
)
```

2. Review pattern details:
```python
details = await get_pattern_details(pattern_id=1)
print(f"Pattern: {details['pattern']['signature']}")
print(f"Evidence: {details['pattern']['evidence_count']} observations")
print(f"Performance: {details['performance']['accuracy']}")
```

3. Validate or invalidate:
```python
# Confirm correct pattern
await validate_pattern(
    pattern_id=1,
    is_correct=True,
    user="admin",
    comment="Confirmed SSH brute force pattern"
)

# Mark false positive
await validate_pattern(
    pattern_id=2,
    is_correct=False,
    user="admin",
    comment="This is legitimate backup traffic"
)
```

## Safety Features

The learning system includes multiple safety layers:

1. **SafetyEnforcer Integration**
   - All learned rules validated against allowlist
   - Blocks rules that would affect protected IPs

2. **No DROP ALL Rules**
   - System rejects rules without specific source/destination/port
   - Prevents accidental lockout

3. **Confidence Thresholds**
   - Configurable minimum confidence for application
   - Higher thresholds in cautious mode

4. **User Approval**
   - Manual mode requires explicit approval
   - High-risk changes always logged

5. **Rollback Capability**
   - All applied rules create snapshots
   - Can rollback via existing mechanisms

6. **Feedback Loop**
   - User feedback reduces confidence of incorrect patterns
   - Failed applications marked as false positives

## Cold Start Behavior

For new systems with no historical data:

1. System starts in monitor mode by default
2. Collects data for 7 days before generating insights
3. Uses default signatures from SignatureMatcher
4. Gradually increases confidence as evidence accumulates
5. First 10 insights require manual approval regardless of mode

## Performance Considerations

- Learning cycle runs every 1 hour (configurable)
- Pattern analysis limited to last 7 days of data
- In-memory cache for frequently accessed patterns (5-minute TTL)
- Async operations don't block main daemon
- Database indexes on timestamp fields for query performance
- LLM calls batched to reduce latency

## Monitoring

### Check Learning Service Status
```python
status = await learning_service.get_status()
print(f"Running: {status['running']}")
print(f"Mode: {status['mode']}")
print(f"Total patterns: {status['patterns']['total']}")
print(f"Pending insights: {status['pending_insights']}")
```

### View Metrics
```python
metrics = await get_learning_metrics(days=7)
print(f"Patterns detected: {metrics['patterns_detected']}")
print(f"Insights generated: {metrics['insights_generated']}")
print(f"Insights applied: {metrics['insights_applied']}")
```

### Check Daemon Logs
```bash
# View learning cycle activity
journalctl -u afo-daemon | grep learning_cycle

# View pattern detection
journalctl -u afo-daemon | grep pattern_detected

# View insight application
journalctl -u afo-daemon | grep insight
```

## Troubleshooting

### No Patterns Detected
- Check that deployment logs exist in database
- Verify `LEARNING_HISTORY_DAYS` covers period with activity
- Ensure `LEARNING_MIN_OBSERVATIONS` is not too high
- Check daemon logs for errors

### Insights Not Applied
- Verify `LEARNING_MODE` is not set to `monitor`
- Check confidence thresholds
- Review safety validation failures in logs
- Ensure insights pass safety checks

### LLM Analysis Failing
- Verify Ollama is running: `curl http://localhost:11434/api/tags`
- Check `OLLAMA_HOST` and `OLLAMA_MODEL` settings
- Review LLM call errors in logs
- System works without LLM but with reduced insight quality

### High Memory Usage
- Reduce `LEARNING_HISTORY_DAYS`
- Lower pattern cache TTL
- Limit `LEARNING_CYCLE_INTERVAL` frequency

## Testing

Run the test suite:

```bash
# Test learning system components
pytest tests/test_learning_system.py -v

# Test integration
pytest tests/test_learning_integration.py -v

# Verify installation
python verify_learning_system.py
```

## Future Enhancements

Planned improvements:
- Web UI for reviewing patterns and insights
- Email notifications for high-confidence insights
- Export/import learned patterns between AFO instances
- Collaborative learning across multiple deployments
- Advanced anomaly detection using statistical methods
- Integration with external threat intelligence APIs

## Support

For issues or questions:
- Check logs: `journalctl -u afo-daemon`
- Run verification: `python verify_learning_system.py`
- Review this documentation
- Check GitHub issues: https://github.com/anthropics/afo/issues
