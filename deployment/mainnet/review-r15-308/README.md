Review r15 (agent 308) demonstrations for the launch kit line 6e12ab6. Each script fails (or prints MISMATCH and
exits non-zero) on 6e12ab6 and names its finding in agents/308-l2-review-r15.md. Run one at a time:
`PYTHONDONTWRITEBYTECODE=1 python3 -B deployment/mainnet/review-r15-308/<demo>.py`
