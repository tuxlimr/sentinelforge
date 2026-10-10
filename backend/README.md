# SentinelForge

**Security regression testing for LLM apps, RAG pipelines and AI agents.**

SentinelForge runs deterministic security tests (prompt injection, secret and cross-tenant leakage, tool-permission
abuse) against your AI application, confirms failures by re-running them, and turns confirmed findings into
regression tests for CI. It is a testing aid, not a guarantee of security.

```bash
pip install sentinelforge-ai
sentinelforge guide                                            # 2-minute offline tour, no API keys
sentinelforge init --url https://your-app.example.com/api/ask  # config + GitHub Actions workflow
sentinelforge test --config sentinelforge.yaml                 # test your own app
sentinelforge webscan https://your-site.example.com/ --authorized   # passive website security check
```

The PyPI distribution is `sentinelforge-ai`; the import name and command are `sentinelforge`.

**Responsible use:** an open-source community project for testing applications you own or are explicitly
authorized to test. Any illegal use is strictly prohibited.

Full documentation, the web dashboard and screenshots: https://github.com/tuxlimr/sentinelforge
