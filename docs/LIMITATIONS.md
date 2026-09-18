# Limitations

- The labs use intentionally small, synthetic fixtures. Their results are not general benchmarks.
- The semantic firewall is a local prototype. It is not authenticated, rate limited, or safe to expose as an Internet-facing service.
- Prompt-injection and PII controls can produce false positives and false negatives.
- The RAG defense covers the documented synthetic documents, not every indirect-injection technique.
- AI-assisted code analysis remains advisory. A model can be structurally correct and semantically wrong.
- The harness preserves evidence and prioritizes review. It does not approve deployments, block merges, or make production security decisions.
- Historical claims without recoverable artifacts are labeled as historical and are not presented as verified results.
