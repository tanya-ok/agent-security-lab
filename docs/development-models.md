# Development and review models


These are development/review tools, not a model-compatibility matrix for MCP.

| Tool or role | Model | Evidence |
|---|---|---|
| Claude Code | Opus 5.5 | Maintainer-reported development setup; saved CLI reports do not pin the backend model. |
| Codex | Sol 6.1 (`gpt-6.1-sol`) | Local coding configuration checked. |
| Kimi via Moonshot API | `kimi-k2.6` | Model ID recorded in the earlier portfolio quorum reports. |
| Local mechanical triage | `gemma4:26b` | `ask-local` branch-triage invocation completed; its suggestions require verification. |

Local Ollama configuration, inspected:

| Role | Local model tag | Reported parameters / quantization | Context used |
|---|---|---|---|
| `ask-local` default | `gemma4:26b` | 25.2B / Q4_K_M | 32,768 tokens |
| Quorum reviewer | Gemma 4 (`personal-os-gemma-31:64k`) | 30.7B / Q8_0 | 65,536 tokens |
| Quorum reviewer | gpt-oss (`personal-os-gpt-oss-120:64k`) | 116.8B / MXFP4 | 65,536 tokens |
| Quorum chair | Qwen3.5 (`personal-os-qwen-122:64k`) | 125.1B / Q4_K_M | 65,536 tokens |

Parameter counts are Ollama metadata, not inferred from tag names. `ask-local`
sets temperature 0; `quorum` sets 0.3 and requests model unloading after each
response. All three quorum models completed two local review batches.
This is a bounded review, not a complete security audit. Its packet covers selected ranges in 21 files across
seven repositories; omitted code and test bodies remain outside scope. Reviewers
run serially to limit memory pressure.

The custom quorum uses independent reviews followed by a chair summary and
human verification. Google's [ADK multi-agent workflow patterns](https://github.com/google/adk-docs/blob/main/docs/workflows/patterns.md)
are a related reference for gather/synthesis and generator/critic workflows.
This script does not use Google ADK, implement a Google-prescribed voting rule,
or treat model agreement as approval. Local bulk reading and drafts stay local;
code inspection and tests substantiate any accepted finding.


[Verified review results](local-model-review.md)
