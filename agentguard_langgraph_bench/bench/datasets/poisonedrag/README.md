# PoisonedRAG Artifact Subset

This directory contains the minimal PoisonedRAG artifacts needed for the
AgentGuard LangGraph memory-poisoning benchmark.

The source directory is read-only:

```text
../PoisonedRAG/
```

Copied subset:

- `adv_targeted_results/{dataset}.json`: selected question records with `id`,
  `question`, `correct answer`, `incorrect answer`, and `adv_texts`.
- `beir_results/{dataset}-contriever.json`: top-10 clean retrieval rankings for
  the selected question ids.
- `clean_doc_cache/{dataset}_clean_docs.json`: clean document text for the copied
  rankings.
- `corpus/{dataset}/corpus.jsonl`: the same clean docs in corpus JSONL shape so
  the loader can fall back without scanning the original multi-GB corpora.
- `manifest.json`: generation time, source paths, selected qids, and file sizes.

Datasets covered in this subset:

- `nq`: `test1`, `test11`, `test16`, `test19`
- `msmarco`: `1163399`, `192017`, `1164044`
- `hotpotqa`: `5adbf0a255429947ff17385a`,
  `5a8cb288554299585d9e3726`, `5ab56e32554299637185c594`

The benchmark sends only question text and plain context strings to the demo
agent. Correct answers, incorrect answers, poison labels, internal document ids,
and scores are retained only in tool results and runner metadata for audit and
metric calculation.
