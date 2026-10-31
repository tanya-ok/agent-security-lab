# Checks for "Three months before SMS codes go away"

How the article was produced and what was checked. All checks ran locally; the
text was not sent to any online AI detector.

## Production

1. A local model (Gemma 4 31B, `personal-os-gemma-31:64k` in Ollama) wrote a
   first draft from a fixed facts file and the earlier article as a voice
   reference.
2. The draft was then revised by Claude Code (Opus 5.5), a cloud model, not by
   the local model: invented details were
   removed (for example an emotional reaction and a claim that the attack was
   run manually), sentences were merged and varied, and every technical claim
   was checked against the lab code and README.

## Results

| Check | Local draft | Final text | Earlier article |
|---|---|---|---|
| Words | 1048 | 943 | 1600 |
| Mean sentence length (words) | 8.3 | 13.8 | 13.9 |
| Sentence length standard deviation | 4.3 | 10.2 | 6.5 |
| Burstiness (stdev / mean) | 0.52 | 0.74 | 0.47 |
| Sentences of 30+ words | 0 | 1 | not counted |
| Stock AI phrases from a fixed list | 1 | 0 | not counted |
| Em or en dashes | 0 | 0 | not counted |
| Local model judge, "probability mostly AI" | not run | 10 | not run |

The judge was the same local Gemma model, prompted as a strict editor.

## Limits

- No dedicated AI-text detector is installed on this machine (none found in
  pip, uv, Homebrew or Ollama), and none was downloaded or used online.
- Stylometric numbers are heuristics. A human can write uniform sentences and a
  model can be prompted to vary them.
- A model judging text close to its own output is a weak signal, not evidence.
- Passing these checks says nothing about authorship disclosure; that decision
  stays with the author.
