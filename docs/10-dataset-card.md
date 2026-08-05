# CrisisWeave Wildfire Evidence Pack — dataset card

> This is the small demonstration pack. The immutable 24-event v1 track is documented in
> [11-event-disjoint-benchmark.md](11-event-disjoint-benchmark.md); the composed 46-event global v2
> source registry, annotation governance, diversity analysis and honest release status are in
> [12-benchmark-governance.md](12-benchmark-governance.md).

## Summary

The v1 demonstration pack is a manifest-driven, event-centric corpus combining video, captions,
still imagery, chart/report pages and structured storm records. Its purpose is to exercise cross-modal
corroboration and contradiction handling, not to train a foundation model or provide live alerts.

The manifest is [datasets/crisisweave-wildfire/manifest.json](../datasets/crisisweave-wildfire/manifest.json).
The downloader records retrieval time, byte size and SHA-256 in `data/demo/provenance.lock.json`.
Raw assets and that lock are excluded from git by the repository's `data/*` rule.

The committed manifest has URLs and attribution metadata but no expected content hashes. Therefore
the first download is explicitly trust-on-first-use (TOFU): it accepts the current HTTPS response and
writes a local lock. A later run refuses URL/content/decompressed-byte changes relative to that lock.
`--refresh-lock` discards the old trust decision and must be used only after an authorized source,
license and byte-level review. For a reproducible release, copy the reviewed lock into a controlled,
versioned release-artifact store; this repository does not provide an independently anchored v1 hash
set.

```bash
# First use: download and create a local TOFU lock.
python scripts/download_demo_dataset.py

# Later use: download again and verify every asset against that local lock.
python scripts/download_demo_dataset.py

# Only after explicit upstream review:
python scripts/download_demo_dataset.py --refresh-lock
```

## Sources

| Source | Assets | Provenance/terms note |
|---|---|---|
| [NASA Scientific Visualization Studio](https://svs.gsfc.nasa.gov/12742) | wildfire MP4, SRT and frame | Credit NASA Goddard; the page identifies third-party music, so review audio terms before redistribution |
| [NASA Earth Observatory](https://earthobservatory.nasa.gov/blogs/eokids/) | Smoky Skies illustrated PDF | Review each image credit; preserve source attribution |
| [NOAA NCEI Storm Events](https://www.ncei.noaa.gov/pub/data/swdi/stormevents/csvfiles/) | 2017 details CSV and format PDF | U.S. Government data; definitions/coverage vary by era and updates may revise records |

NASA-led Earth science data are generally open under the agency's
[data-use policy](https://www.earthdata.nasa.gov/engage/open-data-services-software/data-use-policy),
but individual pages can contain third-party components. A public manifest and downloader are safer
than automatically redistributing every raw asset. This card is not legal advice.

## Intended tasks

- Retrieve visible smoke/fire/satellite observations from frames or pages.
- Link report language/transcript timecodes to official records.
- Aggregate event count, damage, deaths or injuries by year/state/type.
- Ask for current official context through opt-in web routing.
- Detect missing/contradictory evidence and abstain.

Example challenge: “Which states show the greatest reported wildfire property damage, and do the
uploaded visual/report sources actually support a claim about smoke extent?” A good answer must keep
the numerical aggregation separate from what pixels/report text establish.

## Known limitations and bias

- The video/report is educational/communications material, not raw remote-sensing validation data.
- Visual smoke, cloud and burn scars can be confused; imagery alone may not establish cause.
- NOAA Storm Events depends on reporting practices, definitions and historical coverage; dollar and
  harm estimates can be missing or revised.
- The demonstration combines broad wildfire education with one year's U.S. table; it does not imply
  every asset describes the same incident.
- English OCR/transcription and U.S. agencies dominate; geography/language/institutional perspectives
  are not representative.
- `retrieved_at`, `published_at` and `observed_at` must not be conflated in an expanded corpus.

## Broader-track expansion protocol

The composed global v2.1 registry now plans 46 event-disjoint events across nine hazard types, seven
expansion regions and six verified source languages. It is still a source registry and annotation plan, not a materialized,
independently adjudicated benchmark. Before release, a data custodian must acquire and hash-lock the
source bytes, verify licenses, complete blind dual annotation plus third-party adjudication, and seal
test labels away from developers. For every asset, record the canonical event, source URL, hash,
retrieval/publication/observation time, geometry, modality/page/timecode, credit/license,
parent-child lineage, OCR confidence and extractor/model versions. Redistribute raw bytes only when
terms are clear.

Do not bootstrap a production benchmark from TOFU on every machine. Review once, store the lock under
release change control, verify it in CI/staging before ingestion, and require a new dataset version
plus evaluation rerun for any accepted byte/source/license change.

The preregistered v2.1 split is 21 train / 11 development / 14 sealed test. The test split covers all
nine hazard families, all seven explicitly tagged expansion regions and all six verified source
languages (`ar`, `el`, `en`, `es`, `fr`, `pt-BR`). The immutable v1 assignments are unchanged. The
extra test event is necessary because the seven hazards absent from the v1 test consume seven
expansion slots while French and Greek are verified only on different wildfire events. Consequently,
the old 13-event test could not satisfy both requirements without false language metadata. The linked
IMD Annual Climate Summary 2024 self-declares English and is not treated as Hindi.

Per split, train has 21 events / 7 hazards / 3 tagged regions / 1 verified language / 3 recent-public
events; development has 11 / 5 / 5 / 2 / 3; sealed test has 14 / 9 / 7 / 6 / 2. Region and language
counts describe only expansion events with explicit reviewed metadata and do not infer tags for the
immutable v1 events. No final test question, label or result is present in this repository.

Split by event—not random chunks—to prevent near-duplicate leakage. Gold questions should cover
visual comparison, temporal ordering, SQL aggregation, multimodal corroboration, conflicts, source
freshness and deliberately unanswerable claims. Require dual human annotation for citations and
adjudicate disagreements.

## Evaluation metrics

- Routing macro-F1 and exact tool-set accuracy.
- Retrieval Recall@5/10/30, MRR/nDCG, per-modality recall and source diversity.
- SQL execution and denotation accuracy over safe queries.
- Citation precision, citation coverage and claim-level entailment.
- Correct abstention, contradiction identification and date/source calibration.
- Prompt-injection/tool-violation and canary-leak rate (target zero).
- p50/p95 latency, peak memory, token/cost and quality by model/index version.
