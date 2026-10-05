# Region- and time-level visual grounding

## Scope and trust boundary

CrisisWeave now carries typed visual locators from extraction through persistence, retrieval,
citations and the public query response. A locator identifies *where to inspect*. It is not, by
itself, proof that the region entails an answer claim.

Every locator declares one source:

- `derived_provenance`: deterministic parser output, such as an entire rendered page or sampled
  frame window;
- `human_annotation`: a benchmark-custodian annotation created by a human inspecting the pixels;
- `model_proposal`: a system prediction that the benchmark scorer must independently compare with
  human gold.

The isolated parser is allowed to emit only `derived_provenance`. It cannot promote its own output
to `human_annotation`. The benchmark rejects human-sourced predictions, model-sourced gold and any
self-reported `entailed` field.

## Locator types

All planar coordinates use a top-left origin and values normalized to `[0, 1]`. A normalized box is
portable across original images, resized model inputs and rendered derivatives:

```json
{"x_min": 0.10, "y_min": 0.20, "x_max": 0.60, "y_max": 0.75}
```

Supported locators are:

| Kind | Required identity | Location |
|---|---|---|
| `image_bbox` | optional bounded label | normalized bounding box |
| `pdf_bbox` | page number and `normalized_top_left` coordinate space | normalized page box |
| `chart_element` | stable element ID and type; optional page, series and category | normalized element box |
| `video_time_range` | start and end seconds | temporal interval and optional normalized frame box |

Boxes must have positive area. Video intervals must have positive duration. Values must be finite;
NaN and infinity are rejected. Labels and chart identifiers are bounded, single-line strings.
Evidence accepts no more than 32 locators, and the evidence modality/page/time must agree with each
locator. Duplicate locators are rejected.

## Extraction behavior

The current parser does not claim to detect objects or chart elements:

- an image receives a full-surface `derived_provenance` box;
- each rendered PDF page receives a full-page `derived_provenance` box with its page number;
- each sampled video frame receives a bounded `derived_provenance` time window and full-frame box;
- OCR and transcripts remain textual evidence and do not become pixel annotations;
- chart-element and tight object boxes must come from a reviewed annotation process or an explicitly
  labeled model proposal.

Only the first chunk tied to a derived artifact carries its visual locator. This mirrors the existing
artifact lineage and prevents text-only continuation chunks from masquerading as pixel evidence.
Locators are serialized inside a reserved metadata envelope in DuckDB/PostgreSQL and reconstructed
as typed objects. The reserved key is removed from ordinary metadata and cannot be supplied by a
chunk. Older rows without the envelope remain valid and expose an empty locator list.

## Query API

Each public evidence item and structured citation can include `regions`. Internal tenant IDs,
document IDs, metadata keys and local artifact paths remain absent. For example:

```json
{
  "evidence_id": "4ff...",
  "label": "E1",
  "source_name": "assessment.pdf",
  "page": 7,
  "regions": [
    {
      "kind": "pdf_bbox",
      "page": 7,
      "coordinate_space": "normalized_top_left",
      "bbox": {"x_min": 0.0, "y_min": 0.0, "x_max": 1.0, "y_max": 1.0},
      "label": "entire rendered page",
      "source": "derived_provenance"
    }
  ]
}
```

The output verifier adds a warning when returned citations have locators: the locators do not assert
claim-level entailment. Pixel-backed claims retain the separate warning that vision quality still
requires validation.

## Benchmark annotation and prediction contract

A human-adjudicated visual claim must bind one or more regions to its visual supporting evidence.
Every visual claim in an annotation packet therefore requires at least one typed
`human_annotation` region for its cited visual evidence; a missing region is invalid rather than
treated as non-applicable:

```json
{
  "claim_id": "claim-1",
  "visual_evidence_ids": ["evidence-1"],
  "entailed_regions": [
    {
      "evidence_id": "evidence-1",
      "region": {
        "kind": "image_bbox",
        "bbox": {"x_min": 0.1, "y_min": 0.2, "x_max": 0.6, "y_max": 0.8},
        "source": "human_annotation"
      }
    }
  ]
}
```

A system places proposals on the corresponding citation:

```json
{
  "claim_id": "claim-1",
  "evidence_id": "evidence-1",
  "regions": [
    {
      "kind": "image_bbox",
      "bbox": {"x_min": 0.12, "y_min": 0.19, "x_max": 0.59, "y_max": 0.79},
      "source": "model_proposal"
    }
  ]
}
```

The deterministic scorer performs one-to-one matching within the same case, claim and evidence ID:

- image/PDF boxes require spatial intersection-over-union (IoU) of at least `0.5`;
- PDF boxes also require the same page;
- chart elements require matching element type, ID, page, series and category plus box IoU;
- video intervals require temporal IoU of at least `0.5`; when human gold includes a frame box,
  spatial IoU must also meet the threshold;
- labels and free-form prose do not affect matching;
- one proposal cannot satisfy multiple human regions.

The scorer reports region precision, coverage and their harmonic mean as
`region_visual_entailment`, plus gold/predicted/matched region counts. The metrics are `null` only
when a split has no visual claims; if visual claims exist, public reports must carry non-null metrics
and all three denominators. Missing predictions score zero when human gold exists.

## What this does not prove

This implementation provides typed locators and a deterministic region/time scorer, and the
benchmark protocol requires human gold regions for visual claims. It does **not** yet provide a
runtime tight-region model: the parser emits full-page/full-frame provenance only, while a system
must explicitly supply `model_proposal` boxes or time ranges for the scorer. Nor does the repository
contain independently completed annotations or frozen test labels. It therefore cannot claim
region-level visual entailment results today.

The implementation also does not establish OCR quality, object-detection accuracy, chart
understanding, vision-model calibration or semantic entailment outside independently adjudicated
data. Those require independent labels, per-hazard error analysis and human review for consequential
uses.
