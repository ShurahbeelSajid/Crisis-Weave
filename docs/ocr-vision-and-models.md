# OCR, vision, and model setup

This guide separates the project's three visual capabilities and gives exact configuration steps.
They solve different problems and can be enabled independently.

## The three layers

| Layer | Runs when | Reads | Produces | Does not prove |
|---|---|---|---|---|
| OCR | Ingestion | Characters visible in a page/image/frame | Searchable text | Object, color, shape, chart, or spatial meaning |
| Visual embedding | Ingestion and retrieval | Pixel features | A vector used to find likely visual evidence | The answer to a visual question |
| Vision-language answer model | Query | The question, evidence text, and selected JPEG pixels | A cited natural-language answer | That every page was inspected or that a region label is human-validated |

For example, OCR may extract the words `Burned area`, CLIP may retrieve a wildfire image, and the
vision model may describe where the scar appears. No one layer replaces the other two.

## Option A: default Windows OCR

The normal local launcher uses Windows Runtime OCR automatically when all of these are true:

- `CRISISWEAVE_APP_ENV=development`;
- the operating system is Windows;
- Tesseract is not found at `CRISISWEAVE_TESSERACT_PATH`;
- a compatible OCR language is installed in the Windows user profile.

No model download or OCR API key is needed. Scanned PDF pages are rendered at approximately 144 DPI
and sparse-text pages are sent to OCR. Standalone images and sampled video frames are also OCR
candidates.

Important boundaries:

- Windows chooses the user-profile OCR language; this project has no separate Windows OCR language
  setting.
- The fallback returns text but not confidence scores or tight word boxes. The stored locator covers
  the source page/image.
- `crisisweave doctor` reports whether Tesseract exists. A `tesseract: false` result does not mean
  the Windows development fallback is unavailable.
- Tesseract takes precedence when its executable is found.
- OCR happens during ingestion. Restart and re-ingest after changing OCR configuration.

The ingestion result displays a warning naming the Windows OCR language when this fallback was used.
Verify critical figures against the cited page.

## Option B: configure Tesseract

Use Tesseract when you need a repeatable OCR executable across machines or a production/parser
environment. Install a reviewed Tesseract distribution and its required language data outside this
repository. Then set its exact path in the same PowerShell process that starts CrisisWeave:

```powershell
$env:CRISISWEAVE_TESSERACT_PATH = "C:\Program Files\Tesseract-OCR\tesseract.exe"
& $env:CRISISWEAVE_TESSERACT_PATH --version
& .\.venv313\Scripts\python.exe -m crisisweave.cli doctor
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\scripts\run_local.ps1"
```

The extractor invokes the executable without a shell, writes OCR to standard output, applies a
timeout, and currently uses automatic page segmentation (`--psm 3`). It does not pass `-l`, so the
application does not currently expose a supported per-document Tesseract language selector. Manage
the executable's installed/default language data deliberately and test it on your documents.

After enabling or changing Tesseract:

1. Stop the existing local process with `Ctrl+C`.
2. Start it with the environment variable above.
3. Reset or delete previously ingested documents.
4. Upload the original files again.
5. Check warnings and compare critical OCR text with the cited pixels.

If Tesseract is found but returns no text, CrisisWeave does not retry the page with Windows OCR. Fix
the Tesseract installation/input quality and re-ingest.

## Configure a router and vision answer model

The model gateway uses an OpenAI-compatible `/chat/completions` contract. Compatibility means more
than accepting text:

- the router deployment must return typed `tool_calls` and support forced function choice;
- the answer deployment must accept OpenAI-style base64 `image_url` data URLs;
- the exact model IDs must exist on that provider;
- the endpoint must not require redirects or ambient proxy settings;
- the endpoint must fit the configured request timeout and response-size limits.

One deployment may serve both roles only if it passes both contracts. Default model-name strings in
configuration are placeholders, not downloaded or verified models.

### 1. Stop the running local copy

Press `Ctrl+C` in the terminal that started CrisisWeave. Re-running the launcher while a healthy copy
is active intentionally leaves its old configuration unchanged.

### 2. Set provider variables

Set these in PowerShell before running the launcher:

```powershell
$env:CRISISWEAVE_LLM_PROVIDER = "openai_compatible"
$env:CRISISWEAVE_LLM_BASE_URL = "https://your-approved-gateway.example/v1"
$env:CRISISWEAVE_LLM_API_KEY = "replace-with-a-scoped-provider-key"
$env:CRISISWEAVE_LLM_ROUTER_MODEL = "exact-tool-capable-model-id"
$env:CRISISWEAVE_LLM_ANSWER_MODEL = "exact-vision-capable-model-id"
$env:CRISISWEAVE_ROUTER_TEMPERATURE = "0.0"
$env:CRISISWEAVE_ANSWER_TEMPERATURE = "0.1"
```

For a no-authentication development endpoint, do not set `CRISISWEAVE_LLM_API_KEY`. Never commit a
real key to `.env`, screenshots, logs, or documentation. The base URL is the API root ending in
`/v1`; do not append `/chat/completions` because the application adds it.

The one-command launcher supplies process-level local defaults when a variable is absent. Therefore,
for this launcher, set model overrides in the current PowerShell process as shown above; editing only
`.env` is not sufficient for fields that the launcher defaults.

Enabling an external provider sends the user's question, bounded evidence text, and up to the
configured number of selected images to that provider. Approve the provider for the data's privacy
classification before enabling it.

### 3. Run the capability probe

Development startup does not automatically contact the model. Run this explicit probe first:

```powershell
& .\.venv313\Scripts\python.exe -c "import asyncio; from crisisweave.config import get_settings; from crisisweave.llm import ModelGateway; asyncio.run(ModelGateway(get_settings()).verify_capabilities()); print('Provider canary passed')"
```

The probe forces one `search_evidence` tool call and sends a self-contained one-pixel red image to
the answer model. `Provider canary passed` proves only those two protocol capabilities. It does not
test OCR, retrieval quality, chart reasoning, citations, bounding boxes, latency, or load.

Production API startup runs this probe automatically and fails closed when it does not pass.

### 4. Start and test

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\scripts\run_local.ps1"
```

First ask a cited text question. Then ask a visual question about a page that is likely to be
retrieved. The gateway attaches only retrieved PDF-page, image, or video-frame artifacts: four images
by default, no more than 5 MiB each, sent as low-detail JPEG data URLs. It does not scan the entire
document at query time.

If synthesis fails, CrisisWeave falls back to a cited extractive answer and reports the provider
error type without exposing credentials.

## Configure real text and visual retrieval

The default hash index validates plumbing but does not encode pixel semantics. To use BGE-style text
embeddings, CLIP visual embeddings, and a cross-encoder reranker, install the ML extras:

```powershell
& .\.venv313\Scripts\python.exe -m pip install -e ".[dev,ui,ml]"
```

Then set reviewed model IDs. These examples match the project's development defaults; they are not
immutable production approvals:

```powershell
$env:CRISISWEAVE_EMBEDDING_PROVIDER = "sentence_transformers"
$env:CRISISWEAVE_TEXT_EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"
$env:CRISISWEAVE_VISUAL_EMBEDDING_MODEL = "clip-ViT-B-32"
$env:CRISISWEAVE_RERANKER_PROVIDER = "cross_encoder"
$env:CRISISWEAVE_RERANKER_MODEL = "BAAI/bge-reranker-base"
$env:CRISISWEAVE_DATA_DIR = "data-real-model"
$env:CRISISWEAVE_QDRANT_COLLECTION = "crisisweave_evidence_bge_clip_v1"
```

Use a new data directory and collection name because hash and real-model vector fingerprints are
incompatible. Start the app and ingest the originals into the new library. Do not point two running
processes at one embedded Qdrant directory.

Model downloads can be large and may execute provider-library model code. Review licenses and model
sources. Production builds must pin immutable revisions, verify hashes, bundle weights offline, scan
the exact image, and use a new collection/alias migration for embedding changes.

Enabling only the vision answer model lets it inspect pixels on pages selected by the existing
retriever. Enabling CLIP improves visual page selection. For reliable visual question answering,
benchmark the combination rather than either component alone.

## Configure video and transcription

Video frame extraction requires `ffmpeg` and `ffprobe`. Put reviewed binaries on `PATH` or set:

```powershell
$env:CRISISWEAVE_FFMPEG_PATH = "C:\path\to\ffmpeg.exe"
$env:CRISISWEAVE_FFPROBE_PATH = "C:\path\to\ffprobe.exe"
```

For speech-to-text, install the ML extras and set:

```powershell
$env:CRISISWEAVE_TRANSCRIPTION_PROVIDER = "faster_whisper"
$env:CRISISWEAVE_WHISPER_MODEL = "small"
```

Restart and re-ingest. Test the chosen model on the event language, accents, names, background noise,
and domain terminology. Timestamped transcription is separate from frame OCR and vision analysis.

## Configuration and validation checklist

| Expected behavior | Required configuration | Validation |
|---|---|---|
| Search scanned English PDF text on Windows | Development launcher plus compatible Windows OCR language | Ingestion warning names Windows OCR; cited text matches page |
| Repeatable executable OCR | Valid Tesseract path | `--version`, doctor, re-ingest, page comparison |
| Agentic model routing | Tool-capable router model | Capability probe returns success |
| Pixel interpretation | Image-input answer model | Red-image canary plus document-specific visual cases |
| Visual page retrieval | CLIP visual embedding model and fresh index | Per-modality Recall@K on labeled cases |
| Semantic text retrieval | BGE/SentenceTransformers and fresh index | Recall@K, nDCG, MRR |
| Model reranking | Cross-encoder reranker | Compare with no-reranking baseline |
| Video frames | FFmpeg and ffprobe | Known short video with expected timestamps |
| Speech transcript | Faster Whisper | Human-checked word/timestamp sample |

## Known limitations

- OCR does not understand layout reliably and may join the wrong table row or column.
- The project has no supported per-upload OCR language selector today.
- Windows OCR provides no tight region coordinates in this implementation.
- The answer model sees a bounded retrieved subset, so retrieval failure can hide the right image.
- Low-detail image requests may be insufficient for tiny labels or dense charts.
- Runtime parser locators are provenance-only. Region-level semantic groundedness requires
  independently annotated boxes/chart elements/video intervals and a real-model evaluation.
- A successful capability probe establishes protocol compatibility, not answer quality or safety.
- Production requires the additional identity, tenant-isolation, storage, malware-scanning,
  observability, release-evidence, and resilience gates in [deployment](06-deployment.md) and
  [QA/VAPT status](09-qa-vapt.md).
