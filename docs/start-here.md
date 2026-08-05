# Start here

This guide is for a new local user. It explains what the project can do now, how to start it, what
data to upload, what questions to ask, and what its answers mean.

## Before you begin

CrisisWeave is a research and evidence-discovery tool. It is not an emergency alert source and must
not make an operational decision by itself. Treat every answer as a lead back to cited evidence.

The simplest Windows profile needs:

- Windows 10 or 11;
- Python 3.12 or 3.13 (Python 3.14 is intentionally unsupported);
- enough free space for originals and rendered pages;
- no Docker and no external model for basic PDF/text/OCR use.

FFmpeg/ffprobe are needed only for video. Tesseract is optional for Windows development because the
application can use Windows Runtime OCR. A vision-language model is optional, but pixel-level image
and chart questions need one.

## First-time installation

Run these commands once from the project directory. The example selects Python 3.13 explicitly so a
newer unsupported default interpreter is not used accidentally. Python 3.12 is also supported.

```powershell
py -3.13 --version
py -3.13 -m venv .venv313
& .\.venv313\Scripts\python.exe -m pip install --upgrade pip
& .\.venv313\Scripts\python.exe -m pip install -e ".[dev,ui]"
Copy-Item .env.example .env -ErrorAction SilentlyContinue
```

The directory is deliberately named `.venv313` because the one-command launcher uses that exact
path. It is generated locally and should not be committed.

## Start the backend and frontend

Use one command; activation is not required:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\scripts\run_local.ps1"
```

Then:

1. Open `http://127.0.0.1:8501`.
2. Enter `local-dev-key` when the UI asks for an API key.
3. Keep the PowerShell window open. Press `Ctrl+C` there to stop both services.

The API is at `http://127.0.0.1:8000`; development API docs are at
`http://127.0.0.1:8000/docs`. If a healthy copy is already running, the launcher reports it and
returns safely. If another program owns port 8000 or 8501, the launcher identifies the occupied
port without killing that program.

## Choose useful test data

Start with a small, coherent evidence library rather than unrelated files. Good examples are:

- one disaster assessment report plus its annexes;
- several official situation reports for the same event;
- a report, a satellite image, and a structured event CSV;
- a video briefing plus its transcript;
- reports from two sources that may disagree on totals.

Supported inputs are PDF, JPEG, PNG, WebP, MP4, WebM, CSV, JSON, TXT, MD, SRT, and VTT. The default
upload limit is 50 MB per file. PDFs are limited to 250 pages by default; videos are bounded by
duration and sampled-frame limits.

Prefer sources with a clear title, publisher, event, date, geography, units, and methodology. Add an
HTTPS source URI when known. Avoid mixing unrelated events if you expect a precise comparative
answer; retrieval can only rank the evidence it has.

## Ingest several files

1. Open **Ingestion**.
2. Select multiple files in the uploader.
3. Add source information when available.
4. Submit the batch.
5. Wait for each job to reach `succeeded`, `cancelled`, or `dead_letter`.

Read warnings. For example, an OCR warning means text extraction may be incomplete. A succeeded job
with provenance-only image evidence does not mean the application understood the pixels.

OCR, transcription, and embedding happen during ingestion. After changing those components, delete
or reset the old evidence and ingest the original files again.

## Ask answerable questions

Match the question to the evidence and configured capability.

### Text and OCR questions

- `What total affected population is reported, and where is it stated?`
- `List the three largest economic losses with units and citations.`
- `What methodology does the report use to estimate direct loss?`
- `Do the executive summary and detailed section report the same total?`

### Structured-data questions

- `How many events are recorded by state?`
- `Which event type has the highest total property damage?`
- `Compare average injuries across the listed event types.`

Only normalized allowlisted fields are queryable by SQL. A general table embedded in a PDF is not
automatically equivalent to the structured event table.

### Cross-file questions

- `Which sources agree on the fatality total, and which source differs?`
- `Build a timeline from the three situation reports.`
- `What claim appears in the report but is not supported by the uploaded table?`

### Visual questions

- `What trend does the bar chart on page 20 show?`
- `Which map region is shaded darkest?`
- `Where is the largest visible burn scar?`

These require the relevant page/image to be retrieved and a configured vision-capable answer model.
OCR alone can read labels but cannot establish colors, objects, shapes, or spatial relationships.
See [OCR, vision, and model setup](ocr-vision-and-models.md).

### Abstention checks

Ask one question whose answer is absent, such as `How many hospital beds were damaged?` when the
report has no hospital-bed figure. A safe system should say that authorized evidence is insufficient
rather than inventing an answer.

## Interpret the response

- **Answer:** generated or query-matched text based on the returned evidence.
- **[E#] citation:** a label tied to one evidence unit in this response.
- **Source/page/time locator:** where the evidence came from.
- **Route trace:** which bounded tools were attempted.
- **Retrieval/source diversity:** how varied and strong the retrieved context was; it is not the
  probability that the answer is true.
- **Freshness/conflict warnings:** reasons to seek newer evidence or human review.
- **Abstention:** the system did not find enough authorized support.

Always open the cited page for important numbers. OCR may confuse decimals, separators, currencies,
units, minus signs, or table columns.

## Reset the evidence library

In the UI, open **Reset evidence library**, type `RESET`, and confirm. This deletes indexed documents,
vectors, analytics rows, metadata, and derived files for the current API-key tenant. It does not
delete the original file from your Downloads folder. Terminal ingestion-job history is retained as
audit history and is managed separately.

## Common local problems

### The launcher says a port is in use

If it says CrisisWeave is already healthy, open the reported URL. Otherwise stop the application
that owns the port or close the earlier CrisisWeave terminal, then run the launcher again. The script
will not terminate an unrelated process for you.

### Reset returns `405 Method Not Allowed`

An older backend is still running. Stop its terminal with `Ctrl+C`, start the current launcher, and
refresh the browser.

### A scanned PDF produces weak answers

Check the ingestion warnings and cited page. Windows OCR depends on an installed user-profile OCR
language. For repeatable server behavior, configure Tesseract, restart, reset the library, and
re-ingest. OCR cannot recover unreadable source pixels.

### A visual question abstains

That is expected in the default profile. Configure both an image-capable answer model and, for
reliable page selection, real visual embeddings. A VLM sees only the retrieved images/pages.

### Video ingestion fails

Install FFmpeg and ffprobe, put them on `PATH` or configure their exact paths, restart, and ingest the
video again. Speech-to-text additionally requires the ML dependency group and Faster Whisper.

### A model is enabled but answers fall back to extractive mode

The provider may not support the required tool-call or base64 image-input contract, the exact model
ID may be wrong, or the endpoint may be unavailable. Run the capability probe in
[OCR, vision, and model setup](ocr-vision-and-models.md) before starting the UI.
