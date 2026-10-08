# AI-Based Cyber Incident Reconstruction and Attack Story Generator

Raw security events -> AI correlation -> incident reconstruction -> attack story -> evidence -> confidence -> interactive investigation.
Works fully offline. No API key needed.

## Install (Windows, PowerShell / CMD)
    python -m venv venv
    venv\Scripts\activate
    pip install -r requirements.txt

## Run
    python app.py
Open http://127.0.0.1:5000

## Use
1. Home -> "Analyze sample dataset" (or upload your own .csv / .txt / .json, max 5 MB).
2. Visit Analysis, Incident Reconstruction, Timeline, Evidence Explorer, Investigation Mode, Report.

## Folder map
- app.py - Flask routes and security settings
- modules/ - log_parser, normalizer, anomaly_detector (Isolation Forest), event_correlator (7-factor score + DBSCAN),
  attack_stage, incident_reconstructor, confidence, story_generator, report_generator, pipeline
- database/database.py - SQLite storage of analysis runs
- templates/, static/ - dark SOC-style web UI (pure HTML/CSS/JS, SVG graph, canvas chart)
- data/sample_incident_logs.csv - fictional dataset (hidden attack + normal users + decoys)

Results are SUSPECTED incidents. They are analytical estimates, not proof of an attack.
