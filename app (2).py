"""
AI-Based Cyber Incident Reconstruction and Attack Story Generator
Flask web application - run with:  python app.py   then open http://127.0.0.1:5000
"""
import os

from flask import (Flask, Response, abort, jsonify, redirect, render_template,
                   request, send_from_directory, url_for)
from werkzeug.utils import secure_filename

from database.database import get_latest_run, init_db, list_runs, save_run
from modules.log_parser import ALLOWED_EXTENSIONS
from modules.pipeline import run_pipeline
from modules.report_generator import build_report

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLE_DIR = os.path.join(BASE_DIR, "data")
SAMPLE_FILE = "sample_incident_logs.csv"

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # SECURITY: uploads larger than 5 MB are rejected
init_db()


# SECURITY: extra browser protections on every response
@app.after_request
def add_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:"
    return resp


def _page(template, page, **extra):
    return render_template(template, page=page, has_result=get_latest_run() is not None, **extra)


# ----------------------------------------------------------------- pages
@app.route("/")
def index():
    return _page("index.html", "home", runs=list_runs(), allowed=sorted(ALLOWED_EXTENSIONS))


@app.route("/upload", methods=["POST"])
def upload():
    """Receive a log file (or choose the sample), run the AI pipeline, store the result."""
    try:
        if request.form.get("use_sample"):
            filename = SAMPLE_FILE
            with open(os.path.join(SAMPLE_DIR, SAMPLE_FILE), "rb") as f:
                content = f.read()
        else:
            file = request.files.get("logfile")
            if file is None or file.filename == "":
                raise ValueError("Please choose a log file first.")
            filename = secure_filename(file.filename) or "upload"
            ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            if ext not in ALLOWED_EXTENSIONS:  # SECURITY: extension whitelist
                raise ValueError("Only .csv, .txt and .json files are allowed.")
            content = file.read()  # kept in memory only: never saved, never executed
        result = run_pipeline(content, filename)
        save_run(filename, result)
    except ValueError as err:
        return _page("index.html", "home", runs=list_runs(), allowed=sorted(ALLOWED_EXTENSIONS), error=str(err)), 400
    return redirect(url_for("analysis"))


@app.errorhandler(413)
def too_large(_):
    return _page("index.html", "home", runs=list_runs(), allowed=sorted(ALLOWED_EXTENSIONS),
                 error="File is too large (limit 5 MB)."), 413


@app.route("/analysis")
def analysis():
    return _page("analysis.html", "analysis")


@app.route("/incident")
def incident():
    return _page("incident.html", "incident")


@app.route("/timeline")
def timeline():
    return _page("timeline.html", "timeline")


@app.route("/evidence")
def evidence():
    return _page("evidence.html", "evidence")


@app.route("/investigation")
def investigation():
    return _page("investigation.html", "investigation")


@app.route("/sample")
def download_sample():
    return send_from_directory(SAMPLE_DIR, SAMPLE_FILE, as_attachment=True)


@app.route("/api/result")
def api_result():
    result = get_latest_run()
    if result is None:
        return jsonify({"error": "No analysis yet"}), 404
    return jsonify(result)


# ----------------------------------------------------------------- report
def _report_context():
    result = get_latest_run()
    if result is None:
        abort(404)
    if not result["incidents"]:
        return None
    return build_report(result, result["incidents"][0])


@app.route("/report")
def report():
    ctx = _report_context()
    return render_template("report.html", page="report", has_result=ctx is not None, ctx=ctx)


@app.route("/report/download")
def report_download():
    ctx = _report_context()
    if ctx is None:
        abort(404)
    html = render_template("report_standalone.html", ctx=ctx)
    name = f"{ctx['incident']['incident_id']}_report.html"
    return Response(html, mimetype="text/html",
                    headers={"Content-Disposition": f"attachment; filename={name}"})


@app.errorhandler(404)
def not_found(_):
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
