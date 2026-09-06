"""
Module 5 — Evidence Report Generator
SIH26106 | AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform

Converts full EmailAnalysisRecord findings into a structured, court/filing-ready
forensic PDF report using Jinja2 and xhtml2pdf.
"""

import os
from io import BytesIO
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, select_autoescape
from xhtml2pdf import pisa

TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
TEMPLATE_NAME = "report_template.html"

# Initialize Jinja2 Environment with autoescape enabled
env = Environment(
    loader=FileSystemLoader(TEMPLATES_DIR),
    autoescape=select_autoescape(["html", "xml"])
)

def _normalize_record(record) -> dict:
    """
    Normalizes a Pydantic EmailAnalysisRecord or raw dict into
    a dictionary suitable for Jinja2 template rendering.
    """
    if hasattr(record, "model_dump"):
        data = record.model_dump()
    elif isinstance(record, dict):
        data = record.copy()
    else:
        raise ValueError("record must be a dict or a Pydantic model with model_dump()")

    # Ensure analyzed_at is formatted nicely
    if "analyzed_at" in data:
        if isinstance(data["analyzed_at"], str):
            try:
                dt = datetime.fromisoformat(data["analyzed_at"].replace("Z", "+00:00"))
                data["analyzed_at"] = dt
            except Exception:
                pass
        elif not isinstance(data["analyzed_at"], datetime):
            data["analyzed_at"] = datetime.utcnow()
    else:
        data["analyzed_at"] = datetime.utcnow()

    return data

def generate_report_html(record) -> str:
    """
    Renders the forensic report HTML template using the provided analysis record.
    """
    data = _normalize_record(record)
    template = env.get_template(TEMPLATE_NAME)
    return template.render(**data)

def generate_report_pdf(record) -> bytes:
    """
    Compiles the forensic findings into a downloadable binary PDF buffer.
    Returns the PDF content as bytes.
    """
    html_content = generate_report_html(record)
    pdf_buffer = BytesIO()
    pisa_status = pisa.CreatePDF(html_content, dest=pdf_buffer)

    if pisa_status.err:
        raise RuntimeError(f"xhtml2pdf encountered errors while creating PDF: {pisa_status.err}")

    return pdf_buffer.getvalue()

def save_report_pdf(record, output_path: str) -> str:
    """
    Generates and saves the PDF report directly to a specified file path.
    """
    pdf_bytes = generate_report_pdf(record)
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(pdf_bytes)
    return output_path
