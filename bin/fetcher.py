import argparse
import json
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

import requests


# ---------------- Logging Setup ----------------
def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(message)s',
        handlers=[logging.StreamHandler()]
    )


def log_json(level, **kwargs):
    print(json.dumps({"level": level, **kwargs}, indent=2))


# ---------------- CLI Parser ----------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Fetch URLs concurrently and save their response body and headers.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument(
        "urls",
        nargs="+",
        help="One or more URLs to fetch"
    )

    parser.add_argument(
        "--output-dir", "-o",
        type=Path,
        default=Path("responses"),
        help="Directory where response files will be saved"
    )

    parser.add_argument(
        "--max-workers", "-w",
        type=int,
        default=10,
        help="Number of concurrent workers (threads)"
    )

    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=10,
        help="Request timeout in seconds"
    )

    parser.add_argument(
        "--json-validate", "-j",
        action="store_true",
        help="Enable optional JSON schema validation for JSON responses"
    )

    return parser.parse_args()


# ---------------- Helpers ----------------
def sanitize_filename(url: str) -> str:
    return re.sub(r"[^\w\-_.]", "_", url)


def format_headers(headers: dict) -> str:
    return "\n".join(f"{k}: {v}" for k, v in headers.items())


def is_html_or_empty(resp: requests.Response) -> bool:
    ct = resp.headers.get("Content-Type", "").lower()
    return "html" in ct or not resp.content.strip()


def validate_json(data: bytes):
    try:
        json.loads(data)
        return True
    except json.JSONDecodeError:
        return False


# ---------------- Fetch Logic ----------------
def fetch_url(url: str, output_dir: Path, timeout: int, validate: bool):
    try:
        resp = requests.get(url, timeout=timeout)
        if is_html_or_empty(resp):
            log_json("warning", url=url, message="Skipped (HTML or empty)")
            return

        fname = sanitize_filename(url)
        output_dir.mkdir(parents=True, exist_ok=True)

        body_path = output_dir / f"{fname}.body"
        headers_path = output_dir / f"{fname}.headers"

        # Save response body
        with open(body_path, "wb") as f:
            f.write(resp.content)

        # Save headers (curl-style)
        with open(headers_path, "w", encoding="utf-8") as f:
            f.write(format_headers(resp.headers))

        log_json("info", url=url, saved_body=str(body_path), saved_headers=str(headers_path))

        if validate:
            if not validate_json(resp.content):
                log_json("error", url=url, message="Invalid JSON content")

    except Exception as e:
        log_json("error", url=url, error=str(e))


# ---------------- Main ----------------
def main():
    setup_logging()
    args = parse_args()

    with ThreadPoolExecutor(max_workers=args.max_workers) as executor:
        futures = [
            executor.submit(fetch_url, url, args.output_dir, args.timeout, args.json_validate)
            for url in args.urls
        ]
        for future in as_completed(futures):
            future.result()


if __name__ == "__main__":
    main()
