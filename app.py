import os
import socket
from dotenv import load_dotenv
load_dotenv()  # Load environment variables from .env file

import io
import re
import json
import sqlite3
import base64
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import logging
import qrcode
import uuid
import secrets
import string
import shutil
import glob
import subprocess
import tempfile
import threading
import time
import concurrent.futures
try:
    import magic  # python-magic (requires libmagic on many platforms)
except Exception:
    magic = None
from collections import defaultdict
from types import SimpleNamespace
import sys
from typing import Any

# bleach is required for HTML sanitization. Provide a clear runtime message
# if it's missing so developers running `py app.py` without the project's
# virtualenv get actionable instructions.
try:
    import bleach
    from bleach.css_sanitizer import CSSSanitizer
except ModuleNotFoundError:
    bleach = None
    CSSSanitizer = None
    if __name__ == '__main__':
        sys.stderr.write('\nMissing required package: bleach\n')
        sys.stderr.write('Install into the project venv or activate it before running.\n')
        sys.stderr.write('To activate venv in PowerShell:\n')
        sys.stderr.write('  .\\.venv\\Scripts\\Activate.ps1\n')
        sys.stderr.write('Then run: python app.py\n')
        sys.stderr.write('Or run directly with the venv python:\n')
        sys.stderr.write('  .\\venv\\Scripts\\python.exe app.py\n\n')
        sys.exit(1)
    else:
        # If imported as a library, raise a clearer error at import time
        raise

# cryptography is required for encrypting stored panel passwords (Server.password)
try:
    from cryptography.fernet import Fernet, InvalidToken
except ModuleNotFoundError:
    Fernet = None
    InvalidToken = Exception
    if __name__ == '__main__':
        sys.stderr.write('\nMissing required package: cryptography\n')
        sys.stderr.write('Install into the project venv or activate it before running.\n')
        sys.stderr.write('Example:\n')
        sys.stderr.write('  pip install -r requirements.txt\n\n')
        sys.exit(1)
    else:
        raise
from datetime import datetime, timedelta, timezone
from functools import wraps
import copy
try:
    from zoneinfo import ZoneInfo, available_timezones
except Exception:
    ZoneInfo = None
    available_timezones = None
from flask import Flask, render_template, jsonify, request, send_file, redirect, url_for, session, g, make_response, Response, stream_with_context
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from urllib.parse import urlparse, quote, urlencode, unquote
from jdatetime import datetime as jdatetime_class
from sqlalchemy import or_, and_, func, text, inspect, case
from sqlalchemy.orm import joinedload

APP_VERSION = "2.3.0"
GITHUB_REPO = "yoyoraya/eve-xui-manager"
APP_START_TS = time.time()

# Simple in-memory cache for update checks
UPDATE_CACHE = {
    'last_check': 0,
    'data': None,
    'ttl': 3600  # 1 hour cache
}

# کش برای نگهداری وضعیت سرورها در RAM
# این دیتا با هر بار ریستارت برنامه پاک می‌شود (امنیت بالا)
GLOBAL_SERVER_DATA = {
    'last_update': None,
    'inbounds': [],
    'stats': {},
    'servers_status': [],
    'is_updating': False
}

# ── Optional Redis (shared cache across gunicorn workers) ────────────────────
# When REDIS_URL is set AND reachable, one worker fetches panel data and writes
# the processed snapshot to Redis; all workers read it from there. If Redis is
# missing/unreachable, the app transparently falls back to per-worker fetching.
REDIS_URL = (os.environ.get('REDIS_URL') or '').strip()
REDIS_SNAPSHOT_KEY = 'eve:server_data_snapshot'
_REDIS_CLIENT = None
_REDIS_CHECKED = False
_REDIS_LOCK = threading.Lock()


def get_redis():
    """Return a connected redis client, or None if unavailable.
    Result is cached; a failed connection disables Redis for the process."""
    global _REDIS_CLIENT, _REDIS_CHECKED
    if _REDIS_CHECKED:
        return _REDIS_CLIENT
    with _REDIS_LOCK:
        if _REDIS_CHECKED:
            return _REDIS_CLIENT
        _REDIS_CHECKED = True
        if not REDIS_URL:
            _REDIS_CLIENT = None
            return None
        try:
            import redis as _redis_lib
            client = _redis_lib.from_url(
                REDIS_URL, socket_connect_timeout=2, socket_timeout=2,
                decode_responses=False)
            client.ping()
            _REDIS_CLIENT = client
            print(f"[Redis] connected: {REDIS_URL}")
        except Exception as _re:
            print(f"[Redis] unavailable ({_re}); using per-worker in-memory cache.")
            _REDIS_CLIENT = None
        return _REDIS_CLIENT


def redis_enabled() -> bool:
    return get_redis() is not None


REDIS_SNAPSHOT_VERSION_KEY = 'eve:server_data_version'
REDIS_SNAPSHOT_TTL = 180  # seconds; expires if the fetcher dies
_LAST_LOADED_SNAPSHOT_VERSION = None


def publish_snapshot_to_redis() -> bool:
    """Serialize the current GLOBAL_SERVER_DATA snapshot to Redis (compressed).
    Called only by the singleton fetcher. Returns True on success."""
    client = get_redis()
    if client is None:
        return False
    try:
        import pickle, zlib
        payload = {
            'inbounds': GLOBAL_SERVER_DATA.get('inbounds') or [],
            'stats': GLOBAL_SERVER_DATA.get('stats') or {},
            'servers_status': GLOBAL_SERVER_DATA.get('servers_status') or [],
            'last_update': GLOBAL_SERVER_DATA.get('last_update'),
        }
        blob = zlib.compress(pickle.dumps(payload, protocol=pickle.HIGHEST_PROTOCOL), 1)
        version = str(time.time())
        pipe = client.pipeline()
        pipe.set(REDIS_SNAPSHOT_KEY, blob, ex=REDIS_SNAPSHOT_TTL)
        pipe.set(REDIS_SNAPSHOT_VERSION_KEY, version, ex=REDIS_SNAPSHOT_TTL)
        pipe.execute()
        return True
    except Exception as e:
        print(f"[Redis] publish snapshot failed: {e}")
        return False


def load_snapshot_from_redis(force: bool = False) -> bool:
    """Pull the shared snapshot from Redis into local GLOBAL_SERVER_DATA, but
    only when the version changed (cheap version check first). Returns True if
    the local cache was updated."""
    global _LAST_LOADED_SNAPSHOT_VERSION
    client = get_redis()
    if client is None:
        return False
    try:
        version = client.get(REDIS_SNAPSHOT_VERSION_KEY)
        if version is None:
            return False
        if not force and version == _LAST_LOADED_SNAPSHOT_VERSION:
            return False  # nothing new — skip the expensive decompress
        blob = client.get(REDIS_SNAPSHOT_KEY)
        if not blob:
            return False
        import pickle, zlib
        payload = pickle.loads(zlib.decompress(blob))
        GLOBAL_SERVER_DATA['inbounds'] = payload.get('inbounds') or []
        GLOBAL_SERVER_DATA['stats'] = payload.get('stats') or {}
        GLOBAL_SERVER_DATA['servers_status'] = payload.get('servers_status') or []
        GLOBAL_SERVER_DATA['last_update'] = payload.get('last_update')
        _LAST_LOADED_SNAPSHOT_VERSION = version
        return True
    except Exception as e:
        print(f"[Redis] load snapshot failed: {e}")
        return False

# Ownership cache: pre-loaded from DB, used by enrich_inbounds_with_ownership.
# Avoids a per-request DB query with thousands of emails in IN clause.
_OWNERSHIP_CACHE: dict = {
    'email_map': {},   # {(server_id, email_lower): {'id':..,'username':..,'created_at':..}}
    'uuid_map':  {},   # {(server_id, uuid_lower):  {'id':..,'username':..,'created_at':..}}
    'updated_at': 0.0, # time.monotonic()
}
_OWNERSHIP_CACHE_LOCK = threading.Lock()
OWNERSHIP_CACHE_TTL = 30  # seconds — ownership refreshed at most every 30 s

def _build_ownership_maps() -> tuple[dict, dict, bool]:
    """Query DB once and return (email_map, uuid_map, success)."""
    email_map: dict = {}
    uuid_map:  dict = {}
    try:
        rows = (
            db.session.query(ClientOwnership, Admin)
            .join(Admin, ClientOwnership.reseller_id == Admin.id)
            .all()
        )
        for own, reseller in rows:
            try:
                sid = int(own.server_id)
            except Exception:
                continue
            created = own.created_at or datetime.min
            info = {
                'id': int(reseller.id) if reseller else None,
                'username': reseller.username if reseller else None,
                'created_at': created,
            }
            em = (own.client_email or '').strip().lower()
            if em:
                key = (sid, em)
                ex = email_map.get(key)
                if not ex or created >= ex.get('created_at', datetime.min):
                    email_map[key] = info
            uu = (own.client_uuid or '').strip().lower()
            if uu:
                key = (sid, uu)
                ex = uuid_map.get(key)
                if not ex or created >= ex.get('created_at', datetime.min):
                    uuid_map[key] = info
        return email_map, uuid_map, True
    except Exception:
        app.logger.exception("_build_ownership_maps failed — ownership cache not updated")
        return email_map, uuid_map, False

def _get_ownership_maps(force: bool = False) -> tuple[dict, dict]:
    """Return cached (email_map, uuid_map); rebuild from DB if stale."""
    now = time.monotonic()
    with _OWNERSHIP_CACHE_LOCK:
        if not force and now - _OWNERSHIP_CACHE['updated_at'] < OWNERSHIP_CACHE_TTL:
            return _OWNERSHIP_CACHE['email_map'], _OWNERSHIP_CACHE['uuid_map']
    # Build outside lock to avoid blocking other threads
    em, um, ok = _build_ownership_maps()
    with _OWNERSHIP_CACHE_LOCK:
        _OWNERSHIP_CACHE['email_map'] = em
        _OWNERSHIP_CACHE['uuid_map']  = um
        if ok:
            # Only cache on success — if DB failed, next request retries immediately
            _OWNERSHIP_CACHE['updated_at'] = time.monotonic()
    return em, um

def invalidate_ownership_cache() -> None:
    """Call after any ownership change so next request rebuilds from DB."""
    with _OWNERSHIP_CACHE_LOCK:
        _OWNERSHIP_CACHE['updated_at'] = 0.0

# Prevent overlapping forced refreshes (e.g. after rapid UI actions)
GLOBAL_REFRESH_LOCK = threading.Lock()

# Refresh job tracking (in-memory; per-process)
REFRESH_JOBS = {}  # job_id -> job dict
REFRESH_JOBS_LOCK = threading.Lock()
REFRESH_MAX_JOBS = 50

# Bulk job tracking. Persist to a shared file so progress polling works across
# gunicorn workers while the background worker updates the job.
BULK_JOBS_FILE = os.path.join(tempfile.gettempdir(), 'eve_bulk_jobs.json')
BULK_JOBS = {}  # job_id -> job dict (status/progress only — client list kept in BULK_JOBS_CLIENTS)
BULK_JOBS_CLIENTS = {}  # job_id -> client list (in-memory only; NOT persisted to avoid huge files)
BULK_JOBS_LOCK = threading.Lock()
BULK_MAX_JOBS = 50
BULK_SAVE_EVERY = 25   # write progress to disk every N clients (not every single one)

# Manual snapshot progress tracking
# Written to a shared file so all gunicorn workers see the same state.
_SNAPSHOT_PROGRESS_FILE = '/tmp/eve_snapshot_progress.json'
_SNAPSHOT_PROGRESS = {
    'status': 'idle',   # idle | running | done | error
    'step': 0,
    'total': 0,
    'current_server': '',
    'message': '',
    'message_fa': '',
    'inbound_count': 0,
    'fetched_fresh': False,
    'error': None,
}

def _set_snap_progress(updates):
    """Update _SNAPSHOT_PROGRESS and persist to shared file for cross-worker visibility."""
    global _SNAPSHOT_PROGRESS
    _SNAPSHOT_PROGRESS.update(updates)
    try:
        import json as _json
        with open(_SNAPSHOT_PROGRESS_FILE, 'w') as _f:
            _json.dump(_SNAPSHOT_PROGRESS, _f)
    except Exception:
        pass

def _read_snap_progress():
    """Read progress from shared file; fall back to in-memory dict."""
    try:
        import json as _json
        with open(_SNAPSHOT_PROGRESS_FILE) as _f:
            return _json.load(_f)
    except Exception:
        return _SNAPSHOT_PROGRESS

# Telegram backup job tracking. Persist to a shared file so all gunicorn
# workers can report status for jobs started by another worker.
TELEGRAM_BACKUP_JOBS_FILE = os.path.join(tempfile.gettempdir(), 'eve_telegram_backup_jobs.json')
TELEGRAM_BACKUP_JOBS = {}  # job_id -> job dict
TELEGRAM_BACKUP_JOBS_LOCK = threading.Lock()
TELEGRAM_BACKUP_MAX_JOBS = 20

MAX_FILE_SIZE = 10 * 1024 * 1024        # 10 MB  — general file uploads
BACKUP_UPLOAD_MAX_SIZE = 2048 * 1024 * 1024  # 2 GB — full migration bundles (DB + all uploaded files) can exceed 512 MB

# Allowed HTML tags and attributes for FAQ content (XSS Prevention)
ALLOWED_FAQ_TAGS = [
    'a', 'abbr', 'acronym', 'b', 'blockquote', 'code', 'em', 'i', 'li', 'ol', 'strong', 'ul',
    'p', 'br', 'span', 'div', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'img', 'hr'
]
ALLOWED_FAQ_ATTRIBUTES = {
    'a': ['href', 'title', 'target'],
    'abbr': ['title'],
    'acronym': ['title'],
    'img': ['src', 'alt', 'title', 'width', 'height', 'class'],
    'span': ['class', 'style'],
    'div': ['class', 'style'],
    'p': ['class', 'style'],
}
ALLOWED_FAQ_STYLES = ['color', 'background-color', 'font-size', 'text-align', 'direction']


def sanitize_html(content, tags=None, attributes=None, styles=None):
    """Sanitize HTML content to prevent XSS."""
    if content is None:
        return None
    if not isinstance(content, str):
        content = str(content)
    
    # bleach 5.0+ uses CSSSanitizer instead of styles argument
    css_sanitizer = None
    if styles is not None and CSSSanitizer:
        css_sanitizer = CSSSanitizer(allowed_css_properties=styles)
    
    return bleach.clean(
        content,
        tags=tags if tags is not None else [],
        attributes=attributes if attributes is not None else {},
        css_sanitizer=css_sanitizer,
        strip=True
    )

# Backoff to avoid hammering failing servers during periodic refresh
REFRESH_BACKOFF = {}  # server_id -> {fail_count:int, next_allowed_at:float, last_error:str, last_failed_at:float}
REFRESH_MAX_BACKOFF_SEC = 300

# Session cache for X-UI panels to speed up API calls
XUI_SESSION_CACHE = {}  # server_id -> {'session': requests.Session, 'expiry': float}
XUI_SESSION_TTL = 600  # 10 minutes cache

WHATSAPP_SEND_TRACKER = {
    'per_recipient': {},
    'daily': {'date': '', 'count': 0}
}
WHATSAPP_SEND_TRACKER_LOCK = threading.Lock()


def _utc_iso_now():
    return datetime.utcnow().isoformat()


def _parse_bool(value) -> bool:
    return str(value or '').strip().lower() in ('1', 'true', 'yes', 'y', 'on')


def _summarize_job(job):
    if not isinstance(job, dict):
        return None
    # keep payload small
    keys = (
        'id', 'state', 'mode', 'server_id', 'force',
        'created_at', 'started_at', 'finished_at',
        'progress', 'error'
    )
    return {k: job.get(k) for k in keys if k in job}


def _summarize_bulk_job(job):
    if not isinstance(job, dict):
        return None
    keys = (
        'id', 'state', 'action',
        'created_at', 'started_at', 'finished_at',
        'progress', 'error', 'report_rows', 'report_rules'
    )
    return {k: job.get(k) for k in keys if k in job}


def _summarize_telegram_backup_job(job):
    if not isinstance(job, dict):
        return None
    keys = (
        'id', 'state', 'trigger',
        'created_at', 'started_at', 'finished_at',
        'stage', 'progress', 'error',
        'success_count', 'total', 'results'
    )
    return {k: job.get(k) for k in keys if k in job}


def _prune_telegram_backup_jobs_locked():
    if len(TELEGRAM_BACKUP_JOBS) <= TELEGRAM_BACKUP_MAX_JOBS:
        return
    jobs_sorted = sorted(TELEGRAM_BACKUP_JOBS.items(), key=lambda kv: kv[1].get('created_at_ts', 0))
    to_delete = max(0, len(TELEGRAM_BACKUP_JOBS) - TELEGRAM_BACKUP_MAX_JOBS)
    deleted = 0
    for job_id, job in jobs_sorted:
        if deleted >= to_delete:
            break
        if job.get('state') in ('done', 'error'):
            TELEGRAM_BACKUP_JOBS.pop(job_id, None)
            deleted += 1


def _load_telegram_backup_jobs_locked():
    global TELEGRAM_BACKUP_JOBS
    try:
        with open(TELEGRAM_BACKUP_JOBS_FILE, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            TELEGRAM_BACKUP_JOBS = data
    except Exception:
        pass
    return TELEGRAM_BACKUP_JOBS


def _save_telegram_backup_jobs_locked():
    try:
        tmp_path = TELEGRAM_BACKUP_JOBS_FILE + '.tmp'
        with open(tmp_path, 'w', encoding='utf-8') as fh:
            json.dump(TELEGRAM_BACKUP_JOBS, fh, ensure_ascii=False)
        os.replace(tmp_path, TELEGRAM_BACKUP_JOBS_FILE)
    except Exception as exc:
        try:
            app.logger.warning(f"Could not persist Telegram backup jobs: {exc}")
        except Exception:
            pass


def _get_telegram_backup_job(job_id: str):
    with TELEGRAM_BACKUP_JOBS_LOCK:
        return copy.deepcopy(_load_telegram_backup_jobs_locked().get(job_id))


def _update_telegram_backup_job(job_id: str, **patch):
    with TELEGRAM_BACKUP_JOBS_LOCK:
        _load_telegram_backup_jobs_locked()
        job = TELEGRAM_BACKUP_JOBS.get(job_id)
        if not job:
            return
        for k, v in patch.items():
            job[k] = v
        TELEGRAM_BACKUP_JOBS[job_id] = job
        _save_telegram_backup_jobs_locked()


def _run_telegram_backup_job(job_id: str):
    with TELEGRAM_BACKUP_JOBS_LOCK:
        _load_telegram_backup_jobs_locked()
        job = TELEGRAM_BACKUP_JOBS.get(job_id)
        if not job:
            return
        job['state'] = 'running'
        job['started_at'] = _utc_iso_now()
        job['stage'] = 'starting'
        TELEGRAM_BACKUP_JOBS[job_id] = job
        _save_telegram_backup_jobs_locked()

    def progress_cb(update: dict):
        if not isinstance(update, dict):
            return
        patch = {}
        if update.get('stage') is not None:
            patch['stage'] = update['stage']
        if update.get('progress') is not None:
            patch['progress'] = update['progress']
        if update.get('results') is not None:
            patch['results'] = update['results']
        if patch:
            _update_telegram_backup_job(job_id, **patch)

    try:
        with app.app_context():
            job_snapshot = _get_telegram_backup_job(job_id) or {}
            result = _run_telegram_backup(trigger=str(job_snapshot.get('trigger') or 'manual'), progress_cb=progress_cb)
    except Exception as exc:
        _update_telegram_backup_job(job_id, state='error', finished_at=_utc_iso_now(), error=str(exc), stage='error')
        return

    all_results = result.get('results') or []
    success_count = int(result.get('success_count') or 0)
    total_count = int(result.get('total') or 0)
    failures = [r for r in all_results if not r.get('success')]

    if result.get('success'):
        # Partial success: some servers failed — still mark done but include failure details
        partial_error = None
        if failures:
            partial_error = '; '.join(f"{r.get('server_name','?')}: {r.get('error','?')}" for r in failures)
        _update_telegram_backup_job(
            job_id,
            state='done',
            finished_at=_utc_iso_now(),
            stage='done',
            success_count=success_count,
            total=total_count,
            results=all_results,
            error=partial_error,
        )
    else:
        _update_telegram_backup_job(
            job_id,
            state='error',
            finished_at=_utc_iso_now(),
            stage='error',
            success_count=success_count,
            total=total_count,
            results=all_results,
            error=result.get('error') or 'Backup failed',
        )


def _prune_bulk_jobs_locked():
    _load_bulk_jobs_locked()
    if len(BULK_JOBS) <= BULK_MAX_JOBS:
        return
    jobs_sorted = sorted(BULK_JOBS.items(), key=lambda kv: kv[1].get('created_at_ts', 0))
    to_delete = max(0, len(BULK_JOBS) - BULK_MAX_JOBS)
    deleted = 0
    for job_id, job in jobs_sorted:
        if deleted >= to_delete:
            break
        if job.get('state') in ('done', 'error'):
            BULK_JOBS.pop(job_id, None)
            deleted += 1
    if deleted:
        _save_bulk_jobs_locked()


def _load_bulk_jobs_locked():
    """Merge the on-disk snapshot into the in-memory BULK_JOBS.

    With gunicorn --workers 3, a bulk job runs as a thread in ONE worker while
    polling requests are load-balanced across all workers. The old code did
    `BULK_JOBS = data` (full replace), which in a multi-worker race could drop
    a job a worker was actively tracking → "Job not found". We now MERGE:
    for each job, keep whichever copy has more progress, and never drop an
    in-memory job that the disk snapshot happens to lack.
    """
    global BULK_JOBS
    try:
        with open(BULK_JOBS_FILE, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return BULK_JOBS
    except Exception:
        return BULK_JOBS

    def _processed(job):
        try:
            return int((job.get('progress') or {}).get('processed', 0) or 0)
        except Exception:
            return 0

    merged = dict(BULK_JOBS)  # start from in-memory
    for jid, disk_job in data.items():
        mem_job = merged.get(jid)
        if mem_job is None:
            merged[jid] = disk_job
            continue
        # A finished state is authoritative; otherwise keep the further-along copy.
        mem_done = mem_job.get('state') in ('done', 'error')
        disk_done = disk_job.get('state') in ('done', 'error')
        if disk_done and not mem_done:
            merged[jid] = disk_job
        elif mem_done and not disk_done:
            pass  # keep mem
        elif _processed(disk_job) > _processed(mem_job):
            merged[jid] = disk_job
        # else keep mem (it's at least as fresh)
    BULK_JOBS = merged
    return BULK_JOBS


def _save_bulk_jobs_locked():
    """Persist BULK_JOBS to disk.  Clients are stored in BULK_JOBS_CLIENTS (memory-only)
    so the file stays small even with thousands of clients per job.

    Before writing, jobs that exist ONLY on disk (created by another gunicorn
    worker) are preserved so a save from this worker never clobbers another
    worker's concurrent job.
    """
    try:
        # Never write the client list to disk — it can be MB-sized per job.
        slim = {}
        for jid, j in BULK_JOBS.items():
            slim[jid] = {k: v for k, v in j.items() if k != 'clients'}

        # Preserve other workers' jobs that we don't have in memory.
        try:
            with open(BULK_JOBS_FILE, 'r', encoding='utf-8') as fh:
                disk = json.load(fh)
            if isinstance(disk, dict):
                for jid, dj in disk.items():
                    if jid not in slim:
                        slim[jid] = dj
        except Exception:
            pass

        tmp_path = BULK_JOBS_FILE + '.tmp'
        with open(tmp_path, 'w', encoding='utf-8') as fh:
            json.dump(slim, fh, ensure_ascii=False)
        os.replace(tmp_path, BULK_JOBS_FILE)
    except Exception as exc:
        try:
            app.logger.warning(f"Could not persist bulk jobs: {exc}")
        except Exception:
            pass


def _bulk_progress_update(job_id: str, *, processed_delta: int = 1,
                          success: int = 0, failed: int = 0, skipped: int = 0,
                          error_entry: dict | None = None,
                          report_row: dict | None = None,
                          force_save: bool = False) -> None:
    """Thread-safe progress update for _run_bulk_job.

    Writes to disk only every BULK_SAVE_EVERY clients (not on every single
    client) to prevent thousands of I/O operations for large bulk actions.
    Pass force_save=True for state transitions (start/done/error).
    """
    with BULK_JOBS_LOCK:
        j = BULK_JOBS.get(job_id)
        if j is None:
            return
        pr = j.get('progress') or {}
        pr['processed'] = int(pr.get('processed', 0) or 0) + processed_delta
        if success:
            pr['success']  = int(pr.get('success',  0) or 0) + success
        if failed:
            pr['failed']   = int(pr.get('failed',   0) or 0) + failed
        if skipped:
            pr['skipped']  = int(pr.get('skipped',  0) or 0) + skipped
        if error_entry:
            errs = j.get('errors') or []
            if len(errs) < 50:
                errs.append(error_entry)
            j['errors'] = errs
        if report_row:
            rows = j.get('report_rows') or []
            if len(rows) < 10000:
                rows.append(report_row)
            j['report_rows'] = rows
        j['progress'] = pr
        BULK_JOBS[job_id] = j
        # Throttle disk writes: only every BULK_SAVE_EVERY clients or on force
        if force_save or (int(pr.get('processed', 0)) % BULK_SAVE_EVERY == 0):
            _save_bulk_jobs_locked()


def _run_bulk_job(job_id: str):
    with BULK_JOBS_LOCK:
        _load_bulk_jobs_locked()
        job = BULK_JOBS.get(job_id)
        if not job:
            return
        job['state'] = 'running'
        job['started_at'] = _utc_iso_now()
        BULK_JOBS[job_id] = job
        _save_bulk_jobs_locked()

    try:
        with app.app_context():
            job = None
            with BULK_JOBS_LOCK:
                # Read status from memory first (avoid disk replacement race).
                # _load_bulk_jobs_locked is intentionally skipped here — the job
                # was just saved at the top of this function.
                job = BULK_JOBS.get(job_id) or {}
                # Client list is kept in the separate in-memory dict to avoid
                # bloating the persisted file with thousands of client entries.
                clients = BULK_JOBS_CLIENTS.get(job_id) or job.get('clients') or []

            action = job.get('action')
            data = job.get('data') or {}
            conditions = job.get('conditions') or {}
            user_id = job.get('user_id')

            user = db.session.get(Admin, user_id)
            if not user:
                raise RuntimeError('User not found')

            reseller_id = None
            if action == 'assign_owner':
                reseller_id = data.get('reseller_id')
                try:
                    reseller_id = int(reseller_id)
                except (TypeError, ValueError):
                    reseller_id = None
                if not reseller_id:
                    raise RuntimeError('reseller_id required')
                reseller = db.session.get(Admin, reseller_id)
                if not reseller or reseller.role != 'reseller':
                    raise RuntimeError('Invalid reseller')

            server_ids = []
            for item in clients:
                if isinstance(item, dict) and 'server_id' in item:
                    server_ids.append(item.get('server_id'))
            normalized_server_ids = []
            for sid in server_ids:
                try:
                    normalized_server_ids.append(int(sid))
                except (TypeError, ValueError):
                    continue
            normalized_server_ids = list({sid for sid in normalized_server_ids})
            servers_by_id = {}
            if normalized_server_ids:
                for s in Server.query.filter(Server.id.in_(normalized_server_ids)).all():
                    servers_by_id[s.id] = s

            def _normalize_bulk_conditions(raw: Any) -> dict:
                if not isinstance(raw, dict):
                    return {}
                enable_state = (raw.get('enable_state') or 'any').strip().lower()
                if enable_state not in ('any', 'enabled', 'disabled'):
                    enable_state = 'any'
                expiry_type = (raw.get('expiry_type') or 'any').strip().lower()
                if expiry_type not in ('any', 'unlimited', 'start_after_use', 'expired', 'today', 'soon', 'normal'):
                    expiry_type = 'any'
                return {
                    'enable_state': enable_state,
                    'expiry_type': expiry_type,
                }

            normalized_conditions = _normalize_bulk_conditions(conditions)

            def _fetch_client_snapshot(_user: 'Admin', _server: 'Server', _inbound_id: int, _email: str):
                """Fetch a best-effort client dict with at least enable/expiryTime/totalGB/up/down."""
                target_client = None
                cached_client_row = None

                try:
                    cached_inbounds = GLOBAL_SERVER_DATA.get('inbounds') or []
                except Exception:
                    cached_inbounds = []

                for ib in cached_inbounds:
                    try:
                        if int(ib.get('server_id', -1)) != int(_server.id):
                            continue
                        if int(ib.get('id', -1)) != int(_inbound_id):
                            continue
                        for c in ib.get('clients', []):
                            if (c.get('email') or '') == _email:
                                cached_client_row = c
                                if isinstance(c, dict) and 'raw_client' in c and isinstance(c.get('raw_client'), dict):
                                    target_client = copy.deepcopy(c.get('raw_client'))
                                break
                    except Exception:
                        continue
                    if cached_client_row:
                        break

                session_obj, error = get_xui_session(_server)
                if error:
                    return None, error

                if not target_client:
                    inbounds, fetch_err, detected_type = fetch_inbounds(session_obj, _server.host, _server.panel_type)
                    if fetch_err:
                        return None, fetch_err
                    persist_detected_panel_type(_server, detected_type)
                    target_client, _ = find_client(inbounds, _inbound_id, _email)
                    if not target_client:
                        return None, 'Client not found'

                # Merge missing caps/usage from cached row when available.
                if cached_client_row and isinstance(target_client, dict):
                    for k in ('enable', 'up', 'down', 'totalGB', 'expiryTime'):
                        try:
                            if target_client.get(k) in (None, '') and cached_client_row.get(k) not in (None, ''):
                                target_client[k] = cached_client_row.get(k)
                            elif k in ('up', 'down', 'totalGB', 'expiryTime'):
                                if int(target_client.get(k) or 0) == 0 and int(cached_client_row.get(k) or 0) != 0:
                                    target_client[k] = cached_client_row.get(k)
                        except Exception:
                            pass

                return target_client, None

            def _matches_conditions(client_obj: dict, cond: dict) -> bool:
                if not cond:
                    return True
                if not isinstance(client_obj, dict):
                    return False

                enable_state = (cond.get('enable_state') or 'any')
                if enable_state != 'any':
                    is_enabled = bool(client_obj.get('enable'))
                    if enable_state == 'enabled' and not is_enabled:
                        return False
                    if enable_state == 'disabled' and is_enabled:
                        return False

                expiry_type = (cond.get('expiry_type') or 'any')
                if expiry_type != 'any':
                    try:
                        exp_info = format_remaining_days(client_obj.get('expiryTime', 0))
                        cur_type = (exp_info.get('type') or '').strip().lower()
                    except Exception:
                        cur_type = ''
                    if cur_type != expiry_type:
                        return False

                return True

            def _wt_patch_cache(_server, _email, tc):
                """Write-through the cache after a successful bulk client update."""
                try:
                    patch_cached_client(
                        _server.id, _email,
                        client_uuid=str(tc.get('id')) if tc.get('id') else None,
                        total_gb_bytes=int(tc.get('totalGB') or 0),
                        expiry_ts=int(tc.get('expiryTime') or 0),
                        enable=tc.get('enable'))
                except Exception:
                    pass

            def _post_client_update(_server: 'Server', _inbound_id: int, _email: str, target_client: dict):
                session_obj, error = get_xui_session(_server)
                if error:
                    return False, error, 400

                if server_is_v3(_server):
                    ok, _vr, verr = v3_update_client(_server, session_obj, _email, target_client)
                    if ok:
                        _wt_patch_cache(_server, _email, target_client)
                        return True, None, 200
                    detail = verr or 'panel rejected update'
                    app.logger.warning(f"Bulk update client (v3) failed for {_email}: {detail}")
                    return False, detail, 502

                # Shadowsocks clients have no UUID 'id' — updateClient/:clientId won't work.
                if 'id' not in target_client:
                    _ibs, _fe, _ = fetch_inbounds(session_obj, _server.host, _server.panel_type)
                    _full_ib = None
                    if not _fe:
                        for _ib in (_ibs or []):
                            if _ib.get('id') == _inbound_id:
                                _full_ib = _ib
                                break
                    if _full_ib is None:
                        detail = 'shadowsocks: could not fetch full inbound for update'
                        app.logger.warning(f"Bulk update client failed for {_email}: {detail}")
                        return False, detail, 400
                    _full_settings = _json_field(_full_ib.get('settings'), {})
                    _full_settings['clients'] = [
                        target_client if c.get('email') == _email else c
                        for c in _full_settings.get('clients', [])
                    ]
                    _ok_push, _push_err = _push_full_inbound(_server, session_obj, _full_ib, _full_settings)
                    if _ok_push:
                        _wt_patch_cache(_server, _email, target_client)
                        return True, None, 200
                    detail = _push_err or 'shadowsocks inbound update failed'
                    app.logger.warning(f"Bulk update client failed for {_email}: {detail}")
                    return False, detail, 400

                client_id = target_client.get('id', target_client.get('password', _email))
                update_payload = {
                    'id': _inbound_id,
                    'settings': json.dumps({'clients': [target_client]})
                }

                replacements = {
                    'id': _inbound_id,
                    'inbound_id': _inbound_id,
                    'inboundId': _inbound_id,
                    'clientId': client_id,
                    'client_id': client_id,
                    'email': _email
                }

                templates = collect_endpoint_templates(_server.panel_type, 'client_update', CLIENT_UPDATE_FALLBACKS)
                errors = []
                for template in templates:
                    full_url = build_panel_url(_server.host, template, replacements)
                    if not full_url:
                        continue
                    try:
                        resp = session_obj.post(full_url, json=update_payload, verify=False, timeout=10)
                    except Exception as exc:
                        errors.append(f"{template}: {exc}")
                        continue
                    if resp.status_code == 200:
                        try:
                            resp_json = resp.json()
                            if isinstance(resp_json, dict) and resp_json.get('success') is False:
                                panel_msg = resp_json.get('msg') or resp_json.get('message') or 'success=false'
                                errors.append(f"{template}: {panel_msg}")
                                continue
                        except ValueError:
                            pass
                        _wt_patch_cache(_server, _email, target_client)
                        return True, None, 200
                    errors.append(f"{template}: HTTP {resp.status_code}")

                detail = '; '.join(errors) or 'no endpoint succeeded'
                app.logger.warning(f"Bulk update client failed for {_email}: {detail}")
                return False, detail, 400

            def _reset_client_traffic_core(_server: 'Server', _inbound_id: int, _email: str):
                session_obj, error = get_xui_session(_server)
                if error:
                    return False, error, 400

                if server_is_v3(_server):
                    ok, _vr, verr = v3_reset_client(_server, session_obj, _email)
                    if ok:
                        return True, None, 200
                    detail = verr or 'reset failed'
                    app.logger.warning(f"Bulk reset traffic (v3) failed for {_email}: {detail}")
                    return False, detail, 502

                replacements = {
                    'id': _inbound_id,
                    'inbound_id': _inbound_id,
                    'inboundId': _inbound_id,
                    'email': _email
                }
                templates = collect_endpoint_templates(_server.panel_type, 'client_reset_traffic', CLIENT_RESET_FALLBACKS)
                errors = []
                for template in templates:
                    full_url = build_panel_url(_server.host, template, replacements)
                    if not full_url:
                        continue
                    requires_path_email = (':email' in template) or ('{email}' in template)
                    payload = None if requires_path_email else {'email': _email}
                    try:
                        if payload is None:
                            resp = session_obj.post(full_url, verify=False, timeout=10)
                        else:
                            resp = session_obj.post(full_url, json=payload, verify=False, timeout=10)
                    except Exception as exc:
                        errors.append(f"{template}: {exc}")
                        continue
                    if resp.status_code == 200:
                        try:
                            resp_json = resp.json()
                            if isinstance(resp_json, dict) and resp_json.get('success') is False:
                                panel_msg = resp_json.get('msg') or resp_json.get('message') or 'success=false'
                                errors.append(f"{template}: {panel_msg}")
                                continue
                        except ValueError:
                            pass
                        return True, None, 200
                    errors.append(f"{template}: HTTP {resp.status_code}")

                detail = '; '.join(errors) or 'no endpoint succeeded'
                app.logger.warning(f"Bulk reset traffic failed for {_email}: {detail}")
                return False, detail, 400

            def _apply_client_limit_delta(_user: 'Admin', _server: 'Server', _inbound_id: int, _email: str,
                                          days_delta: int | None = None, volume_gb_delta: int | None = None):
                if _user.role == 'reseller':
                    if not _has_client_access(_user, _server.id, _email, inbound_id=_inbound_id):
                        return False, 'Access denied', 403

                # validate deltas
                if days_delta is not None:
                    try:
                        days_delta = int(days_delta)
                    except Exception:
                        return False, 'Invalid days value', 400
                    if days_delta <= 0:
                        return False, 'Days must be > 0', 400
                if volume_gb_delta is not None:
                    try:
                        volume_gb_delta = int(volume_gb_delta)
                    except Exception:
                        return False, 'Invalid volume value', 400
                    if volume_gb_delta <= 0:
                        return False, 'Volume must be > 0', 400

                target_client, err = _fetch_client_snapshot(_user, _server, _inbound_id, _email)
                if err:
                    return False, err, 400
                if not isinstance(target_client, dict):
                    return False, 'Client not found', 404

                # Calculate new expiry (if requested)
                if days_delta is not None:
                    current_expiry = target_client.get('expiryTime', 0)
                    try:
                        current_expiry_int = int(current_expiry or 0)
                    except (TypeError, ValueError):
                        current_expiry_int = 0

                    if current_expiry_int < 0:
                        # Not started yet: add to pending duration
                        new_expiry = current_expiry_int - (days_delta * 86400000)
                    elif current_expiry_int > 0:
                        current_date = datetime.fromtimestamp(current_expiry_int / 1000)
                        new_date = current_date + timedelta(days=days_delta)
                        new_expiry = int(new_date.timestamp() * 1000)
                    else:
                        new_date = datetime.now() + timedelta(days=days_delta)
                        new_expiry = int(new_date.timestamp() * 1000)
                    target_client['expiryTime'] = new_expiry

                # Calculate new cap (if requested)
                if volume_gb_delta is not None:
                    try:
                        current_total_bytes = int(target_client.get('totalGB') or 0)
                    except (TypeError, ValueError):
                        current_total_bytes = 0

                    # If current is unlimited (0), keep unlimited.
                    if current_total_bytes == 0:
                        new_total_bytes = 0
                    else:
                        new_total_bytes = current_total_bytes + (volume_gb_delta * 1024 * 1024 * 1024)
                    target_client['totalGB'] = new_total_bytes

                return _post_client_update(_server, _inbound_id, _email, target_client)

            def _normalize_volume_policy_rules(raw_rules: Any) -> list[dict]:
                if not isinstance(raw_rules, list):
                    return []
                rules = []
                for raw_rule in raw_rules:
                    if not isinstance(raw_rule, dict):
                        continue
                    try:
                        min_gb = float(raw_rule.get('min_remaining_gb'))
                        max_gb = float(raw_rule.get('max_remaining_gb'))
                        target_gb = float(raw_rule.get('target_gb'))
                    except (TypeError, ValueError):
                        continue
                    if min_gb < 0 or max_gb < 0 or target_gb < 0:
                        continue
                    if max_gb < min_gb:
                        min_gb, max_gb = max_gb, min_gb
                    mode = str(raw_rule.get('mode') or 'set_remaining').strip().lower()
                    if mode not in ('set_remaining', 'reset_and_set'):
                        mode = 'set_remaining'
                    rules.append({
                        'min_remaining_gb': min_gb,
                        'max_remaining_gb': max_gb,
                        'target_gb': target_gb,
                        'mode': mode,
                    })
                return rules

            def _bytes_to_gb_float(value: int | float | None) -> float:
                try:
                    return round(float(value or 0) / float(1024 ** 3), 3)
                except Exception:
                    return 0.0

            def _apply_client_volume_policy(_user: 'Admin', _server: 'Server', _inbound_id: int, _email: str, raw_rules: Any):
                report = {
                    'server_id': getattr(_server, 'id', None),
                    'server_name': getattr(_server, 'name', '') or '',
                    'inbound_id': _inbound_id,
                    'email': _email,
                    'status': 'failed',
                    'error': None,
                }
                if _user.role == 'reseller':
                    if not _has_client_access(_user, _server.id, _email, inbound_id=_inbound_id):
                        report['error'] = 'Access denied'
                        return False, 'Access denied', 403, report

                rules = _normalize_volume_policy_rules(raw_rules)
                if not rules:
                    report['error'] = 'No valid volume rules'
                    return False, 'No valid volume rules', 400, report

                target_client, err = _fetch_client_snapshot(_user, _server, _inbound_id, _email)
                if err:
                    report['error'] = err
                    return False, err, 400, report
                if not isinstance(target_client, dict):
                    report['error'] = 'Client not found'
                    return False, 'Client not found', 404, report

                try:
                    current_total_bytes = int(target_client.get('totalGB') or 0)
                except (TypeError, ValueError):
                    current_total_bytes = 0
                if current_total_bytes <= 0:
                    report.update({
                        'status': 'skipped',
                        'reason': 'unlimited_volume',
                        'before_total_gb': 0,
                        'before_remaining_gb': None,
                        'after_total_gb': 0,
                        'after_remaining_gb': None,
                    })
                    return True, 'Unlimited volume skipped', 204, report

                try:
                    used_up = int(target_client.get('up') or 0)
                except (TypeError, ValueError):
                    used_up = 0
                try:
                    used_down = int(target_client.get('down') or 0)
                except (TypeError, ValueError):
                    used_down = 0
                used_bytes = max(0, used_up + used_down)
                remaining_bytes = max(0, current_total_bytes - used_bytes)
                remaining_gb = remaining_bytes / float(1024 ** 3)
                report.update({
                    'before_total_gb': _bytes_to_gb_float(current_total_bytes),
                    'before_remaining_gb': round(remaining_gb, 3),
                    'used_gb': _bytes_to_gb_float(used_bytes),
                })

                matched_rule = None
                for rule in rules:
                    if rule['min_remaining_gb'] <= remaining_gb <= rule['max_remaining_gb']:
                        matched_rule = rule
                        break
                if not matched_rule:
                    report.update({
                        'status': 'skipped',
                        'reason': 'no_matching_rule',
                        'after_total_gb': report.get('before_total_gb'),
                        'after_remaining_gb': report.get('before_remaining_gb'),
                    })
                    return True, 'No matching volume rule', 204, report

                target_bytes = int(round(matched_rule['target_gb'] * (1024 ** 3)))
                report.update({
                    'matched_min_gb': matched_rule['min_remaining_gb'],
                    'matched_max_gb': matched_rule['max_remaining_gb'],
                    'target_gb': matched_rule['target_gb'],
                    'mode': matched_rule['mode'],
                })
                if matched_rule['mode'] == 'reset_and_set':
                    target_client['up'] = 0
                    target_client['down'] = 0
                    target_client['totalGB'] = target_bytes
                    ok, update_err, status = _post_client_update(_server, _inbound_id, _email, target_client)
                    if not ok:
                        report['error'] = update_err
                        return ok, update_err, status, report
                    reset_ok, reset_err, reset_status = _reset_client_traffic_core(_server, _inbound_id, _email)
                    if not reset_ok:
                        report['error'] = reset_err
                        return reset_ok, reset_err, reset_status, report
                    report.update({
                        'status': 'changed',
                        'after_total_gb': _bytes_to_gb_float(target_bytes),
                        'after_remaining_gb': _bytes_to_gb_float(target_bytes),
                    })
                    return True, None, 200, report

                new_total_bytes = used_bytes + target_bytes
                target_client['totalGB'] = new_total_bytes
                ok, update_err, status = _post_client_update(_server, _inbound_id, _email, target_client)
                if ok:
                    report.update({
                        'status': 'changed',
                        'after_total_gb': _bytes_to_gb_float(new_total_bytes),
                        'after_remaining_gb': _bytes_to_gb_float(target_bytes),
                    })
                else:
                    report['error'] = update_err
                return ok, update_err, status, report

            def _apply_client_volume_multiplier(_user: 'Admin', _server: 'Server', _inbound_id: int, _email: str, _data: dict):
                """Apply a numeric multiplier to a client's remaining volume.

                mode=set_remaining: new cap = used + (remaining × factor)  [no traffic reset]
                mode=reset_and_set: reset up/down to 0, new cap = remaining × factor
                """
                report = {
                    'server_id': getattr(_server, 'id', None),
                    'server_name': getattr(_server, 'name', '') or '',
                    'inbound_id': _inbound_id,
                    'email': _email,
                    'status': 'failed',
                    'error': None,
                }
                if _user.role == 'reseller':
                    if not _has_client_access(_user, _server.id, _email, inbound_id=_inbound_id):
                        report['error'] = 'Access denied'
                        return False, 'Access denied', 403, report

                try:
                    factor = float(_data.get('factor') or 0)
                except (TypeError, ValueError):
                    factor = 0
                if factor <= 0:
                    report['error'] = 'Invalid factor'
                    return False, 'Invalid factor', 400, report
                mode = str(_data.get('mode') or 'set_remaining').strip().lower()

                target_client, err = _fetch_client_snapshot(_user, _server, _inbound_id, _email)
                if err:
                    report['error'] = err
                    return False, err, 400, report
                if not isinstance(target_client, dict):
                    report['error'] = 'Client not found'
                    return False, 'Client not found', 404, report

                try:
                    current_total_bytes = int(target_client.get('totalGB') or 0)
                except (TypeError, ValueError):
                    current_total_bytes = 0
                if current_total_bytes <= 0:
                    report.update({'status': 'skipped', 'reason': 'unlimited_volume'})
                    return True, 'Unlimited volume skipped', 204, report

                try:
                    used_bytes = max(0, int(target_client.get('up') or 0) + int(target_client.get('down') or 0))
                except (TypeError, ValueError):
                    used_bytes = 0
                remaining_bytes = max(0, current_total_bytes - used_bytes)
                remaining_gb = remaining_bytes / float(1024 ** 3)

                # Optional skip range: if remaining falls within [skip_min_gb, skip_max_gb], do nothing.
                try:
                    skip_min = float(_data.get('skip_min_gb')) if _data.get('skip_min_gb') is not None else None
                except (TypeError, ValueError):
                    skip_min = None
                try:
                    skip_max = float(_data.get('skip_max_gb')) if _data.get('skip_max_gb') is not None else None
                except (TypeError, ValueError):
                    skip_max = None

                in_skip_range = (
                    (skip_min is not None or skip_max is not None) and
                    (skip_min is None or remaining_gb >= skip_min) and
                    (skip_max is None or remaining_gb <= skip_max)
                )
                if in_skip_range:
                    report.update({
                        'status': 'skipped',
                        'reason': 'in_skip_range',
                        'before_remaining_gb': round(remaining_gb, 3),
                    })
                    return True, 'Skipped (remaining in skip range)', 204, report

                new_remaining_bytes = int(round(remaining_bytes * factor))

                report.update({
                    'before_total_gb': _bytes_to_gb_float(current_total_bytes),
                    'before_remaining_gb': _bytes_to_gb_float(remaining_bytes),
                    'used_gb': _bytes_to_gb_float(used_bytes),
                    'factor': factor,
                    'mode': mode,
                })

                if mode == 'reset_and_set':
                    target_client['up'] = 0
                    target_client['down'] = 0
                    target_client['totalGB'] = new_remaining_bytes
                    new_total_bytes = new_remaining_bytes
                else:  # set_remaining
                    new_total_bytes = used_bytes + new_remaining_bytes
                    target_client['totalGB'] = new_total_bytes

                ok, update_err, _status = _post_client_update(_server, _inbound_id, _email, target_client)
                if ok:
                    report.update({
                        'status': 'changed',
                        'after_total_gb': _bytes_to_gb_float(new_total_bytes),
                        'after_remaining_gb': _bytes_to_gb_float(new_remaining_bytes),
                    })
                else:
                    report['error'] = update_err
                return ok, update_err, _status, report

            for item in clients:
                client_ref = item
                if not isinstance(item, dict):
                    _bulk_progress_update(job_id, failed=1)
                    continue

                try:
                    server_id = int(item.get('server_id'))
                    inbound_id = int(item.get('inbound_id'))
                    email = (item.get('email') or '').strip()
                    client_uuid = (item.get('client_uuid') or '').strip()
                except (TypeError, ValueError):
                    server_id = None
                    inbound_id = None
                    email = ''
                    client_uuid = ''

                if not server_id or inbound_id is None or not email:
                    _bulk_progress_update(job_id, failed=1,
                        error_entry={'client': client_ref, 'error': 'server_id, inbound_id and email are required'})
                    continue

                server = servers_by_id.get(server_id)
                if not server:
                    _bulk_progress_update(job_id, failed=1,
                        error_entry={'client': {'server_id': server_id, 'inbound_id': inbound_id, 'email': email},
                                     'error': 'Server not found'})
                    continue

                # Optional conditional targeting
                if normalized_conditions and (normalized_conditions.get('enable_state') != 'any' or normalized_conditions.get('expiry_type') != 'any'):
                    try:
                        snap, snap_err = _fetch_client_snapshot(user, server, inbound_id, email)
                        if snap_err:
                            raise RuntimeError(snap_err)
                        if not _matches_conditions(snap, normalized_conditions):
                            _bulk_progress_update(job_id, skipped=1)
                            continue
                    except Exception as exc:
                        _bulk_progress_update(job_id, failed=1,
                            error_entry={'client': {'server_id': server_id, 'inbound_id': inbound_id, 'email': email},
                                         'error': str(exc) or 'Condition check failed'})
                        continue

                ok = False
                err = None
                skipped = False
                report_row = None

                if action in ('enable', 'disable'):
                    ok, err, _status = _toggle_client_core(user, server, inbound_id, email, action == 'enable')
                elif action == 'delete':
                    ok, err, _status = _delete_client_core(user, server, inbound_id, email)
                elif action == 'add_days':
                    delta = data.get('days_delta')
                    ok, err, _status = _apply_client_limit_delta(user, server, inbound_id, email, days_delta=delta, volume_gb_delta=None)
                elif action == 'add_volume':
                    delta = data.get('volume_gb_delta')
                    ok, err, _status = _apply_client_limit_delta(user, server, inbound_id, email, days_delta=None, volume_gb_delta=delta)
                elif action == 'volume_policy':
                    ok, err, _status, report_row = _apply_client_volume_policy(user, server, inbound_id, email, data.get('volume_rules'))
                    skipped = bool(ok and _status == 204)
                elif action == 'volume_multiplier':
                    ok, err, _status, report_row = _apply_client_volume_multiplier(user, server, inbound_id, email, data)
                    skipped = bool(ok and _status == 204)
                elif action == 'set_start_after_use':
                    snap, snap_err = _fetch_client_snapshot(user, server, inbound_id, email)
                    if snap_err:
                        ok, err, _status = False, snap_err, 400
                    elif not isinstance(snap, dict):
                        ok, err, _status = False, 'Client not found', 404
                    else:
                        try:
                            exp = int(snap.get('expiryTime') or 0)
                        except (TypeError, ValueError):
                            exp = 0
                        if exp <= 0:
                            # already start_after_use (negative) or unlimited (0) → skip
                            ok, err, _status = True, None, 204
                            skipped = True
                        else:
                            now_ms = int(time.time() * 1000)
                            remaining_ms = exp - now_ms
                            if remaining_ms <= 0:
                                # expired → skip
                                ok, err, _status = True, None, 204
                                skipped = True
                            else:
                                snap['expiryTime'] = -remaining_ms
                                ok, err, _status = _post_client_update(server, inbound_id, email, snap)
                elif action == 'set_inbounds':
                    if not server_is_v3(server):
                        ok, err, _status = False, 'Server is not v3', 400
                    else:
                        _mode = (data.get('inbound_mode') or 'set').lower()
                        _tids = data.get('inbound_ids') or []
                        ok, err, _status, _info = _reconcile_client_inbounds(
                            user, server, email, client_uuid, _tids, _mode)
                        skipped = bool(ok and _status == 204)
                elif action == 'assign_owner':
                    email_l = (email or '').lower()
                    try:
                        key_filters = []
                        if client_uuid:
                            key_filters.append(ClientOwnership.client_uuid == client_uuid)
                        if email_l:
                            key_filters.append(func.lower(ClientOwnership.client_email) == email_l)
                        q = ClientOwnership.query.filter(ClientOwnership.server_id == server_id)
                        if key_filters:
                            q = q.filter(or_(*key_filters))
                        q.delete(synchronize_session=False)
                        db.session.flush()  # Ensure delete is sent to DB before insert

                        ownership = ClientOwnership(
                            reseller_id=reseller_id,
                            server_id=server_id,
                            inbound_id=inbound_id,
                            client_email=email,
                            client_uuid=client_uuid if client_uuid else None
                        )
                        db.session.add(ownership)

                        # Keep reseller "Allowed Servers" in sync with assignments
                        try:
                            ensure_reseller_allowed_for_assignment(reseller, server_id, inbound_id)
                        except Exception:
                            pass

                        db.session.commit()
                        ok = True
                    except Exception as exc:
                        db.session.rollback()
                        ok = False
                        err = str(exc)
                elif action == 'unassign_owner':
                    email_l = (email or '').lower()
                    try:
                        key_filters = []
                        if client_uuid:
                            key_filters.append(ClientOwnership.client_uuid == client_uuid)
                        if email_l:
                            key_filters.append(func.lower(ClientOwnership.client_email) == email_l)
                        q = ClientOwnership.query.filter(ClientOwnership.server_id == server_id)
                        if key_filters:
                            q = q.filter(or_(*key_filters))
                        q.delete(synchronize_session=False)
                        db.session.commit()
                        ok = True
                    except Exception as exc:
                        db.session.rollback()
                        ok = False
                        err = str(exc)
                else:
                    ok = False
                    err = 'Invalid action'

                _bulk_progress_update(
                    job_id,
                    success=1 if (ok and not skipped) else 0,
                    skipped=1 if skipped else 0,
                    failed=1 if (not ok and not skipped) else 0,
                    error_entry=(None if (ok or skipped) else
                                 {'client': {'server_id': server_id, 'inbound_id': inbound_id, 'email': email},
                                  'error': err or 'Failed'}),
                    report_row=(report_row if (action == 'volume_policy' and isinstance(report_row, dict)) else None),
                )

        with BULK_JOBS_LOCK:
            job = BULK_JOBS.get(job_id) or {}
            job['state'] = 'done'
            job['finished_at'] = _utc_iso_now()
            BULK_JOBS[job_id] = job
            _save_bulk_jobs_locked()
            _prune_bulk_jobs_locked()
    except Exception as e:
        with BULK_JOBS_LOCK:
            job = BULK_JOBS.get(job_id) or {}
            job['state'] = 'error'
            job['error'] = str(e)
            job['finished_at'] = _utc_iso_now()
            BULK_JOBS[job_id] = job
            _save_bulk_jobs_locked()
            _prune_bulk_jobs_locked()
    finally:
        # Free the in-memory client list once the job is finished
        BULK_JOBS_CLIENTS.pop(job_id, None)


def _prune_refresh_jobs_locked():
    if len(REFRESH_JOBS) <= REFRESH_MAX_JOBS:
        return
    # prune oldest finished jobs first
    jobs_sorted = sorted(REFRESH_JOBS.items(), key=lambda kv: kv[1].get('created_at_ts', 0))
    to_delete = max(0, len(REFRESH_JOBS) - REFRESH_MAX_JOBS)
    deleted = 0
    for job_id, job in jobs_sorted:
        if deleted >= to_delete:
            break
        if job.get('state') in ('done', 'error'):
            REFRESH_JOBS.pop(job_id, None)
            deleted += 1


def _backoff_get(server_id: int) -> dict:
    try:
        return REFRESH_BACKOFF.get(int(server_id)) or {}
    except Exception:
        return {}


def _backoff_should_skip(server_id: int, now_ts: float) -> bool:
    info = _backoff_get(server_id)
    return float(info.get('next_allowed_at', 0) or 0) > float(now_ts)


def _backoff_record_failure(server_id: int, error: str):
    try:
        sid = int(server_id)
    except Exception:
        return
    now = time.time()
    info = REFRESH_BACKOFF.get(sid) or {'fail_count': 0, 'next_allowed_at': 0, 'last_error': '', 'last_failed_at': 0}
    fail_count = int(info.get('fail_count', 0) or 0) + 1
    # exponential backoff: 5,10,20,40,80,160,300...
    delay = min(REFRESH_MAX_BACKOFF_SEC, (2 ** min(fail_count, 6)) * 5)
    info.update({
        'fail_count': fail_count,
        'next_allowed_at': now + delay,
        'last_error': (error or 'Error')[:400],
        'last_failed_at': now,
    })
    REFRESH_BACKOFF[sid] = info


def _backoff_record_success(server_id: int):
    try:
        sid = int(server_id)
    except Exception:
        return
    if sid in REFRESH_BACKOFF:
        REFRESH_BACKOFF[sid] = {'fail_count': 0, 'next_allowed_at': 0, 'last_error': '', 'last_failed_at': 0}


def _check_server_reachable(server: 'Server', timeout_sec: float = 2.0):
    try:
        base, webpath = extract_base_and_webpath(server.host)
        url = f"{base}{webpath}/login"
        resp = requests.get(url, timeout=timeout_sec, verify=False, allow_redirects=True)
        return (resp.status_code < 500), None
    except Exception as e:
        return False, str(e)


def _update_reachability_status(servers, force: bool = False):
    now_iso = _utc_iso_now()
    now_ts = time.time()
    existing_statuses = GLOBAL_SERVER_DATA.get('servers_status') or []
    status_map = {}
    for st in existing_statuses:
        try:
            if isinstance(st, dict) and 'server_id' in st:
                status_map[int(st.get('server_id'))] = st
        except Exception:
            continue

    for srv in servers or []:
        try:
            sid = int(srv.id)
        except Exception:
            continue
        if not force and _backoff_should_skip(sid, now_ts):
            info = _backoff_get(sid)
            st = status_map.get(sid) or {'server_id': sid}
            st['reachable'] = False
            st['reachable_error'] = f"Backoff (until {int(info.get('next_allowed_at', 0) or 0)})"
            st['reachable_checked_at'] = now_iso
            status_map[sid] = st
            continue

        ok, err = _check_server_reachable(srv)
        st = status_map.get(sid) or {'server_id': sid}
        st['reachable'] = bool(ok)
        st['reachable_error'] = None if ok else (err or 'Unreachable')
        st['reachable_checked_at'] = now_iso
        status_map[sid] = st

        if ok:
            _backoff_record_success(sid)
        else:
            _backoff_record_failure(sid, st['reachable_error'])

    # write back preserving server order (if we can)
    ordered = []
    try:
        id_order = [int(s.id) for s in servers]
        for sid in id_order:
            if sid in status_map:
                ordered.append(status_map[sid])
        # include any extra statuses that were not part of the requested servers
        for sid, st in status_map.items():
            if sid not in set(id_order):
                ordered.append(st)
    except Exception:
        ordered = list(status_map.values())
    GLOBAL_SERVER_DATA['servers_status'] = ordered
    GLOBAL_SERVER_DATA['last_update'] = _utc_iso_now()


def _run_refresh_job(job_id: str):
    with REFRESH_JOBS_LOCK:
        job = REFRESH_JOBS.get(job_id)
        if not job:
            return
        job['state'] = 'running'
        job['started_at'] = _utc_iso_now()

    try:
        # Important: background threads must run inside app context for SQLAlchemy.
        with app.app_context():
            with GLOBAL_REFRESH_LOCK:
                GLOBAL_SERVER_DATA['is_updating'] = True
                try:
                    mode = (job.get('mode') or 'full').strip().lower()
                    server_id = job.get('server_id')
                    force = bool(job.get('force'))

                    if mode == 'status':
                        servers_q = Server.query.filter_by(enabled=True).filter(
                            (Server.hidden == False) | (Server.hidden == None))
                        if server_id:
                            servers_q = servers_q.filter(Server.id == int(server_id))
                        servers = servers_q.all()
                        _update_reachability_status(servers, force=force)
                    else:
                        if server_id:
                            try:
                                fetch_and_update_server_data(int(server_id))
                                _backoff_record_success(int(server_id))
                            except Exception as e:
                                _backoff_record_failure(int(server_id), str(e))
                                raise
                        else:
                            fetch_and_update_global_data(force=force)
                    # Propagate manual-refresh results to other workers (Redis mode).
                    publish_snapshot_to_redis()
                finally:
                    GLOBAL_SERVER_DATA['is_updating'] = False

        with REFRESH_JOBS_LOCK:
            job = REFRESH_JOBS.get(job_id) or {}
            job['state'] = 'done'
            job['finished_at'] = _utc_iso_now()
            REFRESH_JOBS[job_id] = job
            _prune_refresh_jobs_locked()
    except Exception as e:
        with REFRESH_JOBS_LOCK:
            job = REFRESH_JOBS.get(job_id) or {}
            job['state'] = 'error'
            job['error'] = str(e)
            job['finished_at'] = _utc_iso_now()
            REFRESH_JOBS[job_id] = job
            _prune_refresh_jobs_locked()


def enqueue_refresh_job(mode: str = 'full', server_id=None, force: bool = False):
    mode_norm = (mode or 'full').strip().lower()
    if mode_norm not in ('full', 'status'):
        mode_norm = 'full'

    sid = None
    try:
        if server_id not in (None, '', 'null'):
            sid = int(server_id)
    except Exception:
        sid = None

    scope_key = f"{mode_norm}:{sid if sid is not None else 'all'}"
    with REFRESH_JOBS_LOCK:
        for existing in REFRESH_JOBS.values():
            if existing.get('scope_key') == scope_key and existing.get('state') in ('queued', 'running'):
                return existing

        job_id = secrets.token_hex(8)
        job = {
            'id': job_id,
            'scope_key': scope_key,
            'mode': mode_norm,
            'server_id': sid,
            'force': bool(force),
            'state': 'queued',
            'created_at': _utc_iso_now(),
            'created_at_ts': time.time(),
            'started_at': None,
            'finished_at': None,
            'progress': {},
            'error': None,
        }
        REFRESH_JOBS[job_id] = job
        _prune_refresh_jobs_locked()

    t = threading.Thread(target=_run_refresh_job, args=(job_id,), daemon=True)
    t.start()
    return job


def _recompute_global_stats_from_server_statuses(server_statuses):
    """Recompute aggregate stats from cached per-server stats."""
    total_stats = {
        "total_inbounds": 0,
        "active_inbounds": 0,
        "total_clients": 0,
        "online_clients": 0,
        "active_clients": 0,
        "inactive_clients": 0,
        "not_started_clients": 0,
        "unlimited_expiry_clients": 0,
        "unlimited_volume_clients": 0,
        "upload_raw": 0,
        "download_raw": 0,
        "remaining_raw": 0,
        "limited_clients": 0,
    }

    for status in server_statuses or []:
        if not isinstance(status, dict) or not status.get("success"):
            continue
        stats = status.get("stats")
        if not isinstance(stats, dict):
            continue
        for k in list(total_stats.keys()):
            v = stats.get(k, 0)
            if isinstance(v, int):
                total_stats[k] += v

    total_stats["total_upload"] = format_bytes(total_stats["upload_raw"])
    total_stats["total_download"] = format_bytes(total_stats["download_raw"])
    total_stats["total_traffic"] = format_bytes(total_stats["upload_raw"] + total_stats["download_raw"])
    total_stats["total_remaining"] = format_bytes(total_stats["remaining_raw"])
    return total_stats


def fetch_and_update_server_data(server_id: int):
    """Fetch a single server's inbounds and update GLOBAL_SERVER_DATA in-place."""
    server = db.session.get(Server, int(server_id))
    if not server or not server.enabled:
        raise ValueError("Server not found or disabled")
    if server.hidden:
        raise ValueError("Server is hidden — skipping fetch")

    admin_user = Admin.query.filter(or_(Admin.is_superadmin == True, Admin.role == 'superadmin')).first()
    if not admin_user:
        admin_user = SimpleNamespace(role='superadmin', id=0, is_superadmin=True)

    session_obj, error = get_xui_session(server)
    if error:
        raise RuntimeError(error)

    inbounds, fetch_error, detected_type = fetch_inbounds(session_obj, server.host, server.panel_type)
    if fetch_error:
        raise RuntimeError(fetch_error)

    # Onlines = web-UI route needing a cookie login; v3 token session can't reach it.
    onlines_session = session_obj
    if get_server_api_token(server) and getattr(server, 'username', '') and get_server_password(server):
        _cookie = get_xui_cookie_session(
            server.host, server.username, get_server_password(server),
            server.panel_type, cache_key=f"sid:{server.id}")
        if _cookie is not None:
            onlines_session = _cookie
    online_index, _ = fetch_onlines(onlines_session, server.host, server.panel_type)
    status_payload, status_error, _status_type = fetch_server_status(session_obj, server.host, server.panel_type)

    # Enrich status_payload with online_count from onlines endpoint
    if online_index:
        online_count = len(online_index.get('pairs', set())) + len(online_index.get('emails', set()))
        if status_payload is None:
            status_payload = {}
        if status_payload.get('online_count') is None and online_count > 0:
            status_payload['online_count'] = online_count

    if persist_detected_panel_type(server, detected_type):
        app.logger.info(f"Detected panel type for server {server.id} as {detected_type}")

    if not isinstance(inbounds, list):
        inbounds = []
    processed, stats = process_inbounds(inbounds, server, admin_user, '*', {}, online_index=online_index)

    # Update cache atomically under lock
    # - Replace only this server's inbounds
    # - Preserve the previous ordering position (do NOT move the server's block to the end)
    # - Update per-server status stats
    # - Recompute aggregate stats
    existing_inbounds = GLOBAL_SERVER_DATA.get('inbounds') or []
    new_block = list(processed or [])

    # Find the first occurrence index of this server in the existing list (if any)
    first_idx = None
    for idx, item in enumerate(existing_inbounds):
        try:
            if int(item.get('server_id', -1)) == int(server.id):
                first_idx = idx
                break
        except Exception:
            continue

    without_server = []
    for item in existing_inbounds:
        try:
            if int(item.get('server_id', -1)) == int(server.id):
                continue
        except Exception:
            pass
        without_server.append(item)

    if first_idx is None:
        # Server didn't exist in cache before: append to end
        GLOBAL_SERVER_DATA['inbounds'] = without_server + new_block
    else:
        # Insert new block at the previous position
        insert_at = min(max(first_idx, 0), len(without_server))
        GLOBAL_SERVER_DATA['inbounds'] = without_server[:insert_at] + new_block + without_server[insert_at:]

    statuses = GLOBAL_SERVER_DATA.get('servers_status') or []
    updated = False
    for st in statuses:
        if isinstance(st, dict) and int(st.get('server_id', -1)) == int(server.id):
            status_payload = status_payload or {}
            st.update({
                "server_id": server.id,
                "success": True,
                "stats": stats,
                "panel_type": server.panel_type,
                "xui_version": status_payload.get('xui_version'),
                "xray_version": status_payload.get('xray_version'),
                "xray_state": status_payload.get('xray_state'),
                "xray_core": status_payload.get('xray_core'),
                "online_count": status_payload.get('online_count'),
                "panel_status_error": status_error if status_error else None,
                "panel_status_checked_at": datetime.utcnow().isoformat()
            })
            updated = True
            break
    if not updated:
        status_payload = status_payload or {}
        statuses.append({
            "server_id": server.id,
            "success": True,
            "stats": stats,
            "panel_type": server.panel_type,
            "xui_version": status_payload.get('xui_version'),
            "xray_version": status_payload.get('xray_version'),
            "xray_state": status_payload.get('xray_state'),
            "xray_core": status_payload.get('xray_core'),
            "online_count": status_payload.get('online_count'),
            "panel_status_error": status_error if status_error else None,
            "panel_status_checked_at": datetime.utcnow().isoformat()
        })
    GLOBAL_SERVER_DATA['servers_status'] = statuses

    GLOBAL_SERVER_DATA['stats'] = _recompute_global_stats_from_server_statuses(statuses)
    GLOBAL_SERVER_DATA['last_update'] = datetime.utcnow().isoformat()


# ── Write-through cache ──────────────────────────────────────────────────────
# After any successful panel write we mutate GLOBAL_SERVER_DATA directly (and
# republish to Redis) so the dashboard reflects the change INSTANTLY without the
# slow per-server panel re-fetch. The background fetcher reconciles on its next
# cycle, so any small drift here is self-healing.

def _recompute_cached_client(cd, thresholds=None, lang=None):
    """Recompute a processed client's derived display fields from its raw_client.
    Mirrors process_inbounds() so a patched row matches a full fetch."""
    raw = cd.get('raw_client') or {}
    if thresholds is None:
        thresholds = _get_dashboard_status_thresholds()
    if lang is None:
        lang = _get_panel_ui_lang()
    up = int(cd.get('up') or 0)
    down = int(cd.get('down') or 0)
    try:
        total_bytes = int(raw.get('totalGB') or 0)
    except (TypeError, ValueError):
        total_bytes = 0

    cd['totalGB'] = total_bytes
    cd['totalGB_formatted'] = format_bytes_gb_tb(total_bytes) if total_bytes > 0 else "Unlimited"

    if total_bytes > 0:
        remaining_bytes = max(total_bytes - (up + down), 0)
        rf = format_bytes_gb_tb(remaining_bytes)
        vs = ""
        if remaining_bytes <= 0:
            rf, vs = "Suspended", "suspended"
        elif remaining_bytes < int(float(thresholds.get('low_volume_gb', 1.0)) * (1024 ** 3)):
            rf, vs = f"{rf} Low", "low"
        cd['remaining_bytes'] = remaining_bytes
        cd['remaining_formatted'] = rf
        cd['volume_status'] = vs
    else:
        remaining_bytes = None
        cd['remaining_bytes'] = -1
        cd['remaining_formatted'] = "Unlimited"
        cd['volume_status'] = "expiry-start-after"

    expiry_raw = raw.get('expiryTime', 0)
    expiry_info = format_remaining_days(expiry_raw, lang=lang)
    cd['expiryTime'] = expiry_info['text']
    cd['expiryTimestamp'] = expiry_raw
    cd['expiryType'] = expiry_info['type']

    try:
        state = _compute_client_service_state(
            enabled=bool(raw.get('enable', True)),
            total_bytes=int(total_bytes or 0),
            remaining_bytes=(None if remaining_bytes is None else int(remaining_bytes)),
            expiry_ts=int(expiry_raw or 0),
            expiry_info=expiry_info,
            thresholds=thresholds,
            lang=lang,
        )
        cd['service_state'] = state.get('key', 'active')
        cd['service_state_label'] = state.get('label', '')
        cd['service_state_emoji'] = state.get('emoji', '')
        cd['service_state_tag'] = state.get('tag', 'ok')
    except Exception:
        pass

    cd['enable'] = bool(raw.get('enable', True))
    cd['comment'] = (raw.get('comment') or '').strip()
    cd['email'] = raw.get('email', cd.get('email'))
    cd['id'] = raw.get('id', cd.get('id'))


def _iter_cached_client_copies(server_id, email, client_uuid=None):
    """Yield (inbound, processed_client) for every cached copy of a client on a
    server (a v3 client appears once per assigned inbound)."""
    try:
        sid = int(server_id)
    except (TypeError, ValueError):
        return
    email_l = (email or '').strip().lower()
    uuid_l = (client_uuid or '').strip().lower()
    for ib in (GLOBAL_SERVER_DATA.get('inbounds') or []):
        try:
            if int(ib.get('server_id', -1)) != sid:
                continue
        except Exception:
            continue
        for cd in (ib.get('clients') or []):
            ce = (cd.get('email') or '').strip().lower()
            cu = (cd.get('id') or '').strip().lower()
            if (email_l and ce == email_l) or (uuid_l and cu == uuid_l):
                yield ib, cd


def patch_cached_client(server_id, email, *, client_uuid=None, new_email=None,
                        comment=None, total_gb_bytes=None, expiry_ts=None,
                        enable=None, up=None, down=None, publish=True):
    """Write-through: update every cached copy of a client after a panel write."""
    changed = False
    try:
        with GLOBAL_REFRESH_LOCK:
            thresholds = _get_dashboard_status_thresholds()
            lang = _get_panel_ui_lang()
            for _ib, cd in _iter_cached_client_copies(server_id, email, client_uuid):
                raw = cd.get('raw_client')
                if not isinstance(raw, dict):
                    raw = {}
                    cd['raw_client'] = raw
                if comment is not None:
                    raw['comment'] = comment
                if total_gb_bytes is not None:
                    raw['totalGB'] = int(total_gb_bytes)
                if expiry_ts is not None:
                    raw['expiryTime'] = int(expiry_ts)
                if enable is not None:
                    raw['enable'] = bool(enable)
                if new_email is not None:
                    raw['email'] = new_email
                if up is not None:
                    cd['up'] = int(up)
                    cd['up_formatted'] = format_bytes(int(up))
                if down is not None:
                    cd['down'] = int(down)
                    cd['down_formatted'] = format_bytes(int(down))
                _recompute_cached_client(cd, thresholds, lang)
                changed = True
            if changed:
                GLOBAL_SERVER_DATA['last_update'] = datetime.utcnow().isoformat()
    except Exception as exc:
        app.logger.debug(f"patch_cached_client failed: {exc}")
        return False
    if changed and publish:
        try:
            publish_snapshot_to_redis()
        except Exception:
            pass
    return changed


def remove_cached_client(server_id, email, *, client_uuid=None, inbound_id=None, publish=True):
    """Write-through: drop a client from cache (all inbounds, or just one)."""
    removed = False
    try:
        with GLOBAL_REFRESH_LOCK:
            try:
                sid = int(server_id)
            except (TypeError, ValueError):
                return False
            email_l = (email or '').strip().lower()
            uuid_l = (client_uuid or '').strip().lower()
            for ib in (GLOBAL_SERVER_DATA.get('inbounds') or []):
                try:
                    if int(ib.get('server_id', -1)) != sid:
                        continue
                except Exception:
                    continue
                if inbound_id is not None:
                    try:
                        if int(ib.get('id', -1)) != int(inbound_id):
                            continue
                    except Exception:
                        continue
                clients = ib.get('clients') or []
                kept = []
                for cd in clients:
                    ce = (cd.get('email') or '').strip().lower()
                    cu = (cd.get('id') or '').strip().lower()
                    if (email_l and ce == email_l) or (uuid_l and cu == uuid_l):
                        removed = True
                        continue
                    kept.append(cd)
                if len(kept) != len(clients):
                    ib['clients'] = kept
            if removed:
                GLOBAL_SERVER_DATA['last_update'] = datetime.utcnow().isoformat()
    except Exception as exc:
        app.logger.debug(f"remove_cached_client failed: {exc}")
        return False
    if removed and publish:
        try:
            publish_snapshot_to_redis()
        except Exception:
            pass
    return removed


def clone_cached_client_into_inbound(server_id, inbound_id, email, client_uuid=None, publish=True):
    """Clone an existing cached processed client into another inbound block on the
    same server (used when a v3 client is newly assigned to an inbound)."""
    done = False
    try:
        with GLOBAL_REFRESH_LOCK:
            try:
                sid = int(server_id)
                iid = int(inbound_id)
            except (TypeError, ValueError):
                return False
            email_l = (email or '').strip().lower()
            uuid_l = (client_uuid or '').strip().lower()
            source = None
            target_ib = None
            for ib in (GLOBAL_SERVER_DATA.get('inbounds') or []):
                try:
                    if int(ib.get('server_id', -1)) != sid:
                        continue
                except Exception:
                    continue
                try:
                    if int(ib.get('id', -1)) == iid:
                        target_ib = ib
                except Exception:
                    pass
                if source is None:
                    for cd in (ib.get('clients') or []):
                        ce = (cd.get('email') or '').strip().lower()
                        cu = (cd.get('id') or '').strip().lower()
                        if (email_l and ce == email_l) or (uuid_l and cu == uuid_l):
                            source = cd
                            break
            if target_ib is None or source is None:
                return False
            tgt_email = (source.get('email') or '').strip().lower()
            for cd in (target_ib.get('clients') or []):
                if (cd.get('email') or '').strip().lower() == tgt_email:
                    return False  # already present
            clone = copy.deepcopy(source)
            clone['inbound_id'] = iid
            target_ib.setdefault('clients', []).append(clone)
            GLOBAL_SERVER_DATA['last_update'] = datetime.utcnow().isoformat()
            done = True
    except Exception as exc:
        app.logger.debug(f"clone_cached_client_into_inbound failed: {exc}")
        return False
    if done and publish:
        try:
            publish_snapshot_to_redis()
        except Exception:
            pass
    return done


# Guard to avoid starting background threads multiple times (important for gunicorn workers / dev reload)
BACKGROUND_THREADS_STARTED = False

SERVER_PASSWORD_PREFIX = 'enc:'
_SERVER_PASSWORD_FERNET = None
_SERVER_PASSWORD_MIGRATION_DONE = False
_SERVER_PASSWORD_MIGRATION_LOCK = threading.Lock()


def _is_dev_mode() -> bool:
    
    env = (os.environ.get('FLASK_ENV') or os.environ.get('ENV') or '').strip().lower()
    debug = (os.environ.get('DEBUG') or '').strip().lower() in ('1', 'true', 'yes', 'on')
    return debug or env in ('development', 'dev')


def _get_server_password_fernet() -> Any:
    """Return cached Fernet instance from SERVER_PASSWORD_KEY.

    SERVER_PASSWORD_KEY must be a URL-safe base64-encoded 32-byte key.
    """
    global _SERVER_PASSWORD_FERNET
    if _SERVER_PASSWORD_FERNET is not None:
        return _SERVER_PASSWORD_FERNET

    key = (os.environ.get('SERVER_PASSWORD_KEY') or '').strip()
    if not key:
        return None

    try:
        _SERVER_PASSWORD_FERNET = Fernet(key)
        return _SERVER_PASSWORD_FERNET
    except Exception:
        # Invalid key format. Log warning and return None to fallback to plaintext.
        app.logger.warning("Invalid SERVER_PASSWORD_KEY (must be Fernet key). Encryption/Decryption disabled.")
        return None


def encrypt_server_password(plaintext: str) -> str:
    f = _get_server_password_fernet()
    if not f:
        # If no key is configured, we store as plaintext (legacy behavior)
        return plaintext
    plain = str(plaintext or '')
    token = f.encrypt(plain.encode('utf-8')).decode('utf-8')
    return f'{SERVER_PASSWORD_PREFIX}{token}'


def decrypt_server_password(value: str) -> str:
    raw = str(value or '')
    if not raw:
        return ''
    if not raw.startswith(SERVER_PASSWORD_PREFIX):
        return raw

    f = _get_server_password_fernet()
    if not f:
        # If no key is configured, we can't decrypt. 
        # Return raw value as fallback (might be plaintext from legacy)
        return raw

    token = raw[len(SERVER_PASSWORD_PREFIX):]
    try:
        return f.decrypt(token.encode('utf-8')).decode('utf-8')
    except InvalidToken:
        # Decryption failed (e.g. key changed or data corrupted).
        # We log a warning instead of raising RuntimeError to avoid crashing background tasks.
        app.logger.warning("Failed to decrypt a stored server password (invalid key/token). Returning empty string.")
        return ""


def get_server_password(server: 'Server') -> str:
    return decrypt_server_password(getattr(server, 'password', '') or '')


def _maybe_migrate_server_passwords() -> None:
    """Encrypt any legacy plaintext Server.password values once (best-effort).

    Runs only when SERVER_PASSWORD_KEY is configured.
    """
    global _SERVER_PASSWORD_MIGRATION_DONE
    if _SERVER_PASSWORD_MIGRATION_DONE:
        return

    f = _get_server_password_fernet()
    if not f:
        return

    with _SERVER_PASSWORD_MIGRATION_LOCK:
        if _SERVER_PASSWORD_MIGRATION_DONE:
            return

        try:
            inspector = inspect(db.engine)
            if 'servers' not in inspector.get_table_names():
                _SERVER_PASSWORD_MIGRATION_DONE = True
                return
        except Exception:
            # DB not ready yet
            return

        try:
            servers = Server.query.all()
            changed = False
            for s in servers:
                try:
                    cur = (s.password or '').strip()
                    if not cur or cur.startswith(SERVER_PASSWORD_PREFIX):
                        continue
                    s.password = encrypt_server_password(cur)
                    changed = True
                except Exception:
                    continue
            if changed:
                db.session.commit()
            _SERVER_PASSWORD_MIGRATION_DONE = True
        except Exception:
            try:
                db.session.rollback()
            except Exception:
                pass


def _security_per_request_setup():
    # CSP nonce for inline <script> blocks that cannot be moved yet.
    # Keep stable per request.
    g.csp_nonce = secrets.token_urlsafe(16)
    _maybe_migrate_server_passwords()

app = Flask(__name__)
# Trust one proxy hop (nginx SSL termination) so Flask sees correct scheme/host
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Register per-request security setup.
app.before_request(_security_per_request_setup)


@app.context_processor
def inject_csp_nonce():
    return {'csp_nonce': getattr(g, 'csp_nonce', '')}

_session_secret = (os.environ.get('SESSION_SECRET') or '').strip()
if not _session_secret:
    if _is_dev_mode():
        # Dev convenience: use a random secret so session forgery isn't trivial.
        # Sessions will reset on restart.
        app.secret_key = secrets.token_urlsafe(32)
        try:
            app.logger.warning('SESSION_SECRET not set; using random dev secret (sessions reset on restart).')
        except Exception:
            pass
    else:
        raise RuntimeError('SESSION_SECRET is required in production (no default fallback).')
else:
    app.secret_key = _session_secret

# Require server password encryption key in production.
if not _is_dev_mode():
    if not (_get_server_password_fernet()):
        raise RuntimeError('SERVER_PASSWORD_KEY is required in production to encrypt stored server passwords.')

# Use SQLite by default, but allow override via DATABASE_URL
db_url = os.environ.get("DATABASE_URL")
if db_url:
    db_url = str(db_url).strip()
    # Heroku-style scheme; SQLAlchemy expects postgresql://
    if db_url.startswith("postgres://"):
        db_url = "postgresql://" + db_url[len("postgres://"):]
else:
    db_path = os.path.join(app.instance_path, 'servers.db')
    os.makedirs(app.instance_path, exist_ok=True)
    db_url = f"sqlite:///{db_path}"

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 2048 * 1024 * 1024  # 2 GB — covers large migration bundles / installers / videos
# Re-read templates from disk on each render in dev so UI edits show without a
# full restart. Harmless in prod; production still benefits from a restart.
if _is_dev_mode():
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.jinja_env.auto_reload = True


@app.errorhandler(413)
def request_entity_too_large(e):
    return jsonify({'success': False, 'error': 'File too large. Maximum allowed size is 512 MB.'}), 413


def _want_json() -> bool:
    """True when the caller expects a JSON response (API path or Accept: application/json)."""
    return (
        request.path.startswith('/api/')
        or 'application/json' in (request.headers.get('Accept') or '')
        or request.is_json
    )


@app.errorhandler(404)
def not_found(e):
    if _want_json():
        return jsonify({'success': False, 'error': f'Not found: {request.path}'}), 404
    return e


@app.errorhandler(405)
def method_not_allowed(e):
    if _want_json():
        return jsonify({'success': False, 'error': f'Method not allowed: {request.method} {request.path}'}), 405
    return e


@app.errorhandler(500)
def internal_server_error(e):
    if _want_json():
        return jsonify({'success': False, 'error': f'Internal server error: {e}'}), 500
    return e


@app.after_request
def add_security_headers(response):
    # Baseline security headers (kept permissive to avoid breaking current inline scripts/styles)
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('Referrer-Policy', 'same-origin')
    response.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')

    nonce = getattr(g, 'csp_nonce', None) or ''
    
    # Debug endpoint
    # print(f"DEBUG: endpoint={getattr(request, 'endpoint', '')}", flush=True)

    # All assets are local by default. Subscription page can optionally allow external
    # online-chat widget domains when an active chat script is configured.
    allow_external_chat = bool(getattr(g, 'allow_external_chat_widget', False))
    script_src_extra = " https:" if allow_external_chat else ""
    connect_src_extra = " https: wss:" if allow_external_chat else ""
    frame_src_part = "frame-src 'self' https:; " if allow_external_chat else ""

    style_src = f"style-src 'self' 'nonce-{nonce}'; "
    response.headers.setdefault(
        'Content-Security-Policy',
        (
            "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'self'; "
            "img-src 'self' data:; "
            "font-src 'self' data:; "
            f"{frame_src_part}"
            f"{style_src}"
            "style-src-attr 'unsafe-inline'; "
            f"script-src 'self' 'nonce-{nonce}'{script_src_extra}; "
            "script-src-attr 'unsafe-inline'; "
            f"connect-src 'self'{connect_src_extra}"
        )
    )
    return response
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_recycle': 1800,
    'pool_pre_ping': True,
    'pool_size': 15,
    'max_overflow': 5,
    'pool_timeout': 10,
}
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE=(os.environ.get('SESSION_COOKIE_SAMESITE') or ('Lax' if _is_dev_mode() else 'Strict')),
    SESSION_COOKIE_SECURE=((os.environ.get('SESSION_COOKIE_SECURE') or '').strip().lower() in ('1', 'true', 'yes', 'on'))
    if (os.environ.get('SESSION_COOKIE_SECURE') is not None)
    else False
)

RECEIPT_ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp', 'heic', 'heif', 'pdf'}
RECEIPTS_DIR = os.path.join(app.instance_path, 'receipts')
os.makedirs(RECEIPTS_DIR, exist_ok=True)

BACKUP_DIR = os.path.join(app.instance_path, 'backups')
os.makedirs(BACKUP_DIR, exist_ok=True)

TELEGRAM_BACKUP_TMP_DIR = os.path.join(app.instance_path, 'telegram_backup_tmp')
os.makedirs(TELEGRAM_BACKUP_TMP_DIR, exist_ok=True)
TELEGRAM_BACKUP_LOCK = threading.Lock()


def _db_uri() -> str:
    return (app.config.get('SQLALCHEMY_DATABASE_URI') or '').strip()


def _is_sqlite_db() -> bool:
    return _db_uri().startswith('sqlite:')


def _is_postgres_db() -> bool:
    return _db_uri().startswith('postgresql:')


# Heavy analytics/log tables whose ROW DATA is excluded from "clean" backups.
# Schema is preserved; the data regenerates on its own after a restore.
_ANALYTICS_EXCLUDE_TABLES = ('usage_snapshots', 'health_logs')


def _pg_dump_backup(dest_path: str, exclude_analytics: bool = True) -> None:
    """Create a PostgreSQL backup using pg_dump (custom format).

    Requires `pg_dump` to be available in PATH on the server.
    """
    pg_dump_bin = shutil.which('pg_dump')
    if not pg_dump_bin:
        raise RuntimeError("pg_dump not found in PATH. Install postgresql-client (pg_dump) on the server.")

    uri = _db_uri()
    parsed = urlparse(uri)

    env = os.environ.copy()
    if parsed.password:
        env['PGPASSWORD'] = parsed.password

    # Custom format is compact and best for pg_restore.
    cmd = [
        pg_dump_bin,
        '--format=custom',
        '--compress=9',
        '--no-owner',
        '--no-privileges',
    ]
    # Keep the schema for analytics tables but drop their (huge) row data so the
    # backup stays small and "clean". They regenerate automatically after restore.
    if exclude_analytics:
        for _t in _ANALYTICS_EXCLUDE_TABLES:
            cmd += ['--exclude-table-data', _t]
    cmd += ['--file', dest_path, '--dbname', uri]
    result = subprocess.run(cmd, env=env, timeout=600)
    if result.returncode != 0:
        raise RuntimeError(f"pg_dump exited with code {result.returncode}")


def _pg_restore_jobs() -> int:
    """Number of parallel pg_restore workers — half of CPUs, min 1, max 8."""
    cpus = os.cpu_count() or 1
    return max(1, min(cpus, 8))


def _pg_env_from_uri(uri: str) -> dict:
    parsed = urlparse(uri)
    env = os.environ.copy()
    if parsed.password:
        env['PGPASSWORD'] = parsed.password
    return env


def _pg_reset_public_schema(uri: str, env: dict) -> None:
    psql_bin = shutil.which('psql')
    if not psql_bin:
        raise RuntimeError("psql not found in PATH. Install postgresql-client (psql) on the server.")

    db.session.remove()
    db.engine.dispose()
    cmd = [
        psql_bin,
        '--dbname', uri,
        '--set', 'ON_ERROR_STOP=1',
        '--command', 'DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;'
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=600)
    if result.returncode != 0:
        err = (result.stderr or result.stdout or 'Unknown error')[:1000].strip()
        raise RuntimeError(f"PostgreSQL schema reset failed (exit {result.returncode}): {err}")


def _pg_restore_backup(backup_path: str) -> None:
    """Restore a PostgreSQL database from a pg_dump file.

    Supports:
    - .dump  (pg_dump --format=custom)  → pg_restore --jobs=N (parallel)
    - .sql   (pg_dump --format=plain)   → psql
    Requires postgresql-client tools (pg_restore / psql) on the server.
    """
    uri = _db_uri()
    env = _pg_env_from_uri(uri)

    ext = os.path.splitext(backup_path)[1].lower()

    if ext == '.dump':
        bin_ = shutil.which('pg_restore')
        if not bin_:
            raise RuntimeError(
                "pg_restore not found in PATH. "
                "Install postgresql-client:  apt install postgresql-client"
            )
        jobs = _pg_restore_jobs()
        cmd = [
            bin_,
            '--no-owner', '--no-acl',
            f'--jobs={jobs}',
            '--dbname', uri,
            backup_path,
        ]
    elif ext == '.sql':
        bin_ = shutil.which('psql')
        if not bin_:
            raise RuntimeError(
                "psql not found in PATH. "
                "Install postgresql-client:  apt install postgresql-client"
            )
        cmd = [bin_, '--dbname', uri, '--file', backup_path]
    else:
        raise ValueError(f"Unsupported backup format for PostgreSQL restore: {ext!r}")

    _pg_reset_public_schema(uri, env)
    result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=600)
    if result.returncode != 0:
        err = (result.stderr or result.stdout or 'Unknown error')[:1000].strip()
        raise RuntimeError(f"Restore failed (exit {result.returncode}): {err}")


def _create_database_backup_file(prefix: str, exclude_analytics: bool = True) -> str:
    """Create a DB backup in BACKUP_DIR and return filename.

    exclude_analytics=True (default) drops the huge usage_snapshots / health_logs
    row data so backups stay small; the schema is kept and data regenerates.
    """
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    if _is_sqlite_db():
        db_path = os.path.join(app.instance_path, 'servers.db')
        if not os.path.exists(db_path):
            raise FileNotFoundError('Database file not found')

        filename = f'{prefix}_{timestamp}.db'
        dest = os.path.join(BACKUP_DIR, filename)
        shutil.copy2(db_path, dest)
        # Clean copy: drop the heavy analytics rows and reclaim space (VACUUM)
        if exclude_analytics:
            try:
                con = sqlite3.connect(dest)
                for _t in _ANALYTICS_EXCLUDE_TABLES:
                    try:
                        con.execute(f'DELETE FROM {_t}')
                    except Exception:
                        pass
                con.commit()
                con.execute('VACUUM')
                con.commit()
                con.close()
            except Exception:
                pass
        return filename

    if _is_postgres_db():
        filename = f'{prefix}_{timestamp}.dump'
        dest = os.path.join(BACKUP_DIR, filename)
        _pg_dump_backup(dest, exclude_analytics=exclude_analytics)
        return filename

    raise RuntimeError('Unsupported database backend for backup')


# Directories that hold user-uploaded files which must travel WITH the database
# in a full migration (the DB only stores their URLs/paths, not the bytes).
def _migration_file_dirs() -> dict:
    """Map of archive-folder-name → absolute source dir for migration bundles."""
    static_folder = app.static_folder or ''
    return {
        'static_uploads':   os.path.join(static_folder, 'uploads'),       # receipts/images uploaded via editor
        'static_app_files': os.path.join(static_folder, _APP_FILES_DIR_NAME),  # app icons / screenshots / tutorial files
        'instance_receipts': RECEIPTS_DIR,                                # manual payment receipts
    }


def _create_full_migration_zip(prefix: str = 'migration') -> str:
    """Create a COMPLETE migration bundle (.zip) in BACKUP_DIR and return filename.

    Contains everything needed to move to another server:
      - database/<db>      the DB dump (.db for SQLite, .dump for PostgreSQL)
      - static_uploads/    uploaded images/receipts
      - static_app_files/  app icons, screenshots, tutorial files
      - instance_receipts/ manual payment receipts
      - manifest.json      metadata (db type, version, created at)
    """
    import zipfile
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    # 1) Produce the DB dump first (reuses the existing logic)
    db_filename = _create_database_backup_file(f'{prefix}_db')
    db_path = os.path.join(BACKUP_DIR, db_filename)
    db_arcname = f"database/{db_filename}"

    zip_filename = f"{prefix}_full_{timestamp}.zip"
    zip_path = os.path.join(BACKUP_DIR, zip_filename)

    manifest = {
        'kind': 'eve_full_migration',
        'version': APP_VERSION,
        'created_at': datetime.now().isoformat(),
        'db_type': 'postgresql' if _is_postgres_db() else 'sqlite',
        'db_file': db_arcname,
        'included_dirs': [],
    }

    try:
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
            # DB
            zf.write(db_path, db_arcname)
            # File directories
            for arc_root, src_dir in _migration_file_dirs().items():
                if not src_dir or not os.path.isdir(src_dir):
                    continue
                file_count = 0
                for root, _dirs, files in os.walk(src_dir):
                    for fname in files:
                        fpath = os.path.join(root, fname)
                        rel = os.path.relpath(fpath, src_dir)
                        zf.write(fpath, f"{arc_root}/{rel}")
                        file_count += 1
                if file_count:
                    manifest['included_dirs'].append({'dir': arc_root, 'files': file_count})
            # Manifest
            zf.writestr('manifest.json', json.dumps(manifest, ensure_ascii=False, indent=2))
    finally:
        # Remove the standalone DB dump (it's now inside the zip)
        try:
            os.remove(db_path)
        except Exception:
            pass

    return zip_filename


def _restore_full_migration_zip(zip_path: str, log=None):
    """Restore a full migration bundle: DB + uploaded file directories.

    `log` is an optional callable(str) for progress messages.
    Returns the db archive member path that was extracted+restored.
    """
    import zipfile, tempfile
    def _say(m):
        if log:
            try: log(m)
            except Exception: pass

    with zipfile.ZipFile(zip_path, 'r') as zf:
        names = zf.namelist()
        # locate the DB file inside database/
        db_member = next((n for n in names if n.startswith('database/') and not n.endswith('/')), None)
        if not db_member:
            raise RuntimeError('Bundle has no database/ file')

        tmp_dir = tempfile.mkdtemp(prefix='eve-migrate-')
        try:
            # 1) Restore the database
            db_ext = os.path.splitext(db_member)[1].lower()
            extracted_db = zf.extract(db_member, tmp_dir)
            _say(f'Database file: {os.path.basename(db_member)}')

            if _is_sqlite_db():
                if db_ext != '.db':
                    raise RuntimeError(f'This server is SQLite but bundle DB is {db_ext}')
                db_path = os.path.join(app.instance_path, 'servers.db')
                if os.path.exists(db_path):
                    shutil.copy2(db_path, os.path.join(BACKUP_DIR, f'pre_restore_{datetime.now():%Y%m%d_%H%M%S}.db'))
                shutil.copy2(extracted_db, db_path)
                _say('✓ SQLite database restored')
            elif _is_postgres_db():
                if db_ext not in ('.dump', '.sql'):
                    raise RuntimeError(f'This server is PostgreSQL but bundle DB is {db_ext}')
                uri = _db_uri()
                env = _pg_env_from_uri(uri)
                _pg_reset_public_schema(uri, env)
                if db_ext == '.dump':
                    bin_ = shutil.which('pg_restore')
                    subprocess.run([bin_, '--no-owner', '--no-acl', f'--jobs={_pg_restore_jobs()}',
                                    '--dbname', uri, extracted_db], env=env, check=False,
                                   capture_output=True, text=True)
                else:
                    bin_ = shutil.which('psql')
                    subprocess.run([bin_, '--dbname', uri, '--file', extracted_db],
                                   env=env, check=False, capture_output=True, text=True)
                _say('✓ PostgreSQL database restored')
            else:
                raise RuntimeError('Unsupported database backend')

            # 2) Restore the uploaded file directories
            dir_map = _migration_file_dirs()
            for arc_root, dest_dir in dir_map.items():
                members = [n for n in names if n.startswith(arc_root + '/') and not n.endswith('/')]
                if not members:
                    continue
                os.makedirs(dest_dir, exist_ok=True)
                restored = 0
                for n in members:
                    rel = n[len(arc_root) + 1:]
                    target = os.path.join(dest_dir, rel)
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    with zf.open(n) as src, open(target, 'wb') as out:
                        shutil.copyfileobj(src, out)
                    restored += 1
                _say(f'✓ Restored {restored} file(s) → {arc_root}')
        finally:
            try:
                shutil.rmtree(tmp_dir)
            except Exception:
                pass


TELEGRAM_BACKUP_DEFAULT_INTERVAL_MINUTES = 60
TELEGRAM_BACKUP_MAX_INTERVAL_MINUTES = 1440


def _get_system_setting_value(key: str, default: str | None = None) -> str | None:
    setting = db.session.get(SystemSetting, key)
    return setting.value if setting else default


def _set_system_setting_value(key: str, value: str | int | bool | None):
    setting = db.session.get(SystemSetting, key)
    if not setting:
        setting = SystemSetting(key=key, value=str(value) if value is not None else '')
        db.session.add(setting)
    else:
        setting.value = str(value) if value is not None else ''
    return setting


def _parse_int(value, default: int, min_value: int | None = None, max_value: int | None = None) -> int:
    try:
        val = int(value)
    except Exception:
        val = default
    if min_value is not None and val < min_value:
        val = min_value
    if max_value is not None and val > max_value:
        val = max_value
    return val


def _parse_iso_datetime(value: str | None):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except Exception:
        return None


def _normalize_proxy_url(raw: str | None) -> str:
    val = (raw or '').strip()
    if not val:
        return ''
    if '://' in val:
        return val
    return f"socks5h://{val}"


def _get_telegram_backup_settings() -> dict:
    enabled = _parse_bool(_get_system_setting_value('telegram_backup_enabled', 'false'))
    send_panel_backup = _parse_bool(_get_system_setting_value('telegram_backup_send_panel_backup', 'false'))
    interval = _parse_int(
        _get_system_setting_value('telegram_backup_interval_minutes', str(TELEGRAM_BACKUP_DEFAULT_INTERVAL_MINUTES)),
        TELEGRAM_BACKUP_DEFAULT_INTERVAL_MINUTES,
        min_value=1,
        max_value=TELEGRAM_BACKUP_MAX_INTERVAL_MINUTES
    )
    use_proxy = _parse_bool(_get_system_setting_value('telegram_backup_use_proxy', 'false'))
    proxy_mode = (_get_system_setting_value('telegram_backup_proxy_mode', 'url') or 'url').strip().lower()
    if proxy_mode not in ('url', 'hostport'):
        proxy_mode = 'url'
    proxy_url = _normalize_proxy_url(_get_system_setting_value('telegram_backup_proxy_url', '') or '')
    proxy_host = (_get_system_setting_value('telegram_backup_proxy_host', '') or '').strip()
    proxy_port = _parse_int(_get_system_setting_value('telegram_backup_proxy_port', ''), 0, min_value=0, max_value=65535)
    proxy_username = (_get_system_setting_value('telegram_backup_proxy_username', '') or '').strip()
    proxy_password = (_get_system_setting_value('telegram_backup_proxy_password', '') or '').strip()
    last_run = _get_system_setting_value('telegram_backup_last_run', '') or ''
    last_dt = _parse_iso_datetime(last_run)
    schedule_mode = (_get_system_setting_value('telegram_backup_schedule_mode', 'interval') or 'interval').strip().lower()
    if schedule_mode not in ('interval', 'daily'):
        schedule_mode = 'interval'
    daily_time = (_get_system_setting_value('telegram_backup_daily_time', '00:00') or '00:00').strip()
    return {
        'enabled': enabled,
        'send_panel_backup': send_panel_backup,
        'schedule_mode': schedule_mode,
        'daily_time': daily_time,
        'interval_minutes': interval,
        'bot_token': _get_system_setting_value('telegram_backup_bot_token', '') or '',
        'chat_id': _get_system_setting_value('telegram_backup_chat_id', '') or '',
        'use_proxy': use_proxy,
        'proxy_mode': proxy_mode,
        'proxy_url': proxy_url,
        'proxy_host': proxy_host,
        'proxy_port': proxy_port,
        'proxy_username': proxy_username,
        'proxy_password': proxy_password,
        'last_run': last_run,
        'last_run_jalali': format_jalali(last_dt) if last_dt else ''
    }


def _inject_proxy_credentials(proxy_url: str, username: str, password: str) -> str:
    if not proxy_url:
        return proxy_url
    if not username and not password:
        return proxy_url

    try:
        parsed = urlparse(proxy_url)
    except Exception:
        return proxy_url

    if parsed.username or parsed.password:
        return proxy_url

    netloc = parsed.netloc or ''
    if '@' in netloc:
        return proxy_url

    user_part = quote(username or '', safe='')
    pass_part = quote(password or '', safe='')
    if pass_part:
        creds = f"{user_part}:{pass_part}"
    else:
        creds = user_part

    updated = parsed._replace(netloc=f"{creds}@{netloc}")
    return updated.geturl()


def _build_telegram_proxies(use_proxy: bool, proxy_mode: str, proxy_url: str, proxy_host: str, proxy_port: int,
                            proxy_username: str, proxy_password: str) -> dict | None:
    if not use_proxy:
        return None

    mode = (proxy_mode or 'url').strip().lower()
    if mode == 'hostport':
        if not proxy_host or not proxy_port:
            return None
        normalized = _normalize_proxy_url(f"{proxy_host}:{proxy_port}")
        # Always inject credentials in hostport mode
        normalized = _inject_proxy_credentials(normalized, proxy_username, proxy_password)
    else:
        normalized = _normalize_proxy_url(proxy_url)
        # Only inject credentials if URL doesn't already have them
        if normalized and '@' not in normalized:
            normalized = _inject_proxy_credentials(normalized, proxy_username, proxy_password)

    if not normalized:
        return None

    return {'http': normalized, 'https': normalized}


def _check_proxy_reachable(proxies: dict | None, timeout_sec: float = 5) -> tuple[bool, str | None]:
    if not proxies:
        return True, None
    url = proxies.get('https') or proxies.get('http') or ''
    if not url:
        return True, None
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port
        if not host or not port:
            return True, None
        with socket.create_connection((host, port), timeout=timeout_sec):
            pass
        return True, None
    except OSError as exc:
        return False, f"Proxy unreachable ({host}:{port}): {exc}"
    except Exception as exc:
        return False, f"Proxy check failed: {exc}"


def _telegram_get_me(token: str, proxies: dict | None = None, timeout_sec: int = 10):
    url = f"https://api.telegram.org/bot{token}/getMe"
    return requests.get(url, proxies=proxies, timeout=timeout_sec)


TELEGRAM_UPLOAD_CONNECT_TIMEOUT_SECONDS = 30
TELEGRAM_UPLOAD_READ_TIMEOUT_SECONDS = 600
TELEGRAM_UPLOAD_RETRIES = 3


def _telegram_send_document(token: str, chat_id: str, file_path: str, caption: str | None, proxies: dict | None = None):
    url = f"https://api.telegram.org/bot{token}/sendDocument"
    data = {'chat_id': chat_id}
    if caption:
        data['caption'] = caption
    timeout = (TELEGRAM_UPLOAD_CONNECT_TIMEOUT_SECONDS, TELEGRAM_UPLOAD_READ_TIMEOUT_SECONDS)
    last_exc = None
    for attempt in range(1, TELEGRAM_UPLOAD_RETRIES + 1):
        try:
            with open(file_path, 'rb') as handle:
                files = {'document': (os.path.basename(file_path), handle)}
                return requests.post(url, data=data, files=files, proxies=proxies, timeout=timeout)
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as exc:
            last_exc = exc
            if attempt >= TELEGRAM_UPLOAD_RETRIES:
                raise
            time.sleep(min(2 * attempt, 5))
    if last_exc:
        raise last_exc
    raise RuntimeError('Telegram upload failed')


def _build_telegram_backup_caption(server: 'Server', backup_time: datetime) -> str:
    server_name = (getattr(server, 'name', '') or f"Server {getattr(server, 'id', '')}").strip()
    server_address = (getattr(server, 'host', '') or '').strip() or '-'
    backup_date = format_jalali(backup_time) or backup_time.isoformat()
    return '\n'.join([
        f"🛢 {server_name}",
        f"🖥️ {server_address}",
        f"📅 {backup_date}",
    ])


def _build_telegram_panel_backup_caption(backup_time: datetime) -> str:
    try:
        iran_tz = ZoneInfo('Asia/Tehran') if ZoneInfo is not None else timezone(timedelta(hours=3, minutes=30))
        if backup_time.tzinfo is None:
            backup_dt = backup_time.replace(tzinfo=timezone.utc)
        else:
            backup_dt = backup_time.astimezone(timezone.utc)
        iran_dt = backup_dt.astimezone(iran_tz)
        backup_date = jdatetime_class.fromgregorian(datetime=iran_dt.replace(tzinfo=None)).strftime('%Y/%m/%d %H:%M')
    except Exception:
        backup_date = format_jalali(backup_time) or backup_time.isoformat()
    return '\n'.join([
        f"Panel version: v{APP_VERSION}",
        f"Date time (Iran): {backup_date}",
    ])


def _content_disposition_filename(header_value: str | None) -> str | None:
    if not header_value:
        return None
    match = re.search(r"filename\*=UTF-8''([^;]+)", header_value)
    if match:
        try:
            return unquote(match.group(1))
        except Exception:
            return match.group(1)
    match = re.search(r'filename="?([^";]+)"?', header_value)
    if match:
        return match.group(1)
    return None


def _guess_backup_extension(content_type: str, filename_hint: str | None = None) -> str:
    if filename_hint:
        _, ext = os.path.splitext(filename_hint)
        if ext:
            return ext
    ct = (content_type or '').lower()
    if 'zip' in ct:
        return '.zip'
    if 'gzip' in ct:
        return '.gz'
    if 'sqlite' in ct or 'x-sqlite3' in ct:
        return '.db'
    if 'octet-stream' in ct:
        return '.db'
    return '.db'


def _try_base64_decode(value: str) -> bytes | None:
    try:
        return base64.b64decode(value, validate=True)
    except Exception:
        return None


def _extract_backup_payload_from_json(data) -> tuple[bytes | None, str | None]:
    if isinstance(data, dict):
        for key in ('obj', 'data', 'result'):
            if key in data:
                return _extract_backup_payload_from_json(data.get(key))

        filename_hint = data.get('filename') or data.get('name')
        for key in ('file', 'content', 'backup', 'bytes'):
            val = data.get(key)
            if isinstance(val, str):
                decoded = _try_base64_decode(val.strip())
                if decoded:
                    return decoded, filename_hint
        return None, filename_hint

    if isinstance(data, str):
        decoded = _try_base64_decode(data.strip())
        return decoded, None

    return None, None


def _extract_backup_bytes_from_response(resp: requests.Response) -> tuple[bytes | None, str | None, str | None]:
    content_type = (resp.headers.get('Content-Type') or '').lower()
    filename_hint = _content_disposition_filename(resp.headers.get('Content-Disposition'))

    if 'application/json' in content_type or content_type.startswith('text/'):
        data, err = _safe_response_json(resp)
        if err:
            return None, None, err
        if isinstance(data, dict) and data.get('success') is False:
            msg = data.get('msg') or data.get('message') or 'Backup failed'
            return None, None, str(msg)
        payload, json_filename = _extract_backup_payload_from_json(data)
        if not payload:
            return None, None, 'Backup payload missing'
        ext = _guess_backup_extension(content_type, json_filename or filename_hint)
        return payload, ext, None

    if resp.status_code != 200:
        return None, None, f"HTTP {resp.status_code}"

    if not resp.content:
        return None, None, "Empty response (status 200)"

    return resp.content, _guess_backup_extension(content_type, filename_hint), None


def _is_sqlite_payload(payload: bytes | None) -> bool:
    if not payload or len(payload) < 16:
        return False
    return payload.startswith(b"SQLite format 3")


def _collect_backup_endpoints(panel_type: str) -> list[tuple[str, str]]:
    normalized = (panel_type or 'auto').strip().lower()
    candidates: list[tuple[str, str]] = []

    if normalized in ('sanaei', 'auto', ''):
        candidates.extend([
            ('POST', '/panel/api/backup'),
            ('GET', '/panel/api/backup'),
            ('GET', '/panel/api/server/getDb'),
            ('GET', '/server/getDb'),
        ])
    if normalized in ('alireza', 'alireza0', 'xui', 'x-ui', 'auto', ''):
        candidates.extend([
            ('POST', '/xui/API/backup'),
            ('GET', '/xui/API/backup'),
            ('POST', '/xui/api/backup'),
            ('GET', '/xui/api/backup'),
            ('GET', '/xui/server/getDb'),
            ('GET', '/api/server/getDb'),
        ])

    candidates.extend([
        ('POST', '/panel/api/backup'),
        ('GET', '/panel/api/backup'),
        ('GET', '/panel/api/server/getDb'),
        ('GET', '/server/getDb'),
        ('POST', '/xui/API/backup'),
        ('GET', '/xui/API/backup'),
        ('POST', '/xui/api/backup'),
        ('GET', '/xui/api/backup'),
        ('GET', '/xui/server/getDb'),
        ('GET', '/api/server/getDb'),
    ])

    seen = set()
    deduped = []
    for method, ep in candidates:
        key = (method, ep)
        if key in seen:
            continue
        seen.add(key)
        deduped.append((method, ep))
    return deduped


def _fetch_xui_backup(session_obj: requests.Session, server: 'Server') -> tuple[bytes | None, str | None, str | None]:
    endpoints = _collect_backup_endpoints(getattr(server, 'panel_type', 'auto'))
    errors = []
    for method, template in endpoints:
        full_url = build_panel_url(server.host, template, {})
        if not full_url:
            continue
        try:
            if method == 'POST':
                resp = session_obj.post(full_url, verify=False, timeout=15)
            else:
                resp = session_obj.get(full_url, verify=False, timeout=15)
        except Exception as exc:
            errors.append(f"{method} {template}: {exc}")
            continue

        payload, ext, err = _extract_backup_bytes_from_response(resp)
        if payload:
            if (template.endswith('/getDb') or (ext or '').lower() == '.db') and not _is_sqlite_payload(payload):
                errors.append(f"{method} {template}: Invalid DB payload")
                continue
            return payload, ext, None
        errors.append(f"{method} {template}: {err or resp.status_code}")

    return None, None, '; '.join(errors) or 'No backup endpoint succeeded'


def _run_telegram_backup(trigger: str = 'scheduled', progress_cb=None) -> dict:
    if not TELEGRAM_BACKUP_LOCK.acquire(blocking=False):
        return {'success': False, 'error': 'Backup already running'}

    tmp_dir = None
    try:
        if progress_cb:
            try:
                progress_cb({'stage': 'loading_settings', 'progress': {'total': 0, 'processed': 0}})
            except Exception:
                pass

        settings = _get_telegram_backup_settings()
        enabled = bool(settings.get('enabled'))
        send_panel_backup = bool(settings.get('send_panel_backup'))
        if trigger == 'scheduled' and not enabled:
            return {'success': True, 'skipped': True, 'message': 'Telegram backup disabled'}

        token = (settings.get('bot_token') or '').strip()
        chat_id = (settings.get('chat_id') or '').strip()
        if not token or not chat_id:
            return {'success': False, 'error': 'Telegram bot token and chat ID are required'}

        if progress_cb:
            try:
                progress_cb({'stage': 'building_proxy'})
            except Exception:
                pass

        proxies = _build_telegram_proxies(
            bool(settings.get('use_proxy')),
            settings.get('proxy_mode') or 'url',
            settings.get('proxy_url') or '',
            settings.get('proxy_host') or '',
            int(settings.get('proxy_port') or 0),
            settings.get('proxy_username') or '',
            settings.get('proxy_password') or ''
        )

        if proxies:
            if progress_cb:
                try:
                    progress_cb({'stage': 'checking_proxy'})
                except Exception:
                    pass
            proxy_ok, proxy_err = _check_proxy_reachable(proxies)
            if not proxy_ok:
                return {
                    'success': False,
                    'error': f"Proxy unreachable — could not connect before upload started. {proxy_err}. "
                             "Check Settings → Telegram Backup → Proxy."
                }

        now = datetime.utcnow()

        servers = Server.query.filter_by(enabled=True).all()
        if not servers and not send_panel_backup:
            return {'success': False, 'error': 'No enabled servers found'}

        if progress_cb:
            try:
                progress_cb({'stage': 'fetching_servers', 'progress': {'total': len(servers) + (1 if send_panel_backup else 0), 'processed': 0}})
            except Exception:
                pass

        tmp_dir = tempfile.mkdtemp(prefix='telegram_backup_', dir=TELEGRAM_BACKUP_TMP_DIR)
        results = []

        total_items = len(servers) + (1 if send_panel_backup else 0)
        processed_items = 0

        for server in servers:
            if progress_cb:
                try:
                    progress_cb({'stage': f"xui_login:{server.name}", 'progress': {'total': total_items, 'processed': processed_items}})
                except Exception:
                    pass

            session_obj, error = get_xui_session(server)
            if error:
                results.append({'server_id': server.id, 'server_name': server.name, 'success': False, 'error': f"X-UI Connection Failed: {error}"})
                processed_items += 1
                if progress_cb:
                    try:
                        progress_cb({'stage': f"xui_failed:{server.name}", 'progress': {'total': total_items, 'processed': processed_items}, 'results': list(results)})
                    except Exception:
                        pass
                continue

            if progress_cb:
                try:
                    progress_cb({'stage': f"xui_download_backup:{server.name}", 'progress': {'total': total_items, 'processed': processed_items}})
                except Exception:
                    pass

            payload, ext, err = _fetch_xui_backup(session_obj, server)
            if err or not payload:
                results.append({'server_id': server.id, 'server_name': server.name, 'success': False, 'error': f"X-UI Backup Download Failed: {err or 'Empty response'}"})
                processed_items += 1
                if progress_cb:
                    try:
                        progress_cb({'stage': f"xui_failed:{server.name}", 'progress': {'total': total_items, 'processed': processed_items}, 'results': list(results)})
                    except Exception:
                        pass
                continue

            safe_server_name = secure_filename(server.name) or f"server_{server.id}"
            timestamp = now.strftime('%Y%m%d_%H%M%S')
            ext = ext or '.db'
            filename = f"{safe_server_name}_{timestamp}{ext}"
            file_path = os.path.join(tmp_dir, filename)
            with open(file_path, 'wb') as handle:
                handle.write(payload)

            caption = _build_telegram_backup_caption(server, now)
            if progress_cb:
                try:
                    progress_cb({'stage': f"telegram_upload:{server.name}", 'progress': {'total': total_items, 'processed': processed_items}})
                except Exception:
                    pass
            try:
                resp = _telegram_send_document(token, chat_id, file_path, caption, proxies=proxies)
            except Exception as exc:
                results.append({'server_id': server.id, 'server_name': server.name, 'success': False, 'error': f"Telegram Upload Failed (Network/Proxy): {str(exc)}"})
                processed_items += 1
                if progress_cb:
                    try:
                        progress_cb({'stage': f"telegram_failed:{server.name}", 'progress': {'total': total_items, 'processed': processed_items}, 'results': list(results)})
                    except Exception:
                        pass
                continue

            resp_json, resp_err = _safe_response_json(resp)
            if resp_err:
                results.append({'server_id': server.id, 'server_name': server.name, 'success': False, 'error': f"Telegram API Error: {resp_err}"})
                processed_items += 1
                if progress_cb:
                    try:
                        progress_cb({'stage': f"telegram_failed:{server.name}", 'progress': {'total': total_items, 'processed': processed_items}, 'results': list(results)})
                    except Exception:
                        pass
                continue

            server_ok = isinstance(resp_json, dict) and resp_json.get('ok')
            if server_ok:
                results.append({'server_id': server.id, 'server_name': server.name, 'success': True})
            else:
                msg = None
                if isinstance(resp_json, dict):
                    msg = resp_json.get('description') or resp_json.get('error')
                results.append({'server_id': server.id, 'server_name': server.name, 'success': False, 'error': f"Telegram API Refused: {msg or 'Unknown error'}"})

            processed_items += 1
            if progress_cb:
                try:
                    stage_name = f"server_done:{server.name}" if server_ok else f"telegram_failed:{server.name}"
                    progress_cb({'stage': stage_name, 'progress': {'total': total_items, 'processed': processed_items}, 'results': list(results)})
                except Exception:
                    pass

        if send_panel_backup:
            panel_label = 'Panel Backup'
            panel_file_path = None
            if progress_cb:
                try:
                    progress_cb({'stage': 'panel_backup_create', 'progress': {'total': total_items, 'processed': processed_items}, 'results': list(results)})
                except Exception:
                    pass
            try:
                panel_filename = _create_database_backup_file('telegram_panel')
                panel_file_path = os.path.join(BACKUP_DIR, panel_filename)
            except Exception as exc:
                results.append({'server_id': None, 'server_name': panel_label, 'kind': 'panel', 'success': False, 'error': f"Panel Backup Create Failed: {str(exc)}"})
                processed_items += 1
                if progress_cb:
                    try:
                        progress_cb({'stage': 'panel_backup_failed', 'progress': {'total': total_items, 'processed': processed_items}, 'results': list(results)})
                    except Exception:
                        pass
            if panel_file_path:
                if progress_cb:
                    try:
                        progress_cb({'stage': 'panel_backup_upload', 'progress': {'total': total_items, 'processed': processed_items}, 'results': list(results)})
                    except Exception:
                        pass
                try:
                    caption = _build_telegram_panel_backup_caption(now)
                    resp = _telegram_send_document(token, chat_id, panel_file_path, caption, proxies=proxies)
                    resp_json, resp_err = _safe_response_json(resp)
                    if resp_err:
                        results.append({'server_id': None, 'server_name': panel_label, 'kind': 'panel', 'success': False, 'error': f"Telegram API Error: {resp_err}"})
                    elif isinstance(resp_json, dict) and resp_json.get('ok'):
                        results.append({'server_id': None, 'server_name': panel_label, 'kind': 'panel', 'success': True})
                    else:
                        msg = None
                        if isinstance(resp_json, dict):
                            msg = resp_json.get('description') or resp_json.get('error')
                        results.append({'server_id': None, 'server_name': panel_label, 'kind': 'panel', 'success': False, 'error': f"Telegram API Refused: {msg or 'Unknown error'}"})
                except Exception as exc:
                    results.append({'server_id': None, 'server_name': panel_label, 'kind': 'panel', 'success': False, 'error': f"Telegram Upload Failed (Network/Proxy): {str(exc)}"})

                processed_items += 1
                if progress_cb:
                    try:
                        panel_ok = bool(results and results[-1].get('success'))
                        stage_name = 'panel_backup_done' if panel_ok else 'panel_backup_failed'
                        progress_cb({'stage': stage_name, 'progress': {'total': total_items, 'processed': processed_items}, 'results': list(results)})
                    except Exception:
                        pass

        success_count = sum(1 for r in results if r.get('success'))

        # Only record last_run timestamp when at least one file was actually delivered
        if success_count > 0:
            try:
                _set_system_setting_value('telegram_backup_last_run', now.isoformat())
                db.session.commit()
            except Exception:
                pass

        # specific top-level error generation
        main_error = None
        if success_count == 0 and results:
            # Collect unique error prefixes
            errs = sorted(list(set(r.get('error', 'Unknown') for r in results)))
            raw = ' '.join(errs).lower()
            # Translate cryptic proxy/network errors into a clear, actionable message
            if 'socks5 authentication failed' in raw or ('authentication' in raw and 'socks' in raw):
                main_error = ('SOCKS5 proxy authentication failed — check the proxy username/password '
                              '(or disable proxy auth if the proxy does not require it). '
                              'Telegram backups have been failing since this started.')
            elif 'failed to establish a new connection' in raw or 'max retries exceeded' in raw or 'connection refused' in raw:
                main_error = ('Could not reach Telegram through the proxy — the proxy may be down or the '
                              'host/port is wrong. Check Settings → Telegram Backup → Proxy.')
            elif 'timed out' in raw or 'timeout' in raw:
                main_error = 'Connection to Telegram/proxy timed out. The proxy or network may be slow or blocked.'
            elif len(errs) == 1:
                main_error = errs[0]
            else:
                main_error = f"All backups failed. Errors: {'; '.join(errs[:2])}..."

        return {
            'success': success_count > 0,
            'error': main_error,
            'results': results,
            'success_count': success_count,
            'total': len(results)
        }
    finally:
        if tmp_dir and os.path.exists(tmp_dir):
            try:
                shutil.rmtree(tmp_dir)
            except Exception:
                pass
        try:
            TELEGRAM_BACKUP_LOCK.release()
        except Exception:
            pass

# Use Redis for rate-limit storage when available so limits are shared across
# gunicorn workers (and the "in-memory storage" warning goes away). Falls back
# to in-memory if Redis isn't configured/reachable.
_LIMITER_STORAGE_URI = REDIS_URL if (REDIS_URL and redis_enabled()) else "memory://"
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["5000 per day", "500 per hour"],
    storage_uri=_LIMITER_STORAGE_URI,
)

db = SQLAlchemy(app)

logger = logging.getLogger(__name__)
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)

# --- MODELS ---

class Admin(db.Model):
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='admin')
    is_superadmin = db.Column(db.Boolean, default=False)
    credit = db.Column(db.Integer, default=0)
    allow_negative_credit = db.Column(db.Boolean, default=False)
    negative_credit_limit = db.Column(db.Integer, default=0)
    allowed_servers = db.Column(db.Text, default='[]')
    enabled = db.Column(db.Boolean, default=True)
    discount_percent = db.Column(db.Integer, default=0)
    custom_cost_per_day = db.Column(db.Integer, nullable=True)
    custom_cost_per_gb = db.Column(db.Integer, nullable=True)
    sub_shown_package_ids = db.Column(db.Text, default='[]')  # admin/global/assigned package IDs this reseller shows on their customers' sub pages
    telegram_id = db.Column(db.String(100), nullable=True)
    support_telegram = db.Column(db.String(100), nullable=True)
    support_whatsapp = db.Column(db.String(64), nullable=True)
    support_sms = db.Column(db.String(64), nullable=True)
    channel_telegram = db.Column(db.Text, nullable=True)
    channel_whatsapp = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    transactions = db.relationship('Transaction', backref='admin', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'role': self.role,
            'is_superadmin': self.is_superadmin,
            'credit': self.credit,
            'allow_negative_credit': bool(self.allow_negative_credit),
            'negative_credit_limit': self.negative_credit_limit or 0,
            'allowed_servers': parse_allowed_servers(self.allowed_servers),
            'enabled': self.enabled,
            'discount_percent': self.discount_percent,
            'custom_cost_per_day': self.custom_cost_per_day,
            'custom_cost_per_gb': self.custom_cost_per_gb,
            'telegram_id': self.telegram_id,
            'support_telegram': self.support_telegram,
            'support_whatsapp': self.support_whatsapp,
            'support_sms': self.support_sms,
            'channel_telegram': self.channel_telegram,
            'channel_whatsapp': self.channel_whatsapp,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }

class Server(db.Model):
    __tablename__ = 'servers'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    host = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    enabled = db.Column(db.Boolean, default=True)
    hidden = db.Column(db.Boolean, default=False)   # hidden=True: skip fetch & dashboard, but still backed up
    panel_type = db.Column(db.String(50), default='auto')
    sub_path = db.Column(db.String(50), default='/sub/')
    json_path = db.Column(db.String(50), default='/json/')
    sub_port = db.Column(db.Integer, nullable=True)
    # 3x-ui v3+ API token (Bearer). When set, EVE authenticates with the token
    # (skips cookie login + CSRF) and uses the v3 /panel/api/clients/* endpoints.
    api_token = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'host': self.host,
            'username': self.username,
            'enabled': self.enabled,
            'hidden': bool(self.hidden),
            'panel_type': self.panel_type,
            'sub_path': self.sub_path,
            'json_path': self.json_path,
            'sub_port': self.sub_port,
            'has_api_token': bool((self.api_token or '').strip()),
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class SubAppConfig(db.Model):
    __tablename__ = 'sub_app_configs'
    id = db.Column(db.Integer, primary_key=True)
    app_code = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(100))
    os_type = db.Column(db.String(20), default='android')  # android, ios, windows
    is_enabled = db.Column(db.Boolean, default=True)
    title_fa = db.Column(db.String(200))
    description_fa = db.Column(db.Text)
    title_en = db.Column(db.String(200))
    description_en = db.Column(db.Text)
    download_link = db.Column(db.String(500))
    store_link = db.Column(db.String(500))
    tutorial_link = db.Column(db.String(500))
    icon_url = db.Column(db.String(500))
    is_recommended = db.Column(db.Boolean, default=False)
    display_order = db.Column(db.Integer, default=0)

    def to_dict(self):
        return {
            'id': self.id,
            'app_code': self.app_code,
            'name': self.name,
            'os_type': self.os_type or 'android',
            'is_enabled': self.is_enabled,
            'title_fa': self.title_fa,
            'description_fa': self.description_fa,
            'title_en': self.title_en,
            'description_en': self.description_en,
            'download_link': self.download_link,
            'store_link': self.store_link,
            'tutorial_link': self.tutorial_link,
            'icon_url': self.icon_url,
            'is_recommended': self.is_recommended or False,
            'display_order': self.display_order or 0,
        }

class FAQ(db.Model):
    __tablename__ = 'faqs'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text)  # HTML content
    image_url = db.Column(db.String(500))
    video_url = db.Column(db.String(500))
    platform = db.Column(db.String(20), default='android')  # android, ios, windows
    is_enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'content': self.content,
            'image_url': self.image_url,
            'video_url': self.video_url,
            'platform': self.platform or 'android',
            'is_enabled': self.is_enabled
        }

class Package(db.Model):
    __tablename__ = 'packages'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    days = db.Column(db.Integer, nullable=False)
    volume = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Integer, nullable=False)
    reseller_price = db.Column(db.Integer, nullable=True)
    enabled = db.Column(db.Boolean, default=True)
    # Extended columns (added via ALTER TABLE migration for existing DBs)
    scope = db.Column(db.String(20), default='global')        # global | assigned | personal
    assigned_reseller_ids = db.Column(db.Text, default='[]')  # JSON list of admin IDs
    created_by = db.Column(db.Integer, nullable=True)
    display_order = db.Column(db.Integer, default=0)
    show_on_sub = db.Column(db.Boolean, default=False)  # show this package on customer subscription page
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        import json as _j
        try:
            assigned = _j.loads(self.assigned_reseller_ids or '[]')
        except Exception:
            assigned = []
        return {
            'id': self.id,
            'name': self.name,
            'days': self.days,
            'volume': self.volume,
            'price': self.price,
            'reseller_price': self.reseller_price,
            'enabled': self.enabled,
            'scope': self.scope or 'global',
            'assigned_reseller_ids': assigned,
            'created_by': self.created_by,
            'display_order': self.display_order or 0,
            'show_on_sub': bool(self.show_on_sub),
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class PriceTier(db.Model):
    """Dynamic pricing rule: applies when volume_gb/days fall within the defined range."""
    __tablename__ = 'price_tiers'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    # Conditions — None means no constraint on that dimension
    min_volume_gb = db.Column(db.Float, nullable=True)   # volume >= this
    max_volume_gb = db.Column(db.Float, nullable=True)   # volume < this (exclusive)
    min_days = db.Column(db.Integer, nullable=True)
    max_days = db.Column(db.Integer, nullable=True)
    # Rate overrides (None = fall through to system default)
    cost_per_gb = db.Column(db.Integer, nullable=True)
    cost_per_day = db.Column(db.Integer, nullable=True)
    # Scope: None = global; reseller_id is legacy single-reseller scope.
    # assigned_reseller_ids stores a JSON list for multi-reseller rules.
    reseller_id = db.Column(db.Integer, nullable=True, index=True)
    assigned_reseller_ids = db.Column(db.Text, default='[]')
    server_id = db.Column(db.Integer, nullable=True, index=True)
    priority = db.Column(db.Integer, default=0)  # higher = evaluated first
    is_active = db.Column(db.Boolean, default=True)
    created_by = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        try:
            assigned = json.loads(self.assigned_reseller_ids or '[]')
        except Exception:
            assigned = []
        if self.reseller_id and self.reseller_id not in assigned:
            assigned.append(self.reseller_id)
        return {
            'id': self.id,
            'name': self.name,
            'min_volume_gb': self.min_volume_gb,
            'max_volume_gb': self.max_volume_gb,
            'min_days': self.min_days,
            'max_days': self.max_days,
            'cost_per_gb': self.cost_per_gb,
            'cost_per_day': self.cost_per_day,
            'reseller_id': self.reseller_id,
            'assigned_reseller_ids': assigned,
            'server_id': self.server_id,
            'priority': self.priority,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class SystemConfig(db.Model):
    __tablename__ = 'system_configs'
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.Text)


RECEIPT_STATUS_PENDING = 'pending'
RECEIPT_STATUS_AUTO_PENDING = 'auto_pending'
RECEIPT_STATUS_APPROVED = 'approved'
RECEIPT_STATUS_AUTO_APPROVED = 'auto_approved'
RECEIPT_STATUS_REJECTED = 'rejected'


class BankCard(db.Model):
    __tablename__ = 'bank_cards'
    id = db.Column(db.Integer, primary_key=True)
    label = db.Column(db.String(120), nullable=False)
    bank_name = db.Column(db.String(120))
    owner_name = db.Column(db.String(120))
    card_number = db.Column(db.String(32))
    iban = db.Column(db.String(34))
    account_number = db.Column(db.String(64))
    notes = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def masked_card(self):
        if not self.card_number:
            return None
        cleaned = ''.join(filter(str.isdigit, self.card_number))
        if len(cleaned) <= 4:
            return cleaned
        return f"{'*' * (len(cleaned) - 4)}{cleaned[-4:]}"

    def to_dict(self):
        return {
            'id': self.id,
            'label': self.label,
            'bank_name': self.bank_name,
            'owner_name': self.owner_name,
            'card_number': self.card_number,
            'masked_card': self.masked_card(),
            'iban': self.iban,
            'account_number': self.account_number,
            'notes': self.notes,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class NotificationTemplate(db.Model):
    __tablename__ = 'notification_templates'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(50), default='client_created')
    is_active = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # NULL = global; reseller admin.id = reseller-specific (takes priority over global)
    owner_id = db.Column(db.Integer, db.ForeignKey('admins.id'), nullable=True, index=True)

    def to_dict(self):
        owner_username = None
        if self.owner_id:
            try:
                _owner = db.session.get(Admin, self.owner_id)
                owner_username = _owner.username if _owner else None
            except Exception:
                pass
        return {
            'id': self.id,
            'name': self.name,
            'content': self.content,
            'type': self.type,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'owner_id': self.owner_id,
            'owner_username': owner_username,
            'scope': 'reseller' if self.owner_id else 'global',
        }


class RenewTemplate(db.Model):
    __tablename__ = 'renew_templates'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    is_active = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'content': self.content,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


announcement_servers = db.Table(
    'announcement_servers',
    db.Column('announcement_id', db.Integer, db.ForeignKey('announcements.id'), primary_key=True),
    db.Column('server_id', db.Integer, db.ForeignKey('servers.id'), primary_key=True),
)


class Announcement(db.Model):
    __tablename__ = 'announcements'
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)
    all_servers = db.Column(db.Boolean, default=True)
    # Reseller-style targeting rules (same shape as Admin.allowed_servers):
    # '*' OR JSON list of {server_id: int, inbounds: '*'|[int,...]}
    targets = db.Column(db.Text)
    start_at = db.Column(db.DateTime, nullable=False)
    end_at = db.Column(db.DateTime, nullable=False)
    created_by = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    hide_from_resellers = db.Column(db.Boolean, default=False)  # when True, not shown on reseller-owned accounts' sub pages
    is_popup = db.Column(db.Boolean, default=False)  # when True, shown as a modal popup when the sub page opens
    button_text = db.Column(db.String(120))          # popup dismiss-button label (optional)

    servers = db.relationship('Server', secondary=announcement_servers, lazy='subquery')

    def to_dict(self):
        server_ids = []
        server_names = []
        try:
            for s in (self.servers or []):
                server_ids.append(s.id)
                server_names.append(s.name)
        except Exception:
            pass

        now_utc = datetime.utcnow()
        is_active = False
        try:
            is_active = bool(self.start_at and self.end_at and self.start_at <= now_utc <= self.end_at)
        except Exception:
            is_active = False

        return {
            'id': self.id,
            'message': self.message,
            'all_servers': bool(self.all_servers),
            'targets': self.targets or ('*' if self.all_servers else ''),
            'server_ids': server_ids,
            'server_names': server_names,
            'start_at': self.start_at.isoformat() if self.start_at else None,
            'end_at': self.end_at.isoformat() if self.end_at else None,
            'start_at_jalali': format_jalali(self.start_at) if self.start_at else None,
            'end_at_jalali': format_jalali(self.end_at) if self.end_at else None,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'created_at_jalali': format_jalali(self.created_at) if self.created_at else None,
            'is_active': is_active,
            'hide_from_resellers': bool(self.hide_from_resellers),
            'is_popup': bool(self.is_popup),
            'button_text': self.button_text or '',
        }


class OnlineChatScript(db.Model):
    __tablename__ = 'online_chat_scripts'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    script_code = db.Column(db.Text, nullable=False)
    is_active = db.Column(db.Boolean, default=False)
    created_by = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        preview = (self.script_code or '').strip().replace('\n', ' ')
        if len(preview) > 160:
            preview = preview[:160] + '...'
        return {
            'id': self.id,
            'name': self.name,
            'script_code': self.script_code,
            'preview': preview,
            'is_active': bool(self.is_active),
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class BackupConfig(db.Model):
    __tablename__ = 'backup_configs'
    id = db.Column(db.Integer, primary_key=True)
    server_id = db.Column(db.Integer, db.ForeignKey('servers.id', ondelete='SET NULL'), nullable=True)
    title = db.Column(db.String(200), nullable=False)
    config_url = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text, nullable=False, default='')
    is_enabled = db.Column(db.Boolean, default=True)
    sort_order = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    server = db.relationship('Server', backref=db.backref('backup_configs', passive_deletes=True), foreign_keys=[server_id])

    DEFAULT_DESCRIPTION = (
        'این کانفیگ پشتیبانه. اگه کانفیگ اصلیت کار نمیکنه، '
        'این رو کپی کن و توی برنامه VPN بزن Import from clipboard.\n\n'
        'This is a backup config. If your main connection isn\'t working, '
        'copy this and import it in your VPN app.'
    )

    def to_dict(self):
        return {
            'id': self.id,
            'server_id': self.server_id,
            'server_name': self.server.name if self.server else None,
            'title': self.title,
            'config_url': self.config_url,
            'description': self.description,
            'is_enabled': bool(self.is_enabled),
            'sort_order': self.sort_order,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class SystemSetting(db.Model):
    __tablename__ = 'system_settings'
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.Text)


class VolumeRulePreset(db.Model):
    """Saved Volume Filter rule sets so users can reload them instead of
    re-entering rules every time."""
    __tablename__ = 'volume_rule_presets'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    rules = db.Column(db.Text, nullable=False)  # JSON list of rule dicts
    owner_id = db.Column(db.Integer, db.ForeignKey('admins.id'), nullable=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        try:
            rules = json.loads(self.rules or '[]')
        except Exception:
            rules = []
        return {
            'id': self.id,
            'name': self.name,
            'rules': rules,
            'owner_id': self.owner_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class UsageSnapshot(db.Model):
    """Hourly usage snapshot per subscription. No personal data stored."""
    __tablename__ = 'usage_snapshots'
    id = db.Column(db.Integer, primary_key=True)
    server_id = db.Column(db.Integer, db.ForeignKey('servers.id', ondelete='CASCADE'), nullable=False, index=True)
    sub_id = db.Column(db.String(128), nullable=False, index=True)
    inbound_tag = db.Column(db.String(256), nullable=True, index=True)
    recorded_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    upload_bytes = db.Column(db.BigInteger, nullable=False, default=0)
    download_bytes = db.Column(db.BigInteger, nullable=False, default=0)
    total_bytes = db.Column(db.BigInteger, nullable=False, default=0)
    remaining_bytes = db.Column(db.BigInteger, nullable=True)
    volume_limit_bytes = db.Column(db.BigInteger, nullable=True)

    __table_args__ = (
        db.Index('ix_usage_snapshots_server_sub', 'server_id', 'sub_id'),
        db.Index('ix_usage_snapshots_server_inbound', 'server_id', 'inbound_tag'),
    )


class RenewalEvent(db.Model):
    """Detected renewal event for a subscription."""
    __tablename__ = 'renewal_events'
    id = db.Column(db.Integer, primary_key=True)
    server_id = db.Column(db.Integer, db.ForeignKey('servers.id', ondelete='CASCADE'), nullable=False, index=True)
    sub_id = db.Column(db.String(128), nullable=False, index=True)
    renewed_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    volume_bytes = db.Column(db.BigInteger, nullable=True)
    days = db.Column(db.Integer, nullable=True)
    is_unlimited_volume = db.Column(db.Boolean, default=False)
    is_unlimited_time = db.Column(db.Boolean, default=False)

    __table_args__ = (
        db.Index('ix_renewal_events_server_sub', 'server_id', 'sub_id'),
    )


RENEW_TEMPLATE_SETTING_KEY = 'renew_template'
DEFAULT_RENEW_TEMPLATE = """🔰{email}\n⌛{days_label} 📊{volume_label}\nتمدید شد"""

MONITOR_SETTINGS_KEY = 'monitor_settings'
GENERAL_TIMEZONE_SETTING_KEY = 'general_timezone'
PANEL_UI_LANG_SETTING_KEY = 'panel_ui_lang'
PANEL_DOMAIN_SETTING_KEY = 'panel_domain'
GENERAL_EXPIRY_WARNING_DAYS_KEY = 'general_expiry_warning_days'
GENERAL_EXPIRY_WARNING_HOURS_KEY = 'general_expiry_warning_hours'
GENERAL_LOW_VOLUME_WARNING_GB_KEY = 'general_low_volume_warning_gb'
DEFAULT_APP_TIMEZONE = 'Asia/Tehran'
WHATSAPP_DEPLOYMENT_REGION_KEY = 'whatsapp_deployment_region'
WHATSAPP_ENABLED_KEY = 'whatsapp_enabled'
WHATSAPP_PROVIDER_KEY = 'whatsapp_provider'
WHATSAPP_TRIGGER_RENEW_KEY = 'whatsapp_trigger_renew_success'
WHATSAPP_TRIGGER_WELCOME_KEY = 'whatsapp_trigger_welcome'
WHATSAPP_TRIGGER_PRE_EXPIRY_KEY = 'whatsapp_trigger_pre_expiry'
WHATSAPP_MIN_INTERVAL_SECONDS_KEY = 'whatsapp_min_interval_seconds'
WHATSAPP_DAILY_LIMIT_KEY = 'whatsapp_daily_limit'
WHATSAPP_PRE_EXPIRY_HOURS_KEY = 'whatsapp_pre_expiry_hours'
WHATSAPP_RETRY_COUNT_KEY = 'whatsapp_retry_count'
WHATSAPP_BACKOFF_SECONDS_KEY = 'whatsapp_backoff_seconds'
WHATSAPP_CIRCUIT_BREAKER_KEY = 'whatsapp_circuit_breaker'
WHATSAPP_TEMPLATE_RENEW_KEY = 'whatsapp_template_renew'
WHATSAPP_TEMPLATE_WELCOME_KEY = 'whatsapp_template_welcome'
WHATSAPP_TEMPLATE_PRE_EXPIRY_KEY = 'whatsapp_template_pre_expiry'
WHATSAPP_GATEWAY_URL_KEY = 'whatsapp_gateway_url'
WHATSAPP_GATEWAY_API_KEY = 'whatsapp_gateway_api_key'
WHATSAPP_GATEWAY_TIMEOUT_KEY = 'whatsapp_gateway_timeout_seconds'

DEFAULT_WHATSAPP_TEMPLATE_RENEW = "سلام {user}، تمدید شما با موفقیت انجام شد."
DEFAULT_WHATSAPP_TEMPLATE_WELCOME = "سلام {user}، اشتراک شما فعال شد."
DEFAULT_WHATSAPP_TEMPLATE_PRE_EXPIRY = "سلام {user}، اشتراک شما تا {time_left} دیگر منقضی می‌شود."
ACCOUNT_INFO_WHATSAPP_TEMPLATE_TYPE = 'account_info_whatsapp'
ACCOUNT_INFO_SMS_TEMPLATE_TYPE = 'account_info_sms'
ROYALTY_INFO_WHATSAPP_TEMPLATE_TYPE = 'royalty_info_whatsapp'
ROYALTY_INFO_SMS_TEMPLATE_TYPE = 'royalty_info_sms'
# Channel-specific variants for Client-Created and Renew notifications
CLIENT_CREATED_WHATSAPP_TEMPLATE_TYPE = 'client_created_whatsapp'
CLIENT_CREATED_SMS_TEMPLATE_TYPE = 'client_created_sms'
RENEW_WHATSAPP_TEMPLATE_TYPE = 'renew_whatsapp'
RENEW_SMS_TEMPLATE_TYPE = 'renew_sms'

DEFAULT_ACCOUNT_INFO_WHATSAPP_TEMPLATE = """اطلاعات اکانت شما
اسم اکانت: {email}
مدت زمان باقی مانده: {remaining_time}
حجم باقی مانده: {remaining_volume}
لینک dash sub: {dashboard_link}

لطفا از طریق لینک بالا به سرویس خود متصل شین ."""

DEFAULT_ACCOUNT_INFO_SMS_TEMPLATE = """{email}
Time: {remaining_time}
Volume: {remaining_volume}
Link: {dashboard_link}"""

DEFAULT_ROYALTY_INFO_WHATSAPP_TEMPLATE = """سلام {email} عزیز 👋
اکانت شما آماده‌ست ولی هنوز وصل نشدین!

لینک اتصال: {dashboard_link}

اگه مشکلی دارین بگین کمک کنیم 🙏"""

DEFAULT_ROYALTY_INFO_SMS_TEMPLATE = """{email}
اکانت آماده‌ست، وصل نشدی!
لینک: {dashboard_link}"""

DEFAULT_CLIENT_CREATED_WHATSAPP_TEMPLATE = """اکانت شما ساخته شد ✅
اسم اکانت: {email}
حجم: {volume} | مدت: {days} روز
لینک اتصال: {dashboard_link}

لطفا از طریق لینک بالا به سرویس خود متصل شین."""

DEFAULT_CLIENT_CREATED_SMS_TEMPLATE = """{email}
Volume: {volume} | Days: {days}
Link: {dashboard_link}"""

DEFAULT_RENEW_WHATSAPP_TEMPLATE = """تمدید شد ✅
اسم اکانت: {email}
{days_label} | {volume_label}
تاریخ انقضا: {date}
لینک: {dashboard_link}"""

DEFAULT_RENEW_SMS_TEMPLATE = """{email}
{days_label} | {volume_label}
Renewed. Link: {dashboard_link}"""

WHATSAPP_CONFIG_KEYS = {
    WHATSAPP_DEPLOYMENT_REGION_KEY,
    WHATSAPP_ENABLED_KEY,
    WHATSAPP_PROVIDER_KEY,
    WHATSAPP_TRIGGER_RENEW_KEY,
    WHATSAPP_TRIGGER_WELCOME_KEY,
    WHATSAPP_TRIGGER_PRE_EXPIRY_KEY,
    WHATSAPP_MIN_INTERVAL_SECONDS_KEY,
    WHATSAPP_DAILY_LIMIT_KEY,
    WHATSAPP_PRE_EXPIRY_HOURS_KEY,
    WHATSAPP_RETRY_COUNT_KEY,
    WHATSAPP_BACKOFF_SECONDS_KEY,
    WHATSAPP_CIRCUIT_BREAKER_KEY,
    WHATSAPP_TEMPLATE_RENEW_KEY,
    WHATSAPP_TEMPLATE_WELCOME_KEY,
    WHATSAPP_TEMPLATE_PRE_EXPIRY_KEY,
    WHATSAPP_GATEWAY_URL_KEY,
    WHATSAPP_GATEWAY_API_KEY,
    WHATSAPP_GATEWAY_TIMEOUT_KEY,
}
DEFAULT_MONITOR_SETTINGS = {
    "filters": {
        "warning_days": 3,
        "warning_gb": 2.0,
        "hide_days": 7,
        "debug": False
    },
    "templates": {
        "ended": "مشترک گرامی {user}، حجم سرویس شما به پایان رسیده است.\nلطفا جهت تمدید اقدام فرمایید.",
        "expired": "مشترک گرامی {user}، زمان سرویس شما به پایان رسیده است.\nلطفا جهت تمدید اقدام فرمایید.",
        "low": "مشترک گرامی {user}، تنها {rem} از حجم سرویس شما باقی مانده است.\nتمدید میفرمایید؟",
        "soon": "مشترک گرامی {user}، تنها {time} از زمان سرویس شما باقی مانده است.\nتمدید میفرمایید؟",
        "disabled": "مشترک گرامی {user}، سرویس شما غیرفعال شده است.\nبرای پیگیری با پشتیبانی در تماس باشید."
    }
}

STANDARD_TIMEZONE_OPTIONS = [
    'Asia/Tehran',
    'UTC',
    'Europe/London', 'Europe/Dublin', 'Europe/Paris', 'Europe/Berlin', 'Europe/Amsterdam', 'Europe/Brussels',
    'Europe/Madrid', 'Europe/Rome', 'Europe/Vienna', 'Europe/Prague', 'Europe/Warsaw', 'Europe/Zurich',
    'Europe/Athens', 'Europe/Helsinki', 'Europe/Bucharest', 'Europe/Istanbul', 'Europe/Moscow',
    'Asia/Dubai', 'Asia/Riyadh', 'Asia/Jerusalem', 'Asia/Baghdad', 'Asia/Kuwait', 'Asia/Qatar',
    'Asia/Baku', 'Asia/Tbilisi', 'Asia/Yerevan', 'Asia/Karachi', 'Asia/Kolkata', 'Asia/Dhaka',
    'Asia/Bangkok', 'Asia/Jakarta', 'Asia/Kuala_Lumpur', 'Asia/Singapore', 'Asia/Manila',
    'Asia/Hong_Kong', 'Asia/Shanghai', 'Asia/Taipei', 'Asia/Seoul', 'Asia/Tokyo',
    'Australia/Perth', 'Australia/Adelaide', 'Australia/Sydney', 'Pacific/Auckland',
    'Africa/Cairo', 'Africa/Johannesburg', 'Africa/Nairobi', 'Africa/Lagos',
    'America/St_Johns', 'America/Halifax', 'America/Toronto', 'America/New_York', 'America/Chicago',
    'America/Denver', 'America/Phoenix', 'America/Los_Angeles', 'America/Anchorage', 'Pacific/Honolulu',
    'America/Mexico_City', 'America/Bogota', 'America/Lima', 'America/Caracas', 'America/Sao_Paulo',
    'America/Argentina/Buenos_Aires', 'America/Santiago',
]


def _get_standard_timezone_options() -> list[str]:
    base = []
    seen = set()
    for item in STANDARD_TIMEZONE_OPTIONS:
        key = str(item or '').strip()
        if not key or key in seen:
            continue
        seen.add(key)
        base.append(key)
    return base


def _normalize_timezone_name(value: str | None) -> str | None:
    raw = str(value or '').strip()
    if not raw:
        return None

    lowered = raw.lower()
    for tz_name in _get_standard_timezone_options():
        if tz_name.lower() == lowered:
            return tz_name
    return None


def _get_or_create_system_setting(key: str, default_value: str | None = None) -> str | None:
    """Fetch a SystemSetting value; optionally create with default if missing.

    Keep this safe for request-time usage; only writes when the row is missing.
    """
    setting = db.session.get(SystemSetting, key)
    if setting:
        return setting.value
    if default_value is None:
        return None
    try:
        setting = SystemSetting(key=key, value=str(default_value))
        db.session.add(setting)
        db.session.commit()
    except Exception:
        # Don't fail the request if we can't persist the default.
        try:
            db.session.rollback()
        except Exception:
            pass
    return str(default_value)


def _render_text_template(template: str | None, variables: dict) -> str:
    """Render a python-format template with a safe fallback."""
    raw = (template or '').strip() or DEFAULT_RENEW_TEMPLATE
    try:
        return raw.format(**variables)
    except Exception:
        # Fall back to the built-in default if user template is invalid.
        try:
            return DEFAULT_RENEW_TEMPLATE.format(**variables)
        except Exception:
            return DEFAULT_RENEW_TEMPLATE


def _normalize_monitor_settings(payload: dict | None) -> dict:
    data = payload if isinstance(payload, dict) else {}
    defaults = copy.deepcopy(DEFAULT_MONITOR_SETTINGS)

    filters = data.get('filters') if isinstance(data.get('filters'), dict) else {}
    templates = data.get('templates') if isinstance(data.get('templates'), dict) else {}

    defaults['filters']['warning_days'] = _parse_int(
        filters.get('warning_days'),
        defaults['filters']['warning_days'],
        min_value=1,
        max_value=365
    )
    try:
        defaults['filters']['warning_gb'] = float(filters.get('warning_gb', defaults['filters']['warning_gb']))
    except Exception:
        defaults['filters']['warning_gb'] = DEFAULT_MONITOR_SETTINGS['filters']['warning_gb']
    defaults['filters']['warning_gb'] = max(0.1, min(defaults['filters']['warning_gb'], 1024.0))

    defaults['filters']['hide_days'] = _parse_int(
        filters.get('hide_days'),
        defaults['filters']['hide_days'],
        min_value=0,
        max_value=365
    )
    defaults['filters']['debug'] = bool(filters.get('debug', defaults['filters']['debug']))

    for key in defaults['templates'].keys():
        val = templates.get(key)
        if isinstance(val, str) and val.strip():
            defaults['templates'][key] = val.strip()

    return defaults


def _get_monitor_settings() -> dict:
    raw = _get_or_create_system_setting(
        MONITOR_SETTINGS_KEY,
        json.dumps(DEFAULT_MONITOR_SETTINGS, ensure_ascii=False)
    )
    try:
        parsed = json.loads(raw) if raw else {}
    except Exception:
        parsed = {}
    return _normalize_monitor_settings(parsed)


def _is_valid_timezone_name(value: str | None) -> bool:
    tz_name = _normalize_timezone_name(value)
    if not tz_name:
        return False

    # If tz database is unavailable in runtime, still accept curated standard names.
    if ZoneInfo is None:
        return True

    try:
        ZoneInfo(tz_name)
        return True
    except Exception:
        # Some environments miss tzdata; allow curated values for UX consistency.
        return tz_name in _get_standard_timezone_options()


def _get_app_timezone_name() -> str:
    stored = _get_or_create_system_setting(GENERAL_TIMEZONE_SETTING_KEY, DEFAULT_APP_TIMEZONE)
    normalized = _normalize_timezone_name(stored)
    if _is_valid_timezone_name(normalized):
        return str(normalized).strip()
    return DEFAULT_APP_TIMEZONE


def _normalize_ui_lang(value: str | None, default: str = 'en') -> str:
    raw = (value or '').strip().lower()
    if raw in ('fa', 'en'):
        return raw
    return default


def _get_panel_ui_lang() -> str:
    stored = _get_or_create_system_setting(PANEL_UI_LANG_SETTING_KEY, 'en')
    return _normalize_ui_lang(stored, default='en')


def _get_dashboard_status_thresholds() -> dict:
    raw_days = _get_or_create_system_setting(GENERAL_EXPIRY_WARNING_DAYS_KEY, '3')
    raw_hours = _get_or_create_system_setting(GENERAL_EXPIRY_WARNING_HOURS_KEY, '0')
    raw_gb = _get_or_create_system_setting(GENERAL_LOW_VOLUME_WARNING_GB_KEY, '1')

    near_expiry_days = _parse_int(raw_days, 3, min_value=0, max_value=365)
    near_expiry_hours = _parse_int(raw_hours, 0, min_value=0, max_value=23)

    try:
        low_volume_gb = float(raw_gb if raw_gb is not None else 1.0)
    except Exception:
        low_volume_gb = 1.0
    low_volume_gb = max(0.01, min(low_volume_gb, 1024.0))

    return {
        'near_expiry_days': near_expiry_days,
        'near_expiry_hours': near_expiry_hours,
        'low_volume_gb': low_volume_gb,
    }


def _compute_client_service_state(*, enabled: bool, total_bytes: int, remaining_bytes: int | None, expiry_ts: int, expiry_info: dict, thresholds: dict, lang: str = 'en') -> dict:
    is_fa = _normalize_ui_lang(lang, default='en') == 'fa'

    labels = {
        'active': 'فعاله' if is_fa else 'Active',
        'inactive': 'غیرفعال' if is_fa else 'Inactive',
        'expired': 'منقضی شده' if is_fa else 'Expired',
        'volume_low': 'حجم رو به اتمامه' if is_fa else 'Low Volume',
        'expiring_soon': 'انقضا نزدیکه' if is_fa else 'Expiring Soon',
        'volume_ended': 'حجم تمام کردی' if is_fa else 'Volume Ended',
    }

    low_volume_threshold_gb = float((thresholds or {}).get('low_volume_gb') or 1.0)
    near_expiry_days = int((thresholds or {}).get('near_expiry_days') or 0)
    near_expiry_hours = int((thresholds or {}).get('near_expiry_hours') or 0)
    near_expiry_ms = ((near_expiry_days * 24) + near_expiry_hours) * 3600 * 1000

    # Reasons that hold regardless of the enable flag. Sanaei-style panels flip
    # enable=False the moment time or traffic runs out, so checking these BEFORE
    # the bare enable flag is what lets us show the real reason (expired / volume
    # ended) instead of a generic "inactive" for auto-disabled accounts.
    if total_bytes > 0 and remaining_bytes is not None and remaining_bytes <= 0:
        return {'key': 'volume_ended', 'label': labels['volume_ended'], 'emoji': '🚫', 'tag': 'ended'}

    if str((expiry_info or {}).get('type') or '').lower() == 'expired':
        return {'key': 'expired', 'label': labels['expired'], 'emoji': '⛔', 'tag': 'expired'}

    # Past time/traffic checks: a still-disabled account was turned off manually.
    if not enabled:
        return {'key': 'inactive', 'label': labels['inactive'], 'emoji': '⏸️', 'tag': 'inactive'}

    if total_bytes > 0 and remaining_bytes is not None:
        remaining_gb = float(remaining_bytes) / (1024 ** 3)
        if remaining_gb <= low_volume_threshold_gb:
            return {'key': 'volume_low', 'label': labels['volume_low'], 'emoji': '⚠️', 'tag': 'low'}

    if expiry_ts and expiry_ts > 0 and str((expiry_info or {}).get('type') or '').lower() not in ('unlimited', 'start_after_use'):
        now_ms = int(time.time() * 1000)
        remaining_ms = expiry_ts - now_ms
        if remaining_ms > 0 and near_expiry_ms > 0 and remaining_ms <= near_expiry_ms:
            return {'key': 'expiring_soon', 'label': labels['expiring_soon'], 'emoji': '⏳', 'tag': 'soon'}

    return {'key': 'active', 'label': labels['active'], 'emoji': '✅', 'tag': 'ok'}


def _normalize_whatsapp_region(value: str | None) -> str:
    raw = (value or '').strip().lower()
    if raw in ('iran', 'ir', 'inside', 'inside_iran', 'local', 'domestic'):
        return 'iran'
    return 'outside'


def _normalize_whatsapp_provider(value: str | None) -> str:
    raw = (value or '').strip().lower()
    if raw in ('cloud', 'meta', 'official'):
        return 'cloud'
    return 'baileys'


def _normalize_whatsapp_gateway_url(value: str | None) -> str:
    raw = (value or '').strip()
    if not raw:
        return ''
    if not raw.startswith('http://') and not raw.startswith('https://'):
        raw = f"https://{raw}"
    return raw.rstrip('/')


def _probe_whatsapp_gateway(gateway_url: str, timeout_seconds: int, api_key: str | None = None) -> tuple[bool, int | None, str | None]:
    normalized = _normalize_whatsapp_gateway_url(gateway_url)
    if not normalized:
        return False, None, 'empty_gateway_url'

    headers = {}
    token = (api_key or '').strip()
    if token:
        headers['Authorization'] = f"Bearer {token}"

    try:
        response = requests.get(
            f"{normalized}/health",
            headers=headers,
            timeout=max(3, int(timeout_seconds or 10)),
            verify=False,
        )
        status_code = int(response.status_code)
        if 200 <= status_code < 300:
            return True, status_code, None
        return False, status_code, 'non_success_status'
    except Exception as exc:
        return False, None, str(exc)


def _build_whatsapp_gateway_candidates(host_hint: str | None = None, configured_url: str | None = None) -> list[str]:
    candidates = []
    seen = set()

    def add(raw_value: str | None):
        normalized = _normalize_whatsapp_gateway_url(raw_value)
        if not normalized:
            return
        key = normalized.lower()
        if key in seen:
            return
        seen.add(key)
        candidates.append(normalized)

    add(configured_url)
    add(os.environ.get('WHATSAPP_GATEWAY_URL'))

    host = (host_hint or '').strip().split(':')[0].strip().lower()
    local_hosts = ['127.0.0.1', 'localhost']
    if host and host not in ('127.0.0.1', 'localhost'):
        local_hosts.append(host)

    for h in local_hosts:
        add(f"http://{h}:3000")
        add(f"http://{h}:3001")
        add(f"http://{h}:8080")

    if host and host not in ('127.0.0.1', 'localhost'):
        add(f"https://{host}/wa-gateway")
        add(f"https://{host}/whatsapp-gateway")

    return candidates


def _get_system_config_text(key: str, default: str = '') -> str:
    conf = db.session.get(SystemConfig, key)
    if not conf or conf.value is None:
        return default
    return str(conf.value)


def _get_system_config_int(key: str, default: int, min_value: int | None = None, max_value: int | None = None) -> int:
    return _parse_int(_get_system_config_text(key, str(default)), default, min_value=min_value, max_value=max_value)


def _get_system_config_bool(key: str, default: bool = False) -> bool:
    return _parse_bool(_get_system_config_text(key, 'true' if default else 'false'))


def _get_system_configs_batch(keys: list) -> dict:
    if not keys:
        return {}
    rows = SystemConfig.query.filter(SystemConfig.key.in_(keys)).all()
    result = {r.key: r.value for r in rows}
    for k in keys:
        if k not in result:
            result[k] = None
    return result


def _get_whatsapp_runtime_settings() -> dict:
    _wa_keys = [
        WHATSAPP_DEPLOYMENT_REGION_KEY, WHATSAPP_PROVIDER_KEY, WHATSAPP_ENABLED_KEY,
        WHATSAPP_TRIGGER_RENEW_KEY, WHATSAPP_TRIGGER_WELCOME_KEY, WHATSAPP_TRIGGER_PRE_EXPIRY_KEY,
        WHATSAPP_MIN_INTERVAL_SECONDS_KEY, WHATSAPP_DAILY_LIMIT_KEY, WHATSAPP_PRE_EXPIRY_HOURS_KEY,
        WHATSAPP_RETRY_COUNT_KEY, WHATSAPP_BACKOFF_SECONDS_KEY, WHATSAPP_CIRCUIT_BREAKER_KEY,
        WHATSAPP_TEMPLATE_RENEW_KEY, WHATSAPP_TEMPLATE_WELCOME_KEY, WHATSAPP_TEMPLATE_PRE_EXPIRY_KEY,
        WHATSAPP_GATEWAY_URL_KEY, WHATSAPP_GATEWAY_API_KEY, WHATSAPP_GATEWAY_TIMEOUT_KEY,
    ]
    _c = _get_system_configs_batch(_wa_keys)

    def _txt(key, default=''):
        v = _c.get(key)
        return str(v) if v is not None else default

    def _bool(key, default=False):
        return _parse_bool(_txt(key, 'true' if default else 'false'))

    def _int(key, default, min_value=None, max_value=None):
        return _parse_int(_txt(key, str(default)), default, min_value=min_value, max_value=max_value)

    region = _normalize_whatsapp_region(_txt(WHATSAPP_DEPLOYMENT_REGION_KEY, 'outside'))
    provider = _normalize_whatsapp_provider(_txt(WHATSAPP_PROVIDER_KEY, 'baileys'))
    enabled_requested = _bool(WHATSAPP_ENABLED_KEY, False)
    enabled = bool(enabled_requested and region != 'iran')

    config = {
        'deployment_region': region,
        'provider': provider,
        'enabled_requested': enabled_requested,
        'enabled': enabled,
        'trigger_renew_success': _bool(WHATSAPP_TRIGGER_RENEW_KEY, True),
        'trigger_welcome': _bool(WHATSAPP_TRIGGER_WELCOME_KEY, False),
        'trigger_pre_expiry': _bool(WHATSAPP_TRIGGER_PRE_EXPIRY_KEY, False),
        'min_interval_seconds': _int(WHATSAPP_MIN_INTERVAL_SECONDS_KEY, 45, min_value=45, max_value=3600),
        'daily_limit': _int(WHATSAPP_DAILY_LIMIT_KEY, 100, min_value=1, max_value=50000),
        'pre_expiry_hours': _int(WHATSAPP_PRE_EXPIRY_HOURS_KEY, 24, min_value=1, max_value=720),
        'retry_count': _int(WHATSAPP_RETRY_COUNT_KEY, 3, min_value=0, max_value=10),
        'backoff_seconds': _int(WHATSAPP_BACKOFF_SECONDS_KEY, 30, min_value=5, max_value=3600),
        'circuit_breaker': _bool(WHATSAPP_CIRCUIT_BREAKER_KEY, True),
        'template_renew': _txt(WHATSAPP_TEMPLATE_RENEW_KEY, DEFAULT_WHATSAPP_TEMPLATE_RENEW).strip() or DEFAULT_WHATSAPP_TEMPLATE_RENEW,
        'template_welcome': _txt(WHATSAPP_TEMPLATE_WELCOME_KEY, DEFAULT_WHATSAPP_TEMPLATE_WELCOME).strip() or DEFAULT_WHATSAPP_TEMPLATE_WELCOME,
        'template_pre_expiry': _txt(WHATSAPP_TEMPLATE_PRE_EXPIRY_KEY, DEFAULT_WHATSAPP_TEMPLATE_PRE_EXPIRY).strip() or DEFAULT_WHATSAPP_TEMPLATE_PRE_EXPIRY,
        'gateway_url': _normalize_whatsapp_gateway_url(_txt(WHATSAPP_GATEWAY_URL_KEY, '')),
        'gateway_api_key': _txt(WHATSAPP_GATEWAY_API_KEY, '').strip(),
        'gateway_timeout_seconds': _int(WHATSAPP_GATEWAY_TIMEOUT_KEY, 10, min_value=3, max_value=60),
    }

    if region == 'iran':
        config['blocked_reason'] = 'deployment_in_iran'
    return config


def _normalize_ascii_digits(value: str | None) -> str:
    val = str(value or '')
    table = str.maketrans('۰۱۲۳۴۵۶۷۸۹٠١٢٣٤٥٦٧٨٩', '01234567890123456789')
    return val.translate(table)


def _extract_iran_mobile_from_text(value: str | None, *extra_sources: str | None) -> str:
    """Extract first valid Iranian mobile from value, then extra_sources in order.

    Rules:
    - 09XXXXXXXXX  : must NOT be preceded by any letter or digit.
                     '1097' → no match (digit before 0).
                     'plus09...' → no match (letter before 0).
                     'user_09...' → match (underscore/separator before 0 is OK).
    - +98XXXXXXXXX : literal '+' required; '+' must not be preceded by a letter/digit.
    - 0098XXXXXXXXX: double-zero form; same prefix rule.
    - Spaces/dashes between digit groups are allowed (e.g. '0912 833 4643').
    """
    SEP = r'[\s\-]?'
    # Lookbehind: reject if immediately preceded by any letter (ASCII or Persian/Arabic) or digit.
    _LB = r'(?<![0-9A-Za-z؀-ۿ])'
    _PATTERNS = [
        _LB + r'\+98'  + SEP + r'(9(?:' + SEP + r'\d){9})(?!\d)',  # +98...
        _LB + r'0098'  + SEP + r'(9(?:' + SEP + r'\d){9})(?!\d)',  # 0098...
        _LB + r'0'     + SEP + r'(9(?:' + SEP + r'\d){9})(?!\d)',  # 09...
        _LB +                  r'(9(?:' + SEP + r'\d){9})(?!\d)',  # bare 9...
    ]

    def _try(text: str | None) -> str:
        if not text:
            return ''
        t = _normalize_ascii_digits(text)
        for pat in _PATTERNS:
            m = re.search(pat, t)
            if m:
                digits = re.sub(r'[^\d]', '', m.group(1))
                if len(digits) == 10 and digits.startswith('9'):
                    return f"+98{digits}"
        compact = re.sub(r'[^\d]', '', t)
        m = re.search(r'09\d{9}', compact)
        if m:
            return f"+98{m.group(0)[1:]}"
        m = re.search(r'98(9\d{9})', compact)
        if m:
            return f"+98{m.group(1)}"
        return ''

    for src in (value, *extra_sources):
        r = _try(src)
        if r:
            return r
    return ''


def _take_whatsapp_send_slot(recipient: str, runtime_cfg: dict) -> tuple[bool, str | None]:
    now_ts = time.time()
    today = datetime.utcnow().strftime('%Y-%m-%d')
    min_interval = int(runtime_cfg.get('min_interval_seconds') or 45)
    daily_limit = int(runtime_cfg.get('daily_limit') or 100)

    with WHATSAPP_SEND_TRACKER_LOCK:
        daily = WHATSAPP_SEND_TRACKER.get('daily') or {}
        if daily.get('date') != today:
            WHATSAPP_SEND_TRACKER['daily'] = {'date': today, 'count': 0}

        current_count = int((WHATSAPP_SEND_TRACKER.get('daily') or {}).get('count') or 0)
        if current_count >= daily_limit:
            return False, 'daily_limit_reached'

        per_recipient = WHATSAPP_SEND_TRACKER.get('per_recipient') or {}
        last_sent = float(per_recipient.get(recipient) or 0.0)
        if last_sent > 0 and (now_ts - last_sent) < float(min_interval):
            return False, 'recipient_rate_limited'

        per_recipient[recipient] = now_ts
        WHATSAPP_SEND_TRACKER['per_recipient'] = per_recipient
        WHATSAPP_SEND_TRACKER['daily'] = {'date': today, 'count': current_count + 1}

    return True, None


def _send_whatsapp_message(event_name: str, recipient_source: str, message_text: str, *, recipient_comment: str = '') -> dict:
    runtime_cfg = _get_whatsapp_runtime_settings()
    result = {
        'attempted': False,
        'sent': False,
        'event': event_name,
        'recipient': None,
        'reason': None,
        'status_code': None,
    }

    if runtime_cfg.get('deployment_region') == 'iran':
        result['reason'] = 'deployment_in_iran'
        return result
    if not runtime_cfg.get('enabled'):
        result['reason'] = 'feature_disabled'
        return result

    trigger_key = f"trigger_{event_name}"
    if trigger_key in runtime_cfg and not runtime_cfg.get(trigger_key):
        result['reason'] = 'trigger_disabled'
        return result

    recipient = _extract_iran_mobile_from_text(recipient_source, recipient_comment or None)
    if not recipient:
        result['reason'] = 'recipient_not_found'
        return result

    gateway_url = (runtime_cfg.get('gateway_url') or '').strip()
    if not gateway_url:
        result['reason'] = 'gateway_not_configured'
        return result

    slot_ok, slot_reason = _take_whatsapp_send_slot(recipient, runtime_cfg)
    if not slot_ok:
        result['reason'] = slot_reason
        result['recipient'] = recipient
        return result

    headers = {'Content-Type': 'application/json'}
    api_key = (runtime_cfg.get('gateway_api_key') or '').strip()
    if api_key:
        headers['Authorization'] = f"Bearer {api_key}"

    payload = {
        'to': recipient,
        'message': (message_text or '').strip(),
        'event': event_name,
    }
    result['attempted'] = True
    result['recipient'] = recipient

    try:
        response = requests.post(
            f"{gateway_url}/send",
            json=payload,
            headers=headers,
            timeout=int(runtime_cfg.get('gateway_timeout_seconds') or 10),
            verify=False,
        )
        result['status_code'] = int(response.status_code)
        if 200 <= response.status_code < 300:
            result['sent'] = True
            return result

        result['reason'] = f"gateway_http_{response.status_code}"
        return result
    except Exception as exc:
        result['reason'] = f"gateway_error: {exc}"
        return result


def _get_app_tzinfo():
    tz_name = _get_app_timezone_name()
    if ZoneInfo is not None:
        try:
            return ZoneInfo(tz_name)
        except Exception:
            pass
    # Fallback when zoneinfo database is unavailable
    return timezone(timedelta(hours=3, minutes=30))


def _to_app_timezone(dt: datetime | None):
    if not dt:
        return None
    app_tz = _get_app_tzinfo()
    try:
        if dt.tzinfo is None:
            dt_utc = dt.replace(tzinfo=timezone.utc)
        else:
            dt_utc = dt.astimezone(timezone.utc)
        return dt_utc.astimezone(app_tz)
    except Exception:
        return dt

class ManualReceipt(db.Model):
    __tablename__ = 'manual_receipts'
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admins.id'), nullable=False)
    card_id = db.Column(db.Integer, db.ForeignKey('bank_cards.id'))
    amount = db.Column(db.Integer, nullable=False)
    currency = db.Column(db.String(10), default='IRT')
    deposit_at = db.Column(db.DateTime)
    reference_code = db.Column(db.String(120))
    image_path = db.Column(db.String(300))
    status = db.Column(db.String(32), default=RECEIPT_STATUS_PENDING, index=True)
    auto_deadline = db.Column(db.DateTime, index=True)
    reviewer_id = db.Column(db.Integer, db.ForeignKey('admins.id'))
    reviewed_at = db.Column(db.DateTime)
    rejection_reason = db.Column(db.String(255))
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    admin = db.relationship('Admin', foreign_keys=[admin_id], backref=db.backref('receipts', lazy=True))
    reviewer = db.relationship('Admin', foreign_keys=[reviewer_id])
    card = db.relationship('BankCard', backref=db.backref('receipts', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'admin': {'id': self.admin.id, 'username': self.admin.username} if self.admin else None,
            'card': self.card.to_dict() if self.card else None,
            'amount': self.amount,
            'currency': self.currency,
            'deposit_at': self.deposit_at.isoformat() if self.deposit_at else None,
            'reference_code': self.reference_code,
            'image_path': self.image_path,
            'status': self.status,
            'auto_deadline': self.auto_deadline.isoformat() if self.auto_deadline else None,
            'reviewer': {'id': self.reviewer.id, 'username': self.reviewer.username} if self.reviewer else None,
            'reviewed_at': self.reviewed_at.isoformat() if self.reviewed_at else None,
            'rejection_reason': self.rejection_reason,
            'notes': self.notes,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class AutoApprovalWindow(db.Model):
    __tablename__ = 'auto_approval_windows'
    id = db.Column(db.Integer, primary_key=True)
    starts_at = db.Column(db.DateTime, nullable=False)
    ends_at = db.Column(db.DateTime, nullable=False)
    max_amount = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default='enabled')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def is_active(self, moment=None):
        moment = moment or datetime.utcnow()
        if self.status != 'enabled':
            return False
        return self.starts_at <= moment <= self.ends_at

    def to_dict(self):
        return {
            'id': self.id,
            'starts_at': self.starts_at.isoformat() if self.starts_at else None,
            'ends_at': self.ends_at.isoformat() if self.ends_at else None,
            'max_amount': self.max_amount,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class Payment(db.Model):
    """Track incoming payments from customers"""
    __tablename__ = 'payments'
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admins.id'), nullable=False)
    card_id = db.Column(db.Integer, db.ForeignKey('bank_cards.id'), nullable=True)  # کارت مقصد (شما)
    sender_card = db.Column(db.String(32))  # شماره کارت مشتری (اختیاری)
    sender_name = db.Column(db.String(120))  # نام فرستنده
    amount = db.Column(db.Integer, nullable=False)  # مبلغ به تومان
    payment_date = db.Column(db.DateTime, nullable=False)  # تاریخ واریز
    client_email = db.Column(db.String(100))  # مربوط به کدوم کلاینت
    description = db.Column(db.Text)  # توضیحات
    verified = db.Column(db.Boolean, default=False)  # تایید شده؟
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    admin = db.relationship('Admin', backref=db.backref('payments', lazy=True))
    card = db.relationship('BankCard', backref=db.backref('payments', lazy=True))
    
    def to_dict(self):
        card_info = None
        if self.card:
            card_info = {
                'id': self.card.id,
                'label': self.card.label,
                'bank_name': self.card.bank_name,
                'masked_card': self.card.masked_card()
            }
        
        admin_info = None
        if self.admin:
            admin_info = {
                'id': self.admin.id,
                'username': self.admin.username,
                'role': self.admin.role
            }
        
        return {
            'id': self.id,
            'admin_id': self.admin_id,
            'admin': admin_info,
            'card_id': self.card_id,
            'card': card_info,
            'sender_card': self.sender_card,
            'sender_name': self.sender_name,
            'amount': self.amount,
            'payment_date': self.payment_date.isoformat() if self.payment_date else None,
            'payment_date_jalali': format_jalali(self.payment_date),
            'client_email': self.client_email,
            'description': self.description,
            'verified': self.verified,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class Transaction(db.Model):
    __tablename__ = 'transactions'
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admins.id'), nullable=False)
    server_id = db.Column(db.Integer, db.ForeignKey('servers.id'), nullable=True)
    card_id = db.Column(db.Integer, db.ForeignKey('bank_cards.id'), nullable=True)  # کارت مقصد (شما)
    sender_card = db.Column(db.String(32), nullable=True)  # شماره کارت مشتری
    sender_name = db.Column(db.String(120), nullable=True)  # نام فرستنده
    client_email = db.Column(db.String(100), nullable=True)  # ایمیل کلاینت مرتبط
    amount = db.Column(db.Integer, nullable=False)
    type = db.Column(db.String(20))
    category = db.Column(db.String(16), default='usage', nullable=False)  # 'income', 'expense', 'usage'
    description = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    server = db.relationship('Server', backref='transactions', lazy=True)
    card = db.relationship('BankCard', backref='transactions', lazy=True)
    
    def to_dict(self):
        admin_info = None
        if hasattr(self, 'admin') and self.admin:
            admin_info = {
                'id': self.admin.id,
                'username': self.admin.username,
                'role': self.admin.role
            }
        
        server_info = None
        if self.server:
            server_info = {
                'id': self.server.id,
                'name': self.server.name
            }
        
        card_info = None
        if self.card:
            card_info = {
                'id': self.card.id,
                'label': self.card.label,
                'bank_name': self.card.bank_name,
                'masked_card': self.card.masked_card()
            }
            
        return {
            'id': self.id,
            'admin_id': self.admin_id,
            'server_id': self.server_id,
            'server': server_info,
            'card_id': self.card_id,
            'card': card_info,
            'sender_card': self.sender_card,
            'sender_name': self.sender_name,
            'client_email': self.client_email,
            'amount': self.amount,
            'type': self.type,
            'description': self.description,
            'date': self.created_at.isoformat() if self.created_at else None,
            'date_jalali': format_jalali(self.created_at),
            'admin': admin_info
        }

class ClientPortalUser(db.Model):
    """End-user portal accounts — login with Iranian mobile + password."""
    __tablename__ = 'client_portal_users'
    id = db.Column(db.Integer, primary_key=True)
    mobile = db.Column(db.String(20), unique=True, nullable=False)   # normalised: +989xxxxxxxxx
    password_hash = db.Column(db.String(255), nullable=False)
    must_change_password = db.Column(db.Boolean, default=True)
    enabled = db.Column(db.Boolean, default=True)
    linked_email = db.Column(db.String(255))                         # x-ui client email (optional)
    display_name = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)

    def set_password(self, raw: str):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw: str) -> bool:
        return check_password_hash(self.password_hash, raw)

    def is_locked(self) -> bool:
        if self.locked_until and self.locked_until > datetime.utcnow():
            return True
        return False

    def record_failed(self):
        self.failed_attempts = (self.failed_attempts or 0) + 1
        if self.failed_attempts >= 5:
            self.locked_until = datetime.utcnow() + timedelta(minutes=15)

    def reset_failed(self):
        self.failed_attempts = 0
        self.locked_until = None


class ClientOwnership(db.Model):
    __tablename__ = 'client_ownerships'
    id = db.Column(db.Integer, primary_key=True)
    reseller_id = db.Column(db.Integer, db.ForeignKey('admins.id'), nullable=False)
    server_id = db.Column(db.Integer, db.ForeignKey('servers.id'), nullable=False)
    inbound_id = db.Column(db.Integer, nullable=True)
    client_email = db.Column(db.String(100), nullable=False)
    client_uuid = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    price = db.Column(db.Integer, default=0)
    
    reseller = db.relationship('Admin', backref=db.backref('clients', lazy=True))
    server = db.relationship('Server', backref=db.backref('owned_clients', lazy=True))

class PanelAPI(db.Model):
    __tablename__ = 'panel_apis'
    id = db.Column(db.Integer, primary_key=True)
    panel_type = db.Column(db.String(50), unique=True, nullable=False)  # 'sanaei', 'alireza', etc
    display_name = db.Column(db.String(100))
    login_endpoint = db.Column(db.String(100))
    
    # Inbound endpoints
    inbounds_list = db.Column(db.String(200))
    inbounds_get = db.Column(db.String(200))
    inbounds_add = db.Column(db.String(200))
    inbounds_update = db.Column(db.String(200))
    inbounds_delete = db.Column(db.String(200))
    
    # Client endpoints
    client_add = db.Column(db.String(200))
    client_update = db.Column(db.String(200))
    client_delete = db.Column(db.String(200))
    client_reset_traffic = db.Column(db.String(200))
    client_get_traffic = db.Column(db.String(200))
    
    # Server endpoints
    server_status = db.Column(db.String(200))
    server_restart = db.Column(db.String(200))
    server_stop = db.Column(db.String(200))
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'panel_type': self.panel_type,
            'display_name': self.display_name,
            'login_endpoint': self.login_endpoint,
            'inbounds_list': self.inbounds_list,
            'inbounds_get': self.inbounds_get,
            'client_add': self.client_add,
            'client_reset_traffic': self.client_reset_traffic
        }

def get_panel_api(panel_type):
    """Return PanelAPI config for given panel_type or None."""
    if not panel_type or panel_type == 'auto':
        return None
    return PanelAPI.query.filter_by(panel_type=panel_type).first()


# ---------------------------------------------------------------------------
# HealthLog model – stores health-check events & auto-heal action logs
# ---------------------------------------------------------------------------
class HealthLog(db.Model):
    __tablename__ = 'health_logs'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    level = db.Column(db.String(16), default='info')       # info / warning / error / critical
    category = db.Column(db.String(32), default='general')  # db / server / static / disk / general
    message = db.Column(db.Text, nullable=False)
    action_taken = db.Column(db.Text)                       # description of auto-heal action, if any
    details = db.Column(db.Text)                            # extra JSON payload
    resolved = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() + 'Z' if self.timestamp else None,
            'level': self.level,
            'category': self.category,
            'message': self.message,
            'action_taken': self.action_taken,
            'details': self.details,
            'resolved': self.resolved,
        }


def _add_health_log(level, category, message, action_taken=None, details=None, resolved=False):
    """Helper to insert a HealthLog row safely."""
    try:
        log_entry = HealthLog(
            level=level,
            category=category,
            message=message,
            action_taken=action_taken,
            details=json.dumps(details) if isinstance(details, (dict, list)) else details,
            resolved=resolved,
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        print(f"[HealthLog] Failed to write log: {exc}")


CLIENT_UPDATE_FALLBACKS = [
    "/panel/api/inbounds/updateClient/:clientId",
    "/panel/api/inbounds/:id/updateClient/:clientId",
    "/xui/API/inbounds/updateClient/:clientId",
    "/xui/inbound/updateClient/:clientId"
]

CLIENT_RESET_FALLBACKS = [
    "/panel/api/inbounds/:id/resetClientTraffic/:email",
    "/xui/API/inbounds/:id/resetClientTraffic/:email",
    "/xui/inbounds/:id/resetClientTraffic/:email",
    "/xui/inbound/:id/resetClientTraffic/:email"
]

CLIENT_DELETE_FALLBACKS = [
    "/panel/api/inbounds/:id/delClient/:clientId",
    "/xui/API/inbounds/:id/delClient/:clientId",
    "/xui/inbound/delClient/:clientId"
]


INBOUND_GET_FALLBACKS = [
    "/panel/api/inbounds/get/:id",
    "/xui/API/inbounds/get/:id",
    "/xui/inbound/get/:id",
    "/xui/inbounds/get/:id",
]


INBOUND_UPDATE_FALLBACKS = [
    "/panel/api/inbounds/update/:id",
    "/xui/API/inbounds/update/:id",
    "/xui/inbound/update/:id",
    "/xui/inbounds/update/:id",
]


def _json_field(value, default=None):
    """Parse an x-ui inbound field (settings / streamSettings / sniffing) that may
    arrive as a JSON-encoded STRING (x-ui v2 / Sanaei / Alireza) or as a nested
    JSON OBJECT (3x-ui v3+, which returns these fields already decoded).

    Returns a dict/list; falls back to `default` on anything unparseable.
    This is the single compatibility shim that lets the same code path work
    against both old and new panels.
    """
    if default is None:
        default = {}
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return default
        try:
            return json.loads(s)
        except Exception:
            return default
    return default


def collect_endpoint_templates(panel_type, attr_name, fallbacks):
    """Return ordered list of endpoint templates for the requested action."""
    templates = []

    normalized = (panel_type or 'auto').strip().lower()

    # If panel type is known, prefer its configured endpoint first.
    panel_api = get_panel_api(normalized)
    if panel_api:
        value = getattr(panel_api, attr_name, None)
        if value:
            templates.append(value)

    # Fast path: try hardcoded fallbacks early (especially important for panel_type='auto').
    for item in (fallbacks or []):
        if item and item not in templates:
            templates.append(item)

    # Finally, include any configured endpoints from other panel types.
    # This keeps compatibility with custom PanelAPI rows without making 'auto' slow.
    for api in PanelAPI.query.all():
        value = getattr(api, attr_name, None)
        if value and value not in templates:
            templates.append(value)

    return templates


def build_panel_url(host, template, replacements):
    if not template:
        return None
    endpoint = template
    for key, value in (replacements or {}).items():
        if value is None:
            continue
        safe_value = quote(str(value), safe='')
        endpoint = endpoint.replace(f":{key}", safe_value).replace(f"{{{key}}}", safe_value)
    if endpoint.startswith('http://') or endpoint.startswith('https://'):
        return endpoint
    base, webpath = extract_base_and_webpath(host)
    endpoint_clean = endpoint if endpoint.startswith('/') else f"/{endpoint}"
    return f"{base}{webpath}{endpoint_clean}"


# ── SSL auto-detection (defined early so startup context block can use it) ──

_SSL_KNOWN_PATHS = [
    # Copied by setup.sh / ssl/sync endpoint — evemgr-owned, always readable
    ('/etc/ssl/eve-manager/fullchain.pem', '/etc/ssl/eve-manager/privkey.pem'),
    # Self-signed via setup.sh
    ('/etc/ssl/eve-manager/cert.pem',      '/etc/ssl/eve-manager/privkey.pem'),
]

def _is_ip_address(value: str) -> bool:
    import re as _re
    return bool(_re.match(r'^(\d{1,3}\.){3}\d{1,3}$', (value or '').strip()))


def _nginx_conf_path() -> str:
    return '/etc/nginx/sites-available/eve-manager'


def _build_nginx_config(domain: str, app_port: str, cert_path: str = '', key_path: str = '') -> str:
    """Build nginx config for HTTP or HTTPS depending on whether cert paths are given."""
    sse_block = f"""
    location ~* /stream$ {{
        proxy_pass http://127.0.0.1:{app_port};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_http_version 1.1;
        proxy_set_header Connection '';
    }}"""
    proxy_block = f"""
    location / {{
        proxy_pass http://127.0.0.1:{app_port};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 600s;
        proxy_send_timeout 600s;
        proxy_request_buffering off;
    }}"""

    if cert_path and key_path:
        return f"""server {{
    listen 80;
    server_name {domain};
    return 301 https://$host$request_uri;
}}

server {{
    listen 443 ssl;
    server_name {domain};
    ssl_certificate     {cert_path};
    ssl_certificate_key {key_path};
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    client_max_body_size 512m;
{sse_block}
{proxy_block}
}}
"""
    else:
        return f"""server {{
    listen 80;
    server_name {domain};
    client_max_body_size 512m;
{sse_block}
{proxy_block}
}}
"""


def _apply_nginx_config(domain: str, cert_path: str = '', key_path: str = '') -> tuple[bool, str]:
    """Write nginx config and reload. Returns (ok, error_message)."""
    app_port = os.environ.get('API_PORT', '5000')
    config = _build_nginx_config(domain, app_port, cert_path, key_path)
    conf_path = _nginx_conf_path()

    cmds = [
        (['sudo', 'tee', conf_path], config),
        (['sudo', 'nginx', '-t'], None),
        (['sudo', 'systemctl', 'reload', 'nginx'], None),
    ]
    for cmd, stdin in cmds:
        r = subprocess.run(cmd, input=stdin, text=True, capture_output=True, timeout=15)
        if r.returncode != 0:
            return False, f'{" ".join(cmd[:2])} failed: {r.stderr.strip()}'
    return True, ''


def _autodetect_ssl_paths():
    """Return (cert_path, key_path) from well-known locations, or ('', '').

    Detection order:
    1. Known static paths under /etc/ssl/eve-manager/ (evemgr-readable)
    2. Nginx config ssl_certificate directive (most reliable)
    3. Let's Encrypt live glob
    """
    for cert_cand, key_cand in _SSL_KNOWN_PATHS:
        if os.path.isfile(cert_cand) and os.path.isfile(key_cand):
            return cert_cand, key_cand

    # Read nginx config to discover paths
    try:
        import re as _re
        _service = os.environ.get('SERVICE_NAME', 'eve-manager')
        _nginx_candidates = [
            f'/etc/nginx/sites-available/{_service}',
            f'/etc/nginx/sites-enabled/{_service}',
            '/etc/nginx/sites-available/eve-manager',
            '/etc/nginx/sites-available/eve-xui-manager',
            '/etc/nginx/sites-enabled/eve-manager',
            '/etc/nginx/conf.d/eve-manager.conf',
        ]
        for _nc in _nginx_candidates:
            if not os.path.isfile(_nc):
                continue
            try:
                with open(_nc, 'r', errors='ignore') as _nf:
                    _conf = _nf.read()
                _cm = _re.search(r'ssl_certificate\s+([^;]+);', _conf)
                _km = _re.search(r'ssl_certificate_key\s+([^;]+);', _conf)
                if _cm and _km:
                    _det_cert = _cm.group(1).strip()
                    _det_key = _km.group(1).strip()
                    # Only return if actually readable by the current process
                    if os.path.isfile(_det_cert) and os.access(_det_cert, os.R_OK) \
                            and os.path.isfile(_det_key) and os.access(_det_key, os.R_OK):
                        return _det_cert, _det_key
            except Exception:
                continue
    except Exception:
        pass

    # Let's Encrypt glob fallback (may fail due to permissions on privkey)
    try:
        import glob as _glob
        for _le_cert in sorted(_glob.glob('/etc/letsencrypt/live/*/fullchain.pem')):
            _le_key = os.path.join(os.path.dirname(_le_cert), 'privkey.pem')
            if os.path.isfile(_le_key) and os.access(_le_cert, os.R_OK) and os.access(_le_key, os.R_OK):
                return _le_cert, _le_key
    except Exception:
        pass

    return '', ''


with app.app_context():
    db.create_all()
    
    # Ensure expected columns exist on admins table (older DBs)
    try:
        inspector = inspect(db.engine)
        columns = [c['name'] for c in inspector.get_columns('admins')]
        print(f"Current columns in admins: {columns}")

        _is_pg = db.engine.dialect.name == 'postgresql'
        admin_missing_cols = [
            ('telegram_id',           'VARCHAR(100)'),
            ('support_telegram',      'VARCHAR(100)'),
            ('support_whatsapp',      'VARCHAR(64)'),
            ('channel_telegram',      'TEXT'),
            ('channel_whatsapp',      'TEXT'),
            ('allow_negative_credit', 'BOOLEAN DEFAULT FALSE' if _is_pg else 'BOOLEAN DEFAULT 0'),
            ('negative_credit_limit', 'INTEGER DEFAULT 0'),
            ('sub_shown_package_ids', "TEXT DEFAULT '[]'"),
            ('support_sms', 'VARCHAR(64)'),
        ]

        for col_name, col_type in admin_missing_cols:
            if col_name in columns:
                continue
            print(f"{col_name} column missing on admins, attempting to add...")
            try:
                with db.engine.connect() as conn:
                    conn.execute(text(f'ALTER TABLE admins ADD COLUMN {col_name} {col_type}'))
                    conn.commit()
                print(f"Added {col_name} column to admins table")
            except Exception as _col_err:
                print(f"Migration error ({col_name}): {_col_err}")
    except Exception as e:
        print(f"Migration error: {e}")

    # Ensure announcements columns exist — each in its own try so one failure
    # doesn't prevent the others from running.
    def _ensure_ann_col(col_name, col_type):
        try:
            inspector = inspect(db.engine)
            if 'announcements' not in set(inspector.get_table_names()):
                return
            cols = [c['name'] for c in inspector.get_columns('announcements')]
            if col_name in cols:
                return
            with db.engine.connect() as conn:
                conn.execute(text(f'ALTER TABLE announcements ADD COLUMN {col_name} {col_type}'))
                conn.commit()
            print(f"Migration: added announcements.{col_name}")
        except Exception as _e:
            print(f"Migration error (announcements.{col_name}): {_e}")

    _is_pg = db.engine.dialect.name == 'postgresql'
    _bool_def = 'BOOLEAN DEFAULT FALSE' if _is_pg else 'BOOLEAN DEFAULT 0'
    _ensure_ann_col('hide_from_resellers', _bool_def)
    _ensure_ann_col('is_popup',            _bool_def)
    _ensure_ann_col('button_text',         'VARCHAR(120)')

    # Ensure owner_id exists on notification_templates (per-reseller templates)
    try:
        inspector = inspect(db.engine)
        nt_cols = [c['name'] for c in inspector.get_columns('notification_templates')]
        if 'owner_id' not in nt_cols:
            print("owner_id column missing on notification_templates, adding...")
            with db.engine.connect() as conn:
                conn.execute(text('ALTER TABLE notification_templates ADD COLUMN owner_id INTEGER REFERENCES admins(id)'))
                conn.commit()
            print("Added owner_id to notification_templates")
    except Exception as e:
        print(f"Migration error (notification_templates.owner_id): {e}")

    # Ensure sender_name exists on transactions table (older DBs)
    try:
        inspector = inspect(db.engine)
        tx_columns = [c['name'] for c in inspector.get_columns('transactions')]
        if 'sender_name' not in tx_columns:
            print("sender_name column missing on transactions, attempting to add...")
            with db.engine.connect() as conn:
                conn.execute(text('ALTER TABLE transactions ADD COLUMN sender_name VARCHAR(120)'))
                conn.commit()
            print("Added sender_name column to transactions table")
    except Exception as e:
        print(f"Migration error (transactions.sender_name): {e}")

    # Ensure servers.hidden column exists (added for server hide/show feature)
    try:
        inspector = inspect(db.engine)
        srv_cols = [c['name'] for c in inspector.get_columns('servers')]
        if 'hidden' not in srv_cols:
            with db.engine.connect() as conn:
                conn.execute(text('ALTER TABLE servers ADD COLUMN hidden BOOLEAN DEFAULT FALSE'))
                conn.commit()
            print("Added hidden column to servers table")
        if 'api_token' not in srv_cols:
            with db.engine.connect() as conn:
                conn.execute(text('ALTER TABLE servers ADD COLUMN api_token VARCHAR(255)'))
                conn.commit()
            print("Added api_token column to servers table")
    except Exception as e:
        print(f"Migration error (servers.hidden/api_token): {e}")

    # Ensure system_configs.value can store long URLs (PostgreSQL only)
    try:
        if db.engine.dialect.name == 'postgresql':
            with db.engine.connect() as conn:
                conn.execute(text('ALTER TABLE system_configs ALTER COLUMN value TYPE TEXT'))
                conn.commit()
            print("Ensured system_configs.value is TEXT")
    except Exception as e:
        print(f"Migration error (system_configs.value TEXT): {e}")

    # Ensure announcements.targets exists (SQLite old DBs)
    try:
        inspector = inspect(db.engine)
        tables = set(inspector.get_table_names() or [])
        if 'announcements' in tables:
            ann_columns = [c['name'] for c in inspector.get_columns('announcements')]
            if 'targets' not in ann_columns:
                print("announcements.targets column missing, attempting to add...")
                with db.engine.connect() as conn:
                    conn.execute(text('ALTER TABLE announcements ADD COLUMN targets TEXT'))
                    conn.commit()
                print("Added targets column to announcements table")
    except Exception as e:
        print(f"Migration error (announcements.targets): {e}")
    
    # Auto-detect SSL paths at startup if DB is empty (handles case where setup.sh ran but Flask hadn't started)
    try:
        _c = db.session.get(SystemSetting, 'ssl_cert_path')
        _k = db.session.get(SystemSetting, 'ssl_key_path')
        if not (_c and _c.value) and not (_k and _k.value):
            _det_cert, _det_key = _autodetect_ssl_paths()
            if _det_cert and _det_key:
                db.session.merge(SystemSetting(key='ssl_cert_path', value=_det_cert))
                db.session.merge(SystemSetting(key='ssl_key_path', value=_det_key))
                db.session.commit()
                print(f"[startup] Auto-detected SSL paths: {_det_cert}")
    except Exception as _ssl_e:
        print(f"[startup] SSL auto-detect error: {_ssl_e}")

    # Ensure packages table has extended columns (scope, assigned_reseller_ids, etc.)
    try:
        inspector = inspect(db.engine)
        if 'packages' in set(inspector.get_table_names()):
            _pkg_cols = [c['name'] for c in inspector.get_columns('packages')]
            # TIMESTAMP works in both PostgreSQL and SQLite; DATETIME is SQLite-only
            _ts_type = 'TIMESTAMP' if db.engine.dialect.name == 'postgresql' else 'DATETIME'
            _pkg_new = [
                ('scope', "VARCHAR(20) DEFAULT 'global'"),
                ('assigned_reseller_ids', "TEXT DEFAULT '[]'"),
                ('created_by', 'INTEGER'),
                ('display_order', 'INTEGER DEFAULT 0'),
                ('show_on_sub', 'BOOLEAN DEFAULT FALSE' if _is_pg else 'BOOLEAN DEFAULT 0'),
                ('created_at', _ts_type),
                ('updated_at', _ts_type),
            ]
            for _cn, _cd in _pkg_new:
                if _cn not in _pkg_cols:
                    with db.engine.connect() as _conn:
                        _conn.execute(text(f'ALTER TABLE packages ADD COLUMN {_cn} {_cd}'))
                        _conn.commit()
    except Exception as _pe:
        print(f"Migration error (packages extended columns): {_pe}")

    # Ensure price_tiers supports assigning one dynamic rule to multiple resellers.
    try:
        inspector = inspect(db.engine)
        if 'price_tiers' in set(inspector.get_table_names()):
            _tier_cols = [c['name'] for c in inspector.get_columns('price_tiers')]
            if 'assigned_reseller_ids' not in _tier_cols:
                with db.engine.connect() as _conn:
                    _conn.execute(text("ALTER TABLE price_tiers ADD COLUMN assigned_reseller_ids TEXT DEFAULT '[]'"))
                    _conn.commit()
    except Exception as _te:
        print(f"Migration error (price_tiers assigned_reseller_ids): {_te}")

    # Add inbound_tag to usage_snapshots (older DBs)
    try:
        inspector = inspect(db.engine)
        if 'usage_snapshots' in set(inspector.get_table_names()):
            _snap_cols = [c['name'] for c in inspector.get_columns('usage_snapshots')]
            if 'inbound_tag' not in _snap_cols:
                with db.engine.connect() as _conn:
                    _conn.execute(text('ALTER TABLE usage_snapshots ADD COLUMN inbound_tag VARCHAR(256)'))
                    _conn.commit()
                print("Added inbound_tag column to usage_snapshots table")
    except Exception as _spe:
        print(f"Migration error (usage_snapshots.inbound_tag): {_spe}")

    # Add icon_url and is_recommended to sub_app_configs (older DBs)
    try:
        inspector = inspect(db.engine)
        if 'sub_app_configs' in set(inspector.get_table_names()):
            _sac_cols = [c['name'] for c in inspector.get_columns('sub_app_configs')]
            _is_pg = db.engine.dialect.name == 'postgresql'
            _sac_new = [
                ('icon_url', 'VARCHAR(500)'),
                ('is_recommended', 'BOOLEAN DEFAULT FALSE' if _is_pg else 'BOOLEAN DEFAULT 0'),
                ('display_order', 'INTEGER DEFAULT 0'),
            ]
            for _cn, _cd in _sac_new:
                if _cn not in _sac_cols:
                    with db.engine.connect() as _conn:
                        _conn.execute(text(f'ALTER TABLE sub_app_configs ADD COLUMN {_cn} {_cd}'))
                        _conn.commit()
                    print(f"Added {_cn} column to sub_app_configs table")
    except Exception as _sac_e:
        print(f"Migration error (sub_app_configs new cols): {_sac_e}")

    # Initialize PanelAPI data
    if not PanelAPI.query.first():
        panel_apis = [
            PanelAPI(
                panel_type='sanaei',
                display_name='3X-UI (Sanaei)',
                login_endpoint='/login',
                inbounds_list='/panel/api/inbounds/list',
                inbounds_get='/panel/api/inbounds/get/:id',
                inbounds_add='/panel/api/inbounds/add',
                inbounds_update='/panel/api/inbounds/update/:id',
                inbounds_delete='/panel/api/inbounds/del/:id',
                client_add='/panel/api/inbounds/addClient',
                client_update='/panel/api/inbounds/updateClient/:clientId',
                client_delete='/panel/api/inbounds/:id/delClient/:clientId',
                client_reset_traffic='/panel/api/inbounds/:id/resetClientTraffic/:email',
                client_get_traffic='/panel/api/inbounds/getClientTraffics/:email',
                server_status='/panel/api/server/status',
                server_restart='/panel/api/server/restartXrayService',
                server_stop='/panel/api/server/stopXrayService'
            ),
            PanelAPI(
                panel_type='alireza',
                display_name='X-UI (Alireza)',
                login_endpoint='/login',
                inbounds_list='/xui/API/inbounds/',
                inbounds_get='/xui/API/inbounds/get/:id',
                inbounds_add='/xui/API/inbounds/add',
                inbounds_update='/xui/API/inbounds/update/:id',
                inbounds_delete='/xui/API/inbounds/del/:id',
                client_add='/xui/API/inbounds/addClient/',
                client_update='/xui/API/inbounds/updateClient/:clientId',
                client_delete='/xui/API/inbounds/:id/delClient/:clientId',
                client_reset_traffic='/xui/API/inbounds/:id/resetClientTraffic/:email',
                client_get_traffic='/xui/API/inbounds/getClientTraffics/:email',
                server_status='/xui/API/server/status',
                server_restart='/xui/API/server/restartXrayService',
                server_stop='/xui/API/server/stopXrayService'
            )
        ]
        db.session.add_all(panel_apis)
    
    if Admin.query.count() == 0:
        initial_username = os.environ.get("INITIAL_ADMIN_USERNAME", "admin")
        default_admin = Admin(
            username=initial_username,
            is_superadmin=True,
            role='superadmin',
            enabled=True,
            allowed_servers='*'
        )
        initial_password = os.environ.get("INITIAL_ADMIN_PASSWORD")
        if not initial_password:
            initial_password = secrets.token_urlsafe(12)
            print("\n" + "!"*60)
            print("  CRITICAL SECURITY NOTICE")
            print(f"  Initial admin created with username: {initial_username}")
            print(f"  Generated secure password: {initial_password}")
            print("  PLEASE SAVE THIS PASSWORD IMMEDIATELY!")
            print("!"*60 + "\n")
            
        default_admin.set_password(initial_password)
        db.session.add(default_admin)
        
        if not SubAppConfig.query.first():
            apps_list = [
                # Android
                SubAppConfig(app_code='v2rayng', name='v2rayNG', os_type='android', title_fa='راهنمای v2rayNG', description_fa='۱. برنامه را دانلود کنید.\n۲. لینک سابسکریپشن را کپی کنید.\n۳. در برنامه روی + بزنید و Import from clipboard را انتخاب کنید.', title_en='v2rayNG Guide', description_en='1. Download the app.\n2. Copy the subscription link.\n3. Tap + then "Import from clipboard".', download_link='https://github.com/2dust/v2rayNG/releases/latest', store_link='https://play.google.com/store/apps/details?id=com.v2ray.ang'),
                SubAppConfig(app_code='nekobox', name='NekoBox', os_type='android', title_fa='راهنمای NekoBox', description_fa='۱. برنامه را نصب کنید.\n۲. از منو Profiles را انتخاب کنید.\n۳. روی + بزنید و Add from URL را انتخاب کنید.', title_en='NekoBox Guide', description_en='1. Install the app.\n2. Open Profiles from the menu.\n3. Tap + and select "Add from URL".', download_link='https://github.com/MatsuriDayo/NekoBoxForAndroid/releases/latest'),
                SubAppConfig(app_code='hiddify', name='Hiddify', os_type='android', title_fa='راهنمای Hiddify', description_fa='۱. برنامه را نصب کنید.\n۲. روی Add Profile بزنید.\n۳. لینک سابسکریپشن را وارد کنید.', title_en='Hiddify Guide', description_en='1. Install the app.\n2. Tap Add Profile.\n3. Enter the subscription link.', store_link='https://play.google.com/store/apps/details?id=app.hiddify.com', download_link='https://github.com/hiddify/hiddify-app/releases/latest'),
                SubAppConfig(app_code='v2raytun', name='V2RayTun', os_type='android', title_fa='راهنمای V2RayTun', description_fa='۱. برنامه را نصب کنید.\n۲. لینک ساب را اضافه کنید.', title_en='V2RayTun Guide', description_en='1. Install the app.\n2. Add the subscription link.', store_link='https://play.google.com/store/apps/details?id=com.v2raytun.android'),
                SubAppConfig(app_code='matsuri', name='Matsuri', os_type='android', title_fa='راهنمای Matsuri', description_fa='۱. برنامه را نصب کنید.\n۲. لینک ساب را اضافه کنید.', title_en='Matsuri Guide', description_en='1. Install the app.\n2. Add the subscription link.', download_link='https://github.com/MatsuriDayo/Matsuri/releases/latest'),
                SubAppConfig(app_code='surfboard', name='Surfboard', os_type='android', title_fa='راهنمای Surfboard', description_fa='۱. برنامه را نصب کنید.\n۲. Config را Import کنید.', title_en='Surfboard Guide', description_en='1. Install the app.\n2. Import config.', store_link='https://play.google.com/store/apps/details?id=com.getsurfboard'),
                # iOS
                SubAppConfig(app_code='streisand', name='Streisand', os_type='ios', title_fa='راهنمای Streisand', description_fa='۱. از App Store نصب کنید.\n۲. روی + بزنید و URL را وارد کنید.', title_en='Streisand Guide', description_en='1. Install from App Store.\n2. Tap + and enter the subscription URL.', store_link='https://apps.apple.com/us/app/streisand/id6450534064'),
                SubAppConfig(app_code='shadowrocket', name='Shadowrocket', os_type='ios', title_fa='راهنمای Shadowrocket', description_fa='۱. از App Store نصب کنید (نیاز به اکانت خارجی).\n۲. روی + بزنید، Type را Subscribe انتخاب کنید و URL را وارد کنید.', title_en='Shadowrocket Guide', description_en='1. Install from App Store (requires foreign account).\n2. Tap +, select Type: Subscribe, enter the URL.', store_link='https://apps.apple.com/us/app/shadowrocket/id932747118'),
                SubAppConfig(app_code='foxray', name='FoXray', os_type='ios', title_fa='راهنمای FoXray', description_fa='۱. از App Store نصب کنید.\n۲. لینک ساب را اضافه کنید.', title_en='FoXray Guide', description_en='1. Install from App Store.\n2. Add the subscription link.', store_link='https://apps.apple.com/us/app/foxray/id6448898396'),
                SubAppConfig(app_code='v2box', name='v2Box', os_type='ios', title_fa='راهنمای v2Box', description_fa='۱. از App Store نصب کنید.\n۲. لینک ساب را اضافه کنید.', title_en='v2Box Guide', description_en='1. Install from App Store.\n2. Add the subscription link.', store_link='https://apps.apple.com/us/app/v2box-v2ray-client/id6446814690'),
                SubAppConfig(app_code='hiddify-ios', name='Hiddify (iOS)', os_type='ios', title_fa='راهنمای Hiddify آیفون', description_fa='۱. از App Store نصب کنید.\n۲. روی Add Profile بزنید و لینک را وارد کنید.', title_en='Hiddify iOS Guide', description_en='1. Install from App Store.\n2. Tap Add Profile and enter the link.', store_link='https://apps.apple.com/us/app/hiddify-proxy-vpn/id6596777532'),
                # Windows
                SubAppConfig(app_code='v2rayn', name='v2rayN', os_type='windows', title_fa='راهنمای v2rayN', description_fa='۱. از گیتهاب دانلود کنید.\n۲. برنامه را اجرا کنید.\n۳. از منو Servers > Add subscription server را انتخاب کنید و URL را وارد کنید.', title_en='v2rayN Guide', description_en='1. Download from GitHub.\n2. Run the app.\n3. Go to Servers > Add subscription server and enter the URL.', download_link='https://github.com/2dust/v2rayN/releases/latest'),
                SubAppConfig(app_code='nekoray', name='Nekoray', os_type='windows', title_fa='راهنمای Nekoray', description_fa='۱. از گیتهاب دانلود کنید.\n۲. از منو Program > Add profile from URL استفاده کنید.', title_en='Nekoray Guide', description_en='1. Download from GitHub.\n2. Use Program > Add profile from URL.', download_link='https://github.com/MatsuriDayo/nekoray/releases/latest'),
                SubAppConfig(app_code='clashverge', name='Clash Verge Rev', os_type='windows', title_fa='راهنمای Clash Verge', description_fa='۱. دانلود و نصب کنید.\n۲. روی Profiles بزنید و URL را وارد کنید.', title_en='Clash Verge Guide', description_en='1. Download and install.\n2. Click Profiles and enter the URL.', download_link='https://github.com/clash-verge-rev/clash-verge-rev/releases/latest'),
                SubAppConfig(app_code='flclash', name='FlClash', os_type='windows', title_fa='راهنمای FlClash', description_fa='۱. دانلود و نصب کنید.\n۲. پروفایل را اضافه کنید.', title_en='FlClash Guide', description_en='1. Download and install.\n2. Add profile.', download_link='https://github.com/chen08209/FlClash/releases/latest'),
                # Desktop (multi-platform)
                SubAppConfig(app_code='hiddify-desktop', name='Hiddify Desktop', os_type='desktop', title_fa='راهنمای Hiddify دسکتاپ', description_fa='۱. دانلود و نصب کنید.\n۲. روی Add Profile بزنید و لینک ساب را وارد کنید.', title_en='Hiddify Desktop Guide', description_en='1. Download and install.\n2. Tap Add Profile and enter the subscription link.', download_link='https://github.com/hiddify/hiddify-app/releases/latest'),
                SubAppConfig(app_code='v2raya', name='v2rayA', os_type='desktop', title_fa='راهنمای v2rayA', description_fa='رابط وب‌محور. پس از نصب از مرورگر باز کنید.', title_en='v2rayA Guide', description_en='Web-based UI. Open in browser after installation.', download_link='https://github.com/v2rayA/v2rayA/releases/latest'),
                SubAppConfig(app_code='sing-box', name='sing-box', os_type='desktop', title_fa='راهنمای sing-box', description_fa='کلاینت چندپلتفرمی با پشتیبانی گسترده از پروتکل‌ها.', title_en='sing-box Guide', description_en='Multi-platform client with broad protocol support.', download_link='https://github.com/SagerNet/sing-box/releases/latest'),
            ]
            db.session.add_all(apps_list)
        
        if not SystemConfig.query.filter_by(key='cost_per_gb').first():
            db.session.add(SystemConfig(key='cost_per_gb', value='2000'))
        if not SystemConfig.query.filter_by(key='cost_per_day').first():
            db.session.add(SystemConfig(key='cost_per_day', value='500'))
        
        db.session.commit()

# --- HELPERS ---

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            # For API endpoints, AJAX/XHR requests, or requests that accept JSON, return JSON errors
            is_api_path = request.path.startswith('/api/')
            accepts_json = 'application/json' in (request.headers.get('Accept') or '')
            is_xhr = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json
            if is_api_path or accepts_json or is_xhr:
                return jsonify({"success": False, "error": "Unauthorized"}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def client_portal_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'client_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def superadmin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            return jsonify({"success": False, "error": "Unauthorized"}), 401
        admin = db.session.get(Admin, session['admin_id'])
        if not admin or (admin.role != 'superadmin' and not admin.is_superadmin):
            return jsonify({"success": False, "error": "Access Denied: SuperAdmin only"}), 403
        return f(*args, **kwargs)
    return decorated_function


def user_management_required(f):
    """Allow admins and superadmins to manage users.

    Blocks reseller accounts.
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            return jsonify({"success": False, "error": "Unauthorized"}), 401
        editor = db.session.get(Admin, session['admin_id'])
        if not editor:
            return jsonify({"success": False, "error": "Unauthorized"}), 401
        if editor.role == 'reseller':
            return jsonify({"success": False, "error": "Access Denied"}), 403
        return f(*args, **kwargs)

    return decorated_function


def _normalize_username(raw: str | None) -> str:
    username = (raw or '').strip().lower()
    username = re.sub(r'\s+', '', username)
    username = re.sub(r'[\u0600-\u06FF]', '', username)
    return username


def _validate_username(username: str) -> str | None:
    if not username:
        return 'Username is required'
    if ' ' in username:
        return 'Username cannot contain spaces'
    if any(u'\u0600' <= c <= u'\u06FF' for c in username):
        return 'Persian characters are not allowed'
    return None


def ensure_reseller_allowed_for_assignment(reseller: 'Admin', server_id: int, inbound_id: int | None) -> None:
    """Ensure reseller.allowed_servers includes the given server+inbound.

    This keeps the "Allowed Servers" UI in sync with actual assignments.
    It only ever *adds* permissions; it does not remove them on unassign.
    """
    try:
        if not reseller or reseller.role != 'reseller':
            return
        if reseller.allowed_servers == '*':
            return

        sid = int(server_id)
        inb = int(inbound_id) if inbound_id is not None else None

        allowed_map = resolve_allowed_map(reseller.allowed_servers)
        if allowed_map == '*':
            return

        current = allowed_map.get(sid)
        if current == '*':
            return

        if inb is None:
            allowed_map[sid] = '*'
        else:
            cur_set = set()
            if isinstance(current, (set, list, tuple)):
                for v in current:
                    try:
                        cur_set.add(int(v))
                    except Exception:
                        continue
            cur_set.add(inb)
            allowed_map[sid] = cur_set

        payload = []
        for s, rule in allowed_map.items():
            if rule == '*':
                payload.append({'server_id': int(s), 'inbounds': '*'})
            else:
                try:
                    payload.append({'server_id': int(s), 'inbounds': sorted([int(v) for v in (rule or [])])})
                except Exception:
                    payload.append({'server_id': int(s), 'inbounds': []})

        reseller.allowed_servers = serialize_allowed_servers(payload)
    except Exception:
        # Best-effort; assignment should not fail because of permissions sync.
        return

def validate_password_strength(password):
    """
    Validates password strength:
    - Minimum 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number
    """
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"
    if not any(not c.isalnum() for c in password):
        return False, "Password must contain at least one special character"
    return True, None

def calculate_reseller_price(user, base_price=None, package=None, cost_type=None):
    """
    Calculate price for a reseller based on their settings.
    """
    if user.role != 'reseller':
        if package: return package.price
        return base_price if base_price is not None else 0

    # 1. Custom Plan Logic (Day/GB rates)
    if cost_type == 'day':
        if user.custom_cost_per_day is not None:
            return user.custom_cost_per_day
        discount = user.discount_percent or 0
        return int(base_price * (1 - discount / 100)) if base_price else 0
        
    if cost_type == 'gb':
        if user.custom_cost_per_gb is not None:
            return user.custom_cost_per_gb
        discount = user.discount_percent or 0
        return int(base_price * (1 - discount / 100)) if base_price else 0

    # 2. Package Logic
    if package:
        # Priority 1: Reseller Price on Package (Global Reseller Price)
        # If a specific reseller price is set on the package, use it.
        # However, if the user has a specific discount, maybe they want discount off the standard price?
        # Let's assume: Reseller Price is a fixed override.
        if package.reseller_price is not None and package.reseller_price > 0:
             # If user has a discount, we might want to apply it to the standard price and compare?
             # Or just take the reseller price.
             # Let's stick to: Reseller Price > Discounted Standard Price.
             return package.reseller_price
            
        # Priority 2: Discount on Standard Price
        discount = user.discount_percent or 0
        return int(package.price * (1 - discount / 100))

    return base_price if base_price is not None else 0

def _build_sub_page_packages(owner) -> list[dict]:
    """Packages to surface on a customer's subscription page, based on the
    account OWNER. Only packages flagged show_on_sub are eligible.

    - Reseller-owned account: global + packages assigned to that reseller +
      the reseller's own packages, each priced with the reseller's pricing.
    - No reseller (system/admin-managed): only global packages, standard price.
    """
    import json as _j
    try:
        pkgs = Package.query.filter_by(enabled=True).order_by(Package.display_order, Package.id).all()
    except Exception:
        return []

    is_reseller = bool(owner and getattr(owner, 'role', None) == 'reseller')

    shown_ids = set()
    if is_reseller:
        try:
            shown_ids = set(int(x) for x in _j.loads(owner.sub_shown_package_ids or '[]'))
        except Exception:
            shown_ids = set()

    out = []
    for p in pkgs:
        scope = p.scope or 'global'
        if is_reseller:
            if p.created_by == owner.id:
                # Reseller's own package — controlled by its own show_on_sub flag.
                if not getattr(p, 'show_on_sub', False):
                    continue
                price = p.price
            else:
                # Global or assigned-to-reseller package — the reseller decides
                # per-package whether to surface it (default hidden).
                if scope == 'global':
                    visible = True
                elif scope == 'assigned':
                    try:
                        ids = _j.loads(p.assigned_reseller_ids or '[]')
                    except Exception:
                        ids = []
                    visible = owner.id in ids
                else:
                    visible = False
                if not visible or p.id not in shown_ids:
                    continue
                price = calculate_reseller_price(owner, package=p)
        else:
            # System/admin-managed account: only global packages the admin ticked.
            if scope != 'global' or not getattr(p, 'show_on_sub', False):
                continue
            price = p.price
        out.append({
            'id': p.id,
            'name': p.name,
            'days': int(p.days or 0),
            'volume': int(p.volume or 0),
            'price': int(price or 0),
        })
    return out


def get_config(key, default=0):
    conf = db.session.get(SystemConfig, key)
    return int(conf.value) if conf else default

def log_transaction(user_id, amount, type, desc, server_id=None, card_id=None, sender_card=None, category='usage', client_email=None):
    trans = Transaction(
        admin_id=user_id,
        amount=amount,
        type=type,
        description=desc,
        server_id=server_id,
        card_id=card_id,
        sender_card=sender_card,
        category=category,
        client_email=client_email
    )
    db.session.add(trans)

@app.context_processor
def inject_wallet_credit():
    wallet_credit = 0
    app_timezone = DEFAULT_APP_TIMEZONE
    panel_lang = 'en'
    admin_id = session.get('admin_id')
    if admin_id:
        user = db.session.get(Admin, admin_id)
        if user:
            wallet_credit = user.credit or 0
    try:
        app_timezone = _get_app_timezone_name()
    except Exception:
        app_timezone = DEFAULT_APP_TIMEZONE

    try:
        panel_lang = _get_panel_ui_lang()
    except Exception:
        panel_lang = 'en'

    return {
        "wallet_credit": wallet_credit,
        "app_timezone": app_timezone,
        "panel_lang": panel_lang,
        "panel_dir": ('rtl' if panel_lang == 'fa' else 'ltr'),
    }

def format_jalali(dt):
    if not dt:
        return None
    try:
        dt_local = _to_app_timezone(dt)
        if not dt_local:
            return None
        jalali_date = jdatetime_class.fromgregorian(datetime=dt_local.replace(tzinfo=None))
        return jalali_date.strftime('%Y/%m/%d %H:%M')
    except Exception:
        return dt.isoformat() if dt else None

EMAIL_IN_DESCRIPTION = re.compile(r'([A-Za-z0-9_.+-]+@[A-Za-z0-9-]+\.[A-Za-z0-9-.]+)$')

_DIGIT_TRANSLATION = str.maketrans({
    '۰': '0', '۱': '1', '۲': '2', '۳': '3', '۴': '4', '۵': '5', '۶': '6', '۷': '7', '۸': '8', '۹': '9',
    '٠': '0', '١': '1', '٢': '2', '٣': '3', '٤': '4', '٥': '5', '٦': '6', '٧': '7', '٨': '8', '٩': '9',
})


def parse_amount_to_int(value):
    """Parse amount input to int.

    Accepts strings with commas/spaces and Persian/Arabic digits.
    Returns None if cannot parse.
    """
    if value is None:
        return None
    try:
        if isinstance(value, (int, float)):
            return int(value)
        s = str(value).strip()
        if not s:
            return None
        s = s.translate(_DIGIT_TRANSLATION)
        # Keep digits only (strip separators/currency)
        s = re.sub(r'[^0-9]', '', s)
        if not s:
            return None
        return int(s)
    except Exception:
        return None

def extract_email_from_description(description):
    if not description:
        return None
    match = EMAIL_IN_DESCRIPTION.search(description.strip())
    if not match:
        return None
    email = match.group(1).strip().lower()
    return email.rstrip('.,;') or None

def parse_jalali_date(date_str, end_of_day=False):
    if not date_str:
        return None
    normalized = date_str.strip()
    if not normalized:
        return None
    patterns = ['%Y/%m/%d %H:%M', '%Y-%m-%d %H:%M', '%Y/%m/%d', '%Y-%m-%d']
    for pattern in patterns:
        try:
            j_date = jdatetime_class.strptime(normalized, pattern)
            gregorian = j_date.togregorian()
            dt = None
            if 'H' not in pattern:
                day = gregorian.date()
                time_part = datetime.max.time() if end_of_day else datetime.min.time()
                dt = datetime.combine(day, time_part)
            else:
                dt = gregorian
            
            # Convert Tehran to UTC (-3:30)
            return dt - timedelta(hours=3, minutes=30)
        except ValueError:
            continue
    return None

def parse_allowed_servers(raw_value):
    if not raw_value:
        return []
    if isinstance(raw_value, list):
        return raw_value
    normalized = str(raw_value).strip()
    if normalized == '*':
        return '*'
    if normalized.startswith('"') and normalized.endswith('"'):
        inner = normalized.strip('"')
        if inner == '*':
            return '*'
        # Attempt to decode double-encoded JSON strings
        try:
            decoded_inner = json.loads(inner)
            return decoded_inner if decoded_inner is not None else []
        except Exception:
            pass
    try:
        parsed = json.loads(normalized)
        if isinstance(parsed, str) and parsed.strip() == '*':
            return '*'
        return parsed if isinstance(parsed, list) else parsed
    except Exception:
        return []

def serialize_allowed_servers(value):
    """Serialize server/inbound permissions.

    Supports legacy formats (list of server ids or '*') and new structured
    payloads like [{'server_id': 1, 'inbounds': [10, 12]}, ...].
    """

    def _normalize_inbounds(val):
        if val is None:
            return '*'
        if val == '*' or (isinstance(val, str) and val.strip() == '*'):
            return '*'
        if isinstance(val, list):
            normalized = []
            for v in val:
                try:
                    normalized.append(int(v))
                except (TypeError, ValueError):
                    continue
            return normalized
        try:
            return [int(val)]
        except (TypeError, ValueError):
            return []

    if value == '*' or (isinstance(value, str) and value.strip() == '*'):
        return '*'

    # Parse JSON strings if provided
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return serialize_allowed_servers(parsed)
        except Exception:
            # Fallback for simple comma-separated server IDs
            parts = [p.strip() for p in value.split(',') if p.strip()]
            try:
                return serialize_allowed_servers([int(p) for p in parts])
            except Exception:
                return json.dumps([])

    if isinstance(value, dict):
        value = [value]

    normalized = []
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                server_id = item.get('server_id') or item.get('server') or item.get('id')
                try:
                    server_id = int(server_id)
                except (TypeError, ValueError):
                    continue
                inbounds = _normalize_inbounds(item.get('inbounds', '*'))
                normalized.append({'server_id': server_id, 'inbounds': '*' if inbounds == '*' else inbounds})
            else:
                try:
                    server_id = int(item)
                    normalized.append({'server_id': server_id, 'inbounds': '*'})
                except (TypeError, ValueError):
                    continue

    if not normalized:
        return json.dumps([])

    # Merge duplicates and keep unique inbound lists per server
    merged = {}
    for entry in normalized:
        sid = entry['server_id']
        inb = entry['inbounds']
        if sid not in merged:
            merged[sid] = inb
            continue
        existing = merged[sid]
        if existing == '*' or inb == '*':
            merged[sid] = '*'
        else:
            merged[sid] = sorted(list(set(existing) | set(inb)))

    final_list = [{'server_id': sid, 'inbounds': val} for sid, val in merged.items()]
    return json.dumps(final_list)

def resolve_allowed_servers(raw_value):
    """Backward-compatible resolver returning only server IDs or '*'."""
    allowed_map = resolve_allowed_map(raw_value)
    if allowed_map == '*':
        return '*'
    return list(allowed_map.keys())


def resolve_allowed_map(raw_value):
    """Return mapping of server_id -> inbound rule ('*' or set of ids)."""
    parsed = parse_allowed_servers(raw_value)
    if parsed == '*':
        return '*'

    allowed_map = {}
    items = parsed
    if isinstance(items, dict):
        items = [items]

    if isinstance(items, list):
        for item in items:
            if isinstance(item, dict):
                server_id = item.get('server_id') or item.get('server') or item.get('id')
                try:
                    server_id = int(server_id)
                except (TypeError, ValueError):
                    continue
                inbounds_raw = item.get('inbounds', '*')
                inbounds = set()
                if inbounds_raw == '*' or (isinstance(inbounds_raw, str) and inbounds_raw.strip() == '*'):
                    allowed_map[server_id] = '*'
                    continue
                if isinstance(inbounds_raw, list):
                    for v in inbounds_raw:
                        try:
                            inbounds.add(int(v))
                        except (TypeError, ValueError):
                            continue
                else:
                    try:
                        inbounds.add(int(inbounds_raw))
                    except (TypeError, ValueError):
                        pass
                allowed_map[server_id] = inbounds
            else:
                try:
                    sid = int(item)
                    allowed_map[sid] = '*'
                except (TypeError, ValueError):
                    continue
    return allowed_map


def get_reseller_access_maps(user):
    """Return (allowed_map, assignment_map) for a reseller user."""
    if not user or user.role != 'reseller':
        return '*', {}

    allowed_map = resolve_allowed_map(user.allowed_servers)
    assignments = defaultdict(set)

    ownerships = ClientOwnership.query.filter_by(reseller_id=user.id).all()
    for own in ownerships:
        try:
            sid = int(own.server_id)
        except (TypeError, ValueError):
            continue
        if own.inbound_id is not None:
            try:
                assignments[sid].add(int(own.inbound_id))
            except (TypeError, ValueError):
                continue

    return allowed_map, assignments


def is_server_accessible(server_id, allowed_map, assignments):
    if allowed_map == '*':
        return True
    if server_id in assignments:
        return True
    return server_id in allowed_map


def is_inbound_accessible(server_id, inbound_id, allowed_map, assignments):
    if allowed_map == '*':
        return True

    # Access via explicit assignment
    assigned = assignments.get(server_id, set())
    if '*' in assigned or inbound_id in assigned:
        return True

    server_rule = allowed_map.get(server_id)
    if server_rule == '*':
        return True
    if isinstance(server_rule, (set, list, tuple)):
        return inbound_id in server_rule
    return False

def parse_iso_datetime(value):
    if not value:
        return None
    try:
        if isinstance(value, datetime):
            return value
        return datetime.fromisoformat(value)
    except Exception:
        try:
            # fallback for "2024-12-01 12:00"
            return datetime.strptime(value, '%Y-%m-%d %H:%M')
        except Exception:
            return None

def allowed_receipt_file(file_storage):
    # Check extension
    if not file_storage or not file_storage.filename or '.' not in file_storage.filename:
        return False
    
    # Check actual file type (best-effort). On some platforms (notably Windows)
    # python-magic may be installed without libmagic, so we fall back to
    # extension-only checks instead of crashing the app.
    mime = None
    if magic is not None:
        try:
            file_bytes = file_storage.read(2048)
            file_storage.seek(0)
            mime = magic.from_buffer(file_bytes, mime=True)
        except Exception:
            mime = None
    
    allowed_mimes = {'image/jpeg', 'image/png', 'image/webp', 'image/heic', 'application/pdf'}
    
    ext = file_storage.filename.rsplit('.', 1)[1].lower()
    if ext not in RECEIPT_ALLOWED_EXTENSIONS:
        return False

    # If we couldn't detect MIME, allow based on extension only.
    if not mime:
        return True

    return mime in allowed_mimes

def save_receipt_file(file_storage):
    if not file_storage or not allowed_receipt_file(file_storage):
        return None
    ext = file_storage.filename.rsplit('.', 1)[1].lower()
    subdir = datetime.utcnow().strftime('%Y/%m')
    dest_dir = os.path.join(RECEIPTS_DIR, subdir)
    os.makedirs(dest_dir, exist_ok=True)
    unique_name = f"{uuid.uuid4().hex}.{ext}"
    safe_name = secure_filename(unique_name)
    relative_path = os.path.join('receipts', subdir, safe_name)
    full_path = os.path.join(app.instance_path, relative_path)
    file_storage.save(full_path)
    return relative_path

def get_active_auto_window(now=None):
    now = now or datetime.utcnow()
    return AutoApprovalWindow.query.filter(
        AutoApprovalWindow.status == 'enabled',
        AutoApprovalWindow.starts_at <= now,
        AutoApprovalWindow.ends_at >= now
    ).order_by(AutoApprovalWindow.ends_at.asc()).first()

def apply_receipt_credit(receipt, reviewer=None, auto=False):
    owner = db.session.get(Admin, receipt.admin_id)
    if not owner:
        return False, 'Owner not found'
    owner.credit = (owner.credit or 0) + receipt.amount
    tx_type = 'manual_receipt_auto' if auto else 'manual_receipt'
    description = f"Receipt #{receipt.id}"
    log_transaction(owner.id, receipt.amount, tx_type, description)
    receipt.status = RECEIPT_STATUS_AUTO_APPROVED if auto else RECEIPT_STATUS_APPROVED
    receipt.reviewed_at = datetime.utcnow()
    receipt.reviewer_id = reviewer.id if reviewer else None
    receipt.auto_deadline = None
    receipt.rejection_reason = None
    return True, None

def rollback_receipt_credit(receipt, reviewer=None, reason=None):
    owner = db.session.get(Admin, receipt.admin_id)
    if not owner:
        return False, 'Owner not found'
    owner.credit = (owner.credit or 0) - receipt.amount
    log_transaction(owner.id, -receipt.amount, 'manual_receipt_reversal', f"Receipt #{receipt.id} rejected")
    receipt.reviewer_id = reviewer.id if reviewer else None
    receipt.reviewed_at = datetime.utcnow()
    receipt.rejection_reason = reason
    return True, None

def trigger_auto_receipt_processing():
    now = datetime.utcnow()
    due_receipts = ManualReceipt.query.filter(
        ManualReceipt.status == RECEIPT_STATUS_AUTO_PENDING,
        ManualReceipt.auto_deadline.isnot(None),
        ManualReceipt.auto_deadline <= now
    ).all()
    updated = 0
    for receipt in due_receipts:
        success, err = apply_receipt_credit(receipt, reviewer=None, auto=True)
        if success:
            updated += 1
        else:
            receipt.status = RECEIPT_STATUS_PENDING
            receipt.auto_deadline = None
            receipt.rejection_reason = err
    if updated or due_receipts:
        db.session.commit()

def format_bytes(size):
    if size is None or size == 0: return "0 B"
    power = 2**10
    n = 0
    power_labels = {0: '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
    while size >= power and n < 4:
        size /= power
        n += 1
    return f"{size:.2f} {power_labels[n]}B"

def format_bytes_gb_tb(size):
    """Formats bytes to GB or TB only."""
    if size is None or size == 0: return "0 GB"
    
    gb_val = size / (1024**3)
    if gb_val >= 1024:
        tb_val = gb_val / 1024
        return f"{tb_val:.2f} TB"
    else:
        return f"{gb_val:.2f} GB"

def format_remaining_days(timestamp, lang: str = 'en'):
    is_fa = _normalize_ui_lang(lang, default='en') == 'fa'

    def _fmt_future(days: int, hours: int, minutes: int) -> str:
        if is_fa:
            parts = []
            if days > 0:
                parts.append(f"{days} روز")
            if hours > 0:
                parts.append(f"{hours} ساعت")
            if minutes > 0 and not parts:
                parts.append(f"{minutes} دقیقه")
            if not parts:
                return "امروز"
            return f"{' و '.join(parts)} باقی مانده"

        if days > 0 and hours > 0:
            return f"{days}d {hours}h left"
        if days > 0:
            return f"{days}d left"
        if hours > 0:
            return f"{hours}h left"
        if minutes > 0:
            return f"{minutes}m left"
        return "Today"

    def _fmt_expired(days_ago: int, hours_ago: int) -> str:
        if is_fa:
            if days_ago > 0 and hours_ago > 0:
                ago_label = f"{days_ago} روز و {hours_ago} ساعت پیش"
            elif days_ago > 0:
                ago_label = f"{days_ago} روز پیش"
            elif hours_ago > 0:
                ago_label = f"{hours_ago} ساعت پیش"
            else:
                ago_label = "لحظاتی پیش"
            return f"منقضی شده ({ago_label})"

        if days_ago > 0 and hours_ago > 0:
            ago_label = f"{days_ago}d {hours_ago}h ago"
        elif days_ago > 0:
            ago_label = f"{days_ago}d ago"
        elif hours_ago > 0:
            ago_label = f"{hours_ago}h ago"
        else:
            ago_label = "just now"
        return f"Expired ({ago_label})"

    # Some code paths (e.g. cached client objects) may pass expiry as string
    # like "Unlimited" or a numeric string. Normalize to int milliseconds.
    if isinstance(timestamp, str):
        ts = timestamp.strip()
        if not ts:
            timestamp = 0
        else:
            try:
                timestamp = int(float(ts))
            except Exception:
                # Non-numeric strings (e.g. "Unlimited", "Expired ...")
                timestamp = 0

    if timestamp == 0 or timestamp is None:
        return {"text": ("نامحدود" if is_fa else "Unlimited"), "days": -1, "type": "unlimited"}
    if timestamp < 0:
        days = abs(timestamp) // 86400000
        if is_fa:
            text = (f"{days} روز بعد از اولین اتصال" if days > 0 else "بعد از اولین اتصال")
        else:
            text = (f"Not started ({days} days)" if days > 0 else "Not started")
        return {"text": text, "days": days, "type": "start_after_use"}
    try:
        now_ms = int(time.time() * 1000)
        delta_ms = int(timestamp) - now_ms

        if delta_ms <= 0:
            past_ms = abs(delta_ms)
            days_ago = past_ms // 86400000
            hours_ago = (past_ms % 86400000) // 3600000
            return {"text": _fmt_expired(int(days_ago), int(hours_ago)), "days": -int(days_ago), "type": "expired"}

        days = delta_ms // 86400000
        hours = (delta_ms % 86400000) // 3600000
        minutes = (delta_ms % 3600000) // 60000

        text = _fmt_future(int(days), int(hours), int(minutes))

        if days == 0:
            return {"text": text, "days": 0, "type": "today"}
        if days < 7:
            return {"text": text, "days": int(days), "type": "soon"}
        return {"text": text, "days": int(days), "type": "normal"}
    except:
        return {"text": ("تاریخ نامعتبر" if is_fa else "Invalid Date"), "days": 0, "type": "error"}


def get_accessible_servers(user, include_disabled=False):
    if not user:
        return []
    query = Server.query
    if not include_disabled:
        query = query.filter_by(enabled=True)
    if user.role == 'reseller':
        allowed_map, assignments = get_reseller_access_maps(user)
        if allowed_map == '*':
            return query.all()

        server_ids = set(allowed_map.keys()) | set(assignments.keys())
        if not server_ids:
            return []
        return query.filter(Server.id.in_(server_ids)).all()
    return query.all()

def extract_base_and_webpath(host_url):
    """Extract base URL and webpath from panel URL.
    Example: http://1.2.3.4:8080/webpath/ -> (http://1.2.3.4:8080, /webpath)
    """
    from urllib.parse import urlparse
    parsed = urlparse(host_url.rstrip('/'))
    base = f"{parsed.scheme}://{parsed.netloc}"
    webpath = parsed.path.rstrip('/') if parsed.path and parsed.path != '/' else ''
    return base, webpath


def _safe_response_json(resp: requests.Response):
    """Best-effort JSON parse for upstream panel responses.

    Returns (data, error_message). Never raises JSONDecodeError.
    """
    try:
        raw = resp.content or b''
        if not raw:
            return None, f"Empty response (status {resp.status_code})"
        return resp.json(), None
    except Exception:
        try:
            content_type = (resp.headers.get('Content-Type') or '').split(';')[0].strip().lower()
        except Exception:
            content_type = ''
        try:
            text = (resp.text or '')
        except Exception:
            text = ''
        snippet = re.sub(r"\s+", " ", (text[:200] if text else '')).strip()
        if not snippet:
            snippet = '<no body>'
        return None, f"Non-JSON response (status {resp.status_code}, content-type {content_type}): {snippet}"


def _format_panel_connection_error(server, exc=None):
    """Return a short user-facing panel connection error.

    Raw requests exceptions include noisy pool/socket internals that are useful
    in logs but confusing in the UI.
    """
    try:
        base, _ = extract_base_and_webpath(getattr(server, 'host', '') or '')
    except Exception:
        base = getattr(server, 'host', '') or 'panel host'

    return (
        f"Panel connection timed out for {base}. "
        "The server panel is not reachable right now. "
        "Check panel URL/IP, port, firewall, web path and panel type."
    )


def get_server_api_token(server) -> str:
    """Decrypt the stored 3x-ui v3 API token (Bearer), or '' if none."""
    raw = getattr(server, 'api_token', '') or ''
    if not raw:
        return ''
    try:
        return decrypt_server_password(raw)
    except Exception:
        return raw


def server_is_v3(server) -> bool:
    """A server is treated as 3x-ui v3+ when it has an API token configured."""
    return bool(get_server_api_token(server))


# ── 3x-ui v3+ client API (/panel/api/clients/*) ──────────────────────────────
# In v3 the per-client inbound endpoints (updateClient/delClient/resetClientTraffic)
# were removed; clients are first-class and managed by email here. Verified live:
#   - update : POST /clients/update/{email}  body = bare client dict, id = uuid
#   - delete : POST /clients/del/{email}     (?keepTraffic=1 to keep stats)
#   - reset  : POST /clients/resetTraffic/{email}
#   - add    : POST /clients/add             body = {client, inboundIds}

def _v3_post(server, session_obj, path, json_body=None):
    """POST to a v3 /panel/api/* path. Returns (ok: bool, json|None, error|None)."""
    base, webpath = extract_base_and_webpath(server.host)
    url = f"{base}{webpath}{path}"
    try:
        resp = session_obj.post(url, json=(json_body if json_body is not None else {}),
                                verify=False, timeout=(3, 20))
    except Exception as e:
        return False, None, str(e)
    j, err = _safe_response_json(resp)
    if err:
        return False, None, err
    if resp.status_code == 200 and isinstance(j, dict) and j.get('success'):
        return True, j, None
    msg = (j.get('msg') or j.get('message')) if isinstance(j, dict) else None
    return False, j, (msg or f"HTTP {resp.status_code}")


def _v3_client_payload(client: dict) -> dict:
    """Shape a client dict for v3 /clients/update|add. v3 unmarshals Client.id as a
    string, so `id` must carry the UUID (not the numeric DB row id). Numeric fields
    must be numbers, not empty strings."""
    c = dict(client or {})
    uid = c.get('uuid') or c.get('id') or ''
    if uid:
        c['id'] = uid
    for k in ('tgId', 'limitIp', 'reset'):
        if c.get(k) in ('', None):
            c[k] = 0
    if isinstance(c.get('email'), str):
        c['email'] = _v3_sanitize_email(c['email'])
    return c


def _v3_sanitize_email(email: str) -> str:
    """v3 rejects emails containing spaces; strip them before every API call."""
    return (email or '').replace(' ', '')


def _v3_get(server, session_obj, path):
    """GET a v3 /panel/api/* path. Returns (ok: bool, json|None, error|None)."""
    base, webpath = extract_base_and_webpath(server.host)
    url = f"{base}{webpath}{path}"
    try:
        resp = session_obj.get(url, verify=False, timeout=(3, 20))
    except Exception as e:
        return False, None, str(e)
    j, err = _safe_response_json(resp)
    if err:
        return False, None, err
    if resp.status_code == 200 and isinstance(j, dict) and j.get('success'):
        return True, j, None
    msg = (j.get('msg') or j.get('message')) if isinstance(j, dict) else None
    return False, j, (msg or f"HTTP {resp.status_code}")


def _v3_get_client(server, session_obj, email):
    """Fetch one client via GET /clients/get/{email}. Returns the client dict or None."""
    ok, j, _err = _v3_get(server, session_obj,
                          f"/panel/api/clients/get/{quote(str(email or ''), safe='')}")
    if not ok or not isinstance(j, dict):
        return None
    obj = j.get('obj')
    if not isinstance(obj, dict):
        return None
    inner = obj.get('client')
    if isinstance(inner, dict) and inner.get('email'):
        return inner
    return obj if obj.get('email') else None


def _v3_rename_email_via_inbounds(server, session_obj, old_email, new_email):
    """Fallback rename: rewrite the client's email inside every inbound that
    contains it and push the full inbounds back via the universal
    /inbounds/update/:id endpoint (works even when the per-client API refuses
    the spaced email entirely)."""
    inbounds, fetch_err, _dt = fetch_inbounds(session_obj, server.host, server.panel_type)
    if fetch_err or not inbounds:
        return False
    old_found = False
    clean_taken = False
    for ib in inbounds:
        for c in _json_field(ib.get('settings'), {}).get('clients', []) or []:
            if c.get('email') == old_email:
                old_found = True
            elif c.get('email') == new_email:
                clean_taken = True
    if not old_found:
        # already renamed earlier (clean_taken) or genuinely missing
        return clean_taken
    if clean_taken:
        return False  # a different client already owns the space-free email
    renamed_any = False
    for ib in inbounds:
        settings = _json_field(ib.get('settings'), {})
        clients = settings.get('clients', []) or []
        if not any(c.get('email') == old_email for c in clients):
            continue
        for c in clients:
            if c.get('email') == old_email:
                c['email'] = new_email
        settings['clients'] = clients
        ok_push, _perr = _push_full_inbound(server, session_obj, ib, settings)
        renamed_any = renamed_any or ok_push
    return renamed_any


def _rename_client_email_local(server, old_email, new_email):
    """After a panel-side rename, move ownership rows and the live cache to the
    new email so reseller access checks and the dashboard keep matching."""
    try:
        rows = ClientOwnership.query.filter(
            ClientOwnership.server_id == server.id,
            func.lower(ClientOwnership.client_email) == (old_email or '').strip().lower(),
        ).all()
        for own in rows:
            own.client_email = new_email
        if rows:
            db.session.commit()
    except Exception as exc:
        app.logger.debug(f"ownership rename '{old_email}' -> '{new_email}' failed: {exc}")
        try:
            db.session.rollback()
        except Exception:
            pass
    # Move transaction history (renewals, gifts) to the new email so the
    # "last renewal" / gift-once notices keep matching after the rename.
    # One-time per client; not on the hot renewal path.
    try:
        old_l = (old_email or '').strip().lower()
        tx_rows = Transaction.query.filter(
            func.lower(Transaction.client_email) == old_l,
        ).all()
        for tx in tx_rows:
            tx.client_email = new_email
        if tx_rows:
            db.session.commit()
    except Exception as exc:
        app.logger.debug(f"transaction email rename '{old_email}' -> '{new_email}' failed: {exc}")
        try:
            db.session.rollback()
        except Exception:
            pass
    try:
        patch_cached_client(server.id, old_email, new_email=new_email)
    except Exception:
        pass


def _v3_fix_spaced_email(server, session_obj, email, client_obj=None):
    """v3 panels reject per-client API calls when the client's email contains
    spaces ("update failed"), so the client must FIRST be renamed on the panel
    to the space-free email, and only then can it be updated/deleted/reset.
    Returns the email all subsequent v3 calls should use."""
    original = str(email or '')
    clean = _v3_sanitize_email(original)
    if clean == original or not clean:
        return original

    # Rename via the first-class client update, looking the client up under its
    # current (spaced) email; the body carries the space-free email.
    payload = None
    if isinstance(client_obj, dict) and client_obj.get('email'):
        payload = dict(client_obj)
    else:
        payload = _v3_get_client(server, session_obj, original)
    renamed = False
    if isinstance(payload, dict):
        payload['email'] = clean
        renamed, _j, _err = _v3_post(
            server, session_obj,
            f"/panel/api/clients/update/{quote(original, safe='')}",
            _v3_client_payload(payload))

    if not renamed:
        renamed = _v3_rename_email_via_inbounds(server, session_obj, original, clean)

    if not renamed:
        app.logger.warning(f"v3: could not strip spaces from client email '{original}'")
        return original
    _rename_client_email_local(server, original, clean)
    app.logger.info(f"v3: client email '{original}' renamed to '{clean}' (v3 rejects spaces)")
    return clean


def v3_update_client(server, session_obj, email, client: dict):
    email = _v3_fix_spaced_email(server, session_obj, email, client_obj=client)
    return _v3_post(server, session_obj,
                    f"/panel/api/clients/update/{quote(email, safe='')}",
                    _v3_client_payload(client))


def v3_delete_client(server, session_obj, email, keep_traffic=False):
    email = _v3_fix_spaced_email(server, session_obj, email)
    path = f"/panel/api/clients/del/{quote(email, safe='')}"
    if keep_traffic:
        path += "?keepTraffic=1"
    return _v3_post(server, session_obj, path, {})


def v3_reset_client(server, session_obj, email):
    email = _v3_fix_spaced_email(server, session_obj, email)
    return _v3_post(server, session_obj,
                    f"/panel/api/clients/resetTraffic/{quote(email, safe='')}", {})


def v3_add_client(server, session_obj, client: dict, inbound_ids: list):
    return _v3_post(server, session_obj, "/panel/api/clients/add",
                    {"client": _v3_client_payload(client), "inboundIds": list(inbound_ids or [])})


# ── Multi-inbound membership reconciliation (v3) ─────────────────────────────
# A v3 client's "inbound membership" is the set of inbounds whose
# settings.clients[] contain that email/uuid. We change membership by editing
# the individual inbounds' client lists and pushing the full inbound back via
# the universal /inbounds/update/:id endpoint — this works on every panel
# version (the per-inbound delClient shortcut was removed in v3, the full
# inbound update was not).

def _push_full_inbound(server, session_obj, inbound_obj, settings_dict):
    """POST a full inbound object back to the panel with updated settings.

    settings_dict replaces the inbound's clients list. JSON sub-fields that v3
    returns already-decoded (settings/streamSettings/sniffing/allocate) must be
    re-encoded to strings, which is what the update endpoint expects.
    """
    try:
        inbound_id = int(inbound_obj.get('id'))
    except (TypeError, ValueError):
        return False, 'Bad inbound id'
    update_data = dict(inbound_obj)
    update_data['settings'] = json.dumps(settings_dict)
    for k in ('streamSettings', 'sniffing', 'allocate'):
        v = update_data.get(k)
        if isinstance(v, (dict, list)):
            update_data[k] = json.dumps(v)

    errors = []
    for tpl in collect_endpoint_templates(server.panel_type, 'inbounds_update', INBOUND_UPDATE_FALLBACKS):
        up_url = build_panel_url(server.host, tpl, {'id': inbound_id})
        if not up_url:
            continue
        try:
            resp = session_obj.post(up_url, json=update_data, verify=False, timeout=(3, 20))
        except Exception as exc:
            errors.append(str(exc))
            continue
        if resp.status_code != 200:
            errors.append(f"HTTP {resp.status_code}")
            continue
        j, err = _safe_response_json(resp)
        if err:
            errors.append(err)
            continue
        if isinstance(j, dict) and j.get('success'):
            return True, None
        errors.append((j.get('msg') or j.get('message')) if isinstance(j, dict) else 'update failed')
    return False, ('; '.join(str(e) for e in errors) or 'inbound update failed')


def _add_client_to_inbound(server, session_obj, inbound_obj, client_dict):
    """Append client_dict to an inbound's clients (no-op if email already there)."""
    settings = _json_field(inbound_obj.get('settings'), {}) or {}
    settings.setdefault('clients', [])
    email_l = (client_dict.get('email') or '').strip().lower()
    for c in settings['clients']:
        if (c.get('email') or '').strip().lower() == email_l:
            return True, None  # already present
    settings['clients'].append(client_dict)
    return _push_full_inbound(server, session_obj, inbound_obj, settings)


def _remove_client_from_inbound(server, session_obj, inbound_obj, email, client_uuid):
    """Drop a client (by email or uuid) from one inbound's clients list."""
    settings = _json_field(inbound_obj.get('settings'), {}) or {}
    clients = settings.get('clients') or []
    email_l = (email or '').strip().lower()
    uuid_s = str(client_uuid or '').strip()
    kept = [c for c in clients
            if not (((c.get('email') or '').strip().lower() == email_l and email_l)
                    or (uuid_s and str(c.get('id') or '').strip() == uuid_s))]
    if len(kept) == len(clients):
        return True, None  # nothing to remove
    settings['clients'] = kept
    return _push_full_inbound(server, session_obj, inbound_obj, settings)


def _sync_membership_ownership(user, server, email, client_uuid, added_ids, removed_ids):
    """Keep ClientOwnership rows in step with inbound-membership changes."""
    email_l = (email or '').strip().lower()
    uuid_s = str(client_uuid or '').strip()
    key_filter = []
    if uuid_s:
        key_filter.append(ClientOwnership.client_uuid == uuid_s)
    if email_l:
        key_filter.append(func.lower(ClientOwnership.client_email) == email_l)
    if not key_filter:
        return

    existing = ClientOwnership.query.filter(
        ClientOwnership.server_id == server.id, or_(*key_filter)
    ).all()
    owner_id = existing[0].reseller_id if existing else (user.id if user.role == 'reseller' else None)

    for iid in (added_ids or []):
        if owner_id is None:
            continue
        dup = ClientOwnership.query.filter(
            ClientOwnership.reseller_id == owner_id,
            ClientOwnership.server_id == server.id,
            ClientOwnership.inbound_id == iid,
            or_(*key_filter),
        ).first()
        if not dup:
            db.session.add(ClientOwnership(
                reseller_id=owner_id, server_id=server.id, inbound_id=iid,
                client_email=email, client_uuid=(uuid_s or None), price=0))
            try:
                owner = db.session.get(Admin, owner_id)
                if owner:
                    ensure_reseller_allowed_for_assignment(owner, server.id, iid)
            except Exception:
                pass

    for iid in (removed_ids or []):
        ClientOwnership.query.filter(
            ClientOwnership.server_id == server.id,
            ClientOwnership.inbound_id == iid,
            or_(*key_filter),
        ).delete(synchronize_session=False)

    db.session.commit()
    invalidate_ownership_cache()


def _reconcile_client_inbounds(user, server, email, client_uuid, target_inbound_ids, mode='set'):
    """Add/remove a client across a v3 server's inbounds.

    mode 'set'    → membership becomes exactly (target ∩ accessible)
         'add'    → add the target inbounds
         'remove' → remove the target inbounds
    Only inbounds the user can access are ever touched. Refuses to leave the
    client in zero inbounds. Returns (ok, err, status, info).
    """
    mode = (mode or 'set').lower()
    if mode not in ('set', 'add', 'remove'):
        mode = 'set'

    if user.role == 'reseller':
        allowed_map, assignments = get_reseller_access_maps(user)
        if not _has_client_access(user, server.id, email, inbound_id=None, client_uuid=client_uuid):
            return False, 'Access denied', 403, None
    else:
        allowed_map, assignments = '*', {}

    def _accessible(iid):
        return user.role != 'reseller' or is_inbound_accessible(server.id, iid, allowed_map, assignments)

    session_obj, error = get_xui_session(server)
    if error:
        return False, error, 400, None

    inbounds, fetch_err, detected_type = fetch_inbounds(session_obj, server.host, server.panel_type)
    if fetch_err:
        return False, 'Failed to fetch inbounds', 502, None
    persist_detected_panel_type(server, detected_type)

    email_l = (email or '').strip().lower()
    uuid_s = str(client_uuid or '').strip()
    membership = {}        # inbound_id -> raw client dict
    inbound_by_id = {}
    for ib in inbounds:
        try:
            iid = int(ib.get('id'))
        except (TypeError, ValueError):
            continue
        inbound_by_id[iid] = ib
        settings = _json_field(ib.get('settings'), {}) or {}
        for c in (settings.get('clients') or []):
            ce = (c.get('email') or '').strip().lower()
            cu = str(c.get('id') or '').strip()
            if (email_l and ce == email_l) or (uuid_s and cu == uuid_s):
                membership[iid] = c
                break

    if not membership:
        return False, 'Client not found on this server', 404, None
    current_ids = set(membership.keys())

    try:
        target_ids = {int(x) for x in (target_inbound_ids or []) if x is not None}
    except (TypeError, ValueError):
        target_ids = set()
    target_ids = {i for i in target_ids if i in inbound_by_id and _accessible(i)}

    if mode == 'add':
        to_add, to_remove = (target_ids - current_ids), set()
    elif mode == 'remove':
        to_add, to_remove = set(), (target_ids & current_ids)
    else:  # set
        to_add = target_ids - current_ids
        to_remove = {i for i in (current_ids - target_ids) if _accessible(i)}

    if not to_add and not to_remove:
        return True, None, 204, {'added': [], 'removed': []}

    final_ids = (current_ids - to_remove) | to_add
    if not final_ids:
        return False, 'Refusing to remove the client from all inbounds — delete the client instead', 400, None

    base_client = dict(next(iter(membership.values())))
    added, removed, errors = [], [], []

    for iid in sorted(to_add):
        ib = inbound_by_id[iid]
        clone = dict(base_client)
        proto = (ib.get('protocol') or '').lower()
        ib_settings = _json_field(ib.get('settings'), {}) or {}
        if proto == 'shadowsocks':
            method = ib_settings.get('method') or clone.get('method') or 'chacha20-ietf-poly1305'
            clone['method'] = method
            clone['password'] = clone.get('password') or _ss_password(method)
        elif proto == 'trojan':
            clone['password'] = clone.get('password') or secrets.token_urlsafe(16)
        ok_add, aerr = _add_client_to_inbound(server, session_obj, ib, clone)
        (added.append(iid) if ok_add else errors.append(f"add#{iid}: {aerr}"))

    for iid in sorted(to_remove):
        ib = inbound_by_id[iid]
        ok_rm, rerr = _remove_client_from_inbound(server, session_obj, ib, email, base_client.get('id'))
        (removed.append(iid) if ok_rm else errors.append(f"remove#{iid}: {rerr}"))

    try:
        _sync_membership_ownership(user, server, email, base_client.get('id'), added, removed)
    except Exception:
        db.session.rollback()

    # Write-through cache: reflect membership changes instantly (no panel re-fetch).
    try:
        for _iid in added:
            clone_cached_client_into_inbound(server.id, _iid, email,
                                             client_uuid=base_client.get('id'), publish=False)
        for _iid in removed:
            remove_cached_client(server.id, email, client_uuid=base_client.get('id'),
                                 inbound_id=_iid, publish=False)
        if added or removed:
            publish_snapshot_to_redis()
    except Exception:
        pass

    if errors and not added and not removed:
        return False, '; '.join(errors), 502, None
    return True, ('; '.join(errors) or None), 200, {'added': added, 'removed': removed}


def get_xui_session(server):
    # Current auth identity: the token for v3, or '' for cookie-login panels.
    # Cached sessions are keyed to this so a server that just switched to v3
    # (token added) doesn't keep returning a stale, token-less cookie session
    # — which the v3 panel rejects with 403. This is per-worker, so the cache
    # self-heals on the next call in each gunicorn worker.
    _api_token = get_server_api_token(server)
    _auth_key = _api_token or ''

    # Try to reuse session from cache
    now = time.time()
    if server.id in XUI_SESSION_CACHE:
        cached = XUI_SESSION_CACHE[server.id]
        if now < cached['expiry'] and cached.get('auth_key', '') == _auth_key:
            return cached['session'], None
        else:
            XUI_SESSION_CACHE.pop(server.id, None)

    session_obj = requests.Session()
    session_obj.trust_env = False
    session_obj.proxies = {'http': None, 'https': None}
    # Disable SSL verification at session level so redirects also skip cert checks
    # (self-signed certs on remote panels are supported this way)
    session_obj.verify = False

    # ── 3x-ui v3+ : authenticate with the API token (Bearer) ──
    # The token bypasses the v3 login CSRF guard and never expires, so we attach
    # it to the session and skip the cookie-login dance entirely.
    if _api_token:
        session_obj.headers.update({'Authorization': f'Bearer {_api_token}'})
        XUI_SESSION_CACHE[server.id] = {'session': session_obj, 'expiry': now + XUI_SESSION_TTL, 'auth_key': _auth_key}
        return session_obj, None

    try:
        base, webpath = extract_base_and_webpath(server.host)
        normalized_type = (getattr(server, 'panel_type', None) or 'auto').strip().lower()
        panel_api = get_panel_api(normalized_type)
        login_ep = (getattr(panel_api, 'login_endpoint', None) if panel_api else None) or '/login'
        login_url = login_ep if login_ep.startswith('http') else f"{base}{webpath}{login_ep}"
        panel_password = get_server_password(server)
        credentials = {"username": server.username, "password": panel_password}

        login_resp = None
        login_json = None
        last_err = None

        # Try JSON body first (3x-ui v3.0.0+), then form-encoded (older panels)
        for use_json in (True, False):
            try:
                if use_json:
                    resp = session_obj.post(
                        login_url,
                        json=credentials,
                        timeout=8,
                        headers={"Accept": "application/json"},
                    )
                else:
                    resp = session_obj.post(login_url, data=credentials, timeout=8)

                j, err = _safe_response_json(resp)
                if err:
                    last_err = err
                    continue
                login_resp = resp
                login_json = j
                last_err = None
                if isinstance(j, dict) and j.get('success'):
                    break
            except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout, requests.exceptions.Timeout, requests.exceptions.ConnectionError) as exc:
                last_err = _format_panel_connection_error(server, exc)
                app.logger.warning(
                    "Panel login connection failed for server %s (%s): %s",
                    getattr(server, 'id', None),
                    getattr(server, 'host', None),
                    exc,
                )
                break
            except Exception as exc:
                last_err = str(exc)
                continue

        if login_resp is None:
            return None, last_err or _format_panel_connection_error(server)

        if login_resp.status_code == 200 and isinstance(login_json, dict) and login_json.get('success'):
            XUI_SESSION_CACHE[server.id] = {
                'session': session_obj,
                'expiry': now + XUI_SESSION_TTL,
                'auth_key': _auth_key,
            }
            return session_obj, None

        msg = None
        if isinstance(login_json, dict):
            msg = login_json.get('msg') or login_json.get('message')
        return None, f"Login failed: {login_resp.status_code}{(' - ' + str(msg)) if msg else ''}"
    except Exception as e:
        return None, f"Error: {str(e)}"

def persist_detected_panel_type(server, detected_type: str) -> bool:
    """Persist detected panel type for a Server.

    Only updates when current type is auto/unset to avoid overriding a deliberate manual choice.
    Returns True if updated.
    """
    try:
        if not server:
            return False
        detected = (detected_type or '').strip().lower()
        if not detected or detected == 'auto':
            return False
        current = (getattr(server, 'panel_type', None) or 'auto').strip().lower()
        if current not in ('', 'auto'):
            return False
        if current == detected:
            return False
        server.panel_type = detected
        db.session.commit()
        return True
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
        return False

def fetch_inbounds(session_obj, host, panel_type='auto'):
    base, webpath = extract_base_and_webpath(host)
    timeout_sec = 3
    normalized_type = (panel_type or 'auto').strip().lower()

    # Build a prioritized endpoint map: [(endpoint, detected_panel_type)]
    endpoints_map = []

    # If panel_type is known, try only its configured endpoint first
    panel_api = get_panel_api(normalized_type)
    if normalized_type != 'auto' and panel_api and panel_api.inbounds_list:
        endpoints_map.append((panel_api.inbounds_list, normalized_type))
    else:
        # Auto-discovery: try known panel APIs first (prefer sanaei)
        try:
            all_apis = PanelAPI.query.all()
            # Release the read lock before starting network I/O
            db.session.commit()
        except Exception:
            all_apis = []

        def _api_sort_key(api: 'PanelAPI'):
            pt = (getattr(api, 'panel_type', '') or '').lower()
            if pt == 'sanaei':
                return (0, pt)
            if pt == 'alireza':
                return (1, pt)
            return (2, pt)

        for api in sorted(all_apis, key=_api_sort_key):
            ep = getattr(api, 'inbounds_list', None)
            pt = (getattr(api, 'panel_type', None) or '').strip().lower()
            if ep and pt:
                endpoints_map.append((ep, pt))

        # Hardcoded fallbacks (covers older panels / missing PanelAPI rows)
        endpoints_map.extend([
            ("/panel/api/inbounds/list", "sanaei"),
            ("/xui/API/inbounds/", "alireza"),
            ("/xui/inbound/list", "xui"),
        ])

    # De-duplicate while preserving order
    seen = set()
    deduped = []
    for ep, pt in endpoints_map:
        if not ep:
            continue
        key = (ep, pt)
        if key in seen:
            continue
        seen.add(key)
        deduped.append((ep, pt))

    last_error = None
    for ep, detected_type in deduped:
        try:
            url = ep if ep.startswith('http') else f"{base}{webpath}{ep}"
            ep_l = ep.lower()

            # Request strategy per panel flavor
            if '/xui/' in ep_l and 'api' in ep_l:
                resp = session_obj.get(url, verify=False, timeout=timeout_sec)
                if resp.status_code == 405:
                    resp = session_obj.post(url, verify=False, timeout=timeout_sec)
            elif '/xui/' in ep_l:
                resp = session_obj.post(url, json={"page": 1, "limit": 100}, verify=False, timeout=timeout_sec)
            else:
                resp = session_obj.get(url, verify=False, timeout=timeout_sec)

            if resp.status_code != 200:
                last_error = f"HTTP {resp.status_code} from {ep}"
                continue

            data = resp.json()
            if not isinstance(data, dict) or not data.get('success'):
                last_error = f"Panel returned success=false from {ep}"
                continue

            if 'obj' in data:
                return data['obj'], None, detected_type
            if 'data' in data:
                d = data['data']
                return (d if isinstance(d, list) else d.get('list', [])), None, detected_type
        except Exception as e:
            last_error = str(e)
            app.logger.debug(f"Failed inbounds endpoint {ep}: {last_error}")
            continue

    return None, (last_error or "Failed to fetch inbounds from all known endpoints"), 'auto'


XUI_COOKIE_SESSION_CACHE = {}  # cache_key -> {'session': requests.Session, 'expiry': float}


def get_xui_cookie_session(host, username, password, panel_type='auto', cache_key=None):
    """Return a COOKIE-authenticated session (username/password login).

    v3 panels are normally accessed with a Bearer API token, but some panel
    routes — notably the web-UI `/panel/inbound/onlines` — are NOT exposed on
    the token-authenticated API router and return 404 unless you present a
    valid login cookie. This logs in and caches the cookie session.
    """
    if not username or not password:
        return None
    now = time.time()
    ck = cache_key or f"{host}|{username}"
    cached = XUI_COOKIE_SESSION_CACHE.get(ck)
    if cached and now < cached['expiry']:
        return cached['session']

    try:
        base, webpath = extract_base_and_webpath(host)
        normalized_type = (panel_type or 'auto').strip().lower()
        panel_api = get_panel_api(normalized_type)
        login_ep = (getattr(panel_api, 'login_endpoint', None) if panel_api else None) or '/login'
        login_url = login_ep if login_ep.startswith('http') else f"{base}{webpath}{login_ep}"

        s = requests.Session()
        s.trust_env = False
        s.proxies = {'http': None, 'https': None}
        s.verify = False
        creds = {"username": username, "password": password}
        for use_json in (True, False):
            try:
                if use_json:
                    r = s.post(login_url, json=creds, timeout=8, headers={"Accept": "application/json"})
                else:
                    r = s.post(login_url, data=creds, timeout=8)
                j, err = _safe_response_json(r)
                if r.status_code == 200 and isinstance(j, dict) and j.get('success'):
                    XUI_COOKIE_SESSION_CACHE[ck] = {'session': s, 'expiry': now + XUI_SESSION_TTL}
                    return s
            except Exception:
                continue
    except Exception:
        pass
    return None


def fetch_onlines(session_obj, host, panel_type='auto'):
    """Fetch online clients from panel (best-effort).

    Returns (index, error) where index is:
      {"pairs": set[(inbound_id_norm, email_lower)], "emails": set[email_lower]}
    """
    index = {"pairs": set(), "emails": set()}

    try:
        base, webpath = extract_base_and_webpath(host)
        timeout_sec = 3
        normalized_type = (panel_type or 'auto').strip().lower()

        # Online endpoints:
        # - 3x-ui (Sanaei): base /panel/api/inbounds, method POST /onlines
        # - x-ui (alireza0): base /xui/API/inbounds, method POST /onlines
        # Some installs may also allow GET; keep as fallback.
        candidates = []
        if normalized_type in ('sanaei', 'auto', ''):
            candidates.extend([
                # Web-UI route (present on more 3x-ui builds than the API route)
                ('POST', '/panel/inbound/onlines'),
                ('POST', '/panel/api/inbounds/onlines'),
                ('GET', '/panel/inbound/onlines'),
                ('GET', '/panel/api/inbounds/onlines'),
            ])
        if normalized_type in ('alireza', 'alireza0', 'xui', 'x-ui', 'auto', ''):
            candidates.extend([
                ('POST', '/xui/API/inbounds/onlines'),
                ('POST', '/xui/inbound/onlines'),
                ('POST', '/xui/api/inbounds/onlines'),
                ('GET', '/xui/API/inbounds/onlines'),
                ('GET', '/xui/api/inbounds/onlines'),
            ])

        last_error = None
        last_status = None

        for method, ep in candidates:
            try:
                url = ep if ep.startswith('http') else f"{base}{webpath}{ep}"
                if method == 'POST':
                    resp = session_obj.post(url, json={}, verify=False, timeout=timeout_sec)
                else:
                    resp = session_obj.get(url, verify=False, timeout=timeout_sec)

                last_status = resp.status_code
                try:
                    _body_snippet = re.sub(r'\s+', ' ', (resp.text or ''))[:160]
                    _srv_hdr = resp.headers.get('Server', '?')
                    _ct = resp.headers.get('Content-Type', '?')
                    app.logger.info(f"[onlines] {method} {url} -> HTTP {resp.status_code} [Server={_srv_hdr}, CT={_ct}]: {_body_snippet}")
                except Exception:
                    pass
                if resp.status_code != 200:
                    continue

                data = resp.json()

                # Response shapes vary:
                # - {success: true, obj: [...]} or {success: true, data: {...}}
                # - plain list of emails
                # - dict with a nested list
                obj = None
                if isinstance(data, dict):
                    # Many panels use 'success' flag; if present and false, skip.
                    if 'success' in data and not data.get('success'):
                        continue
                    obj = data.get('obj')
                    if obj is None:
                        obj = data.get('data')
                elif isinstance(data, list):
                    obj = data
                else:
                    continue

                items = []
                if isinstance(obj, list):
                    items = obj
                elif isinstance(obj, dict):
                    for k in ('onlines', 'list', 'data', 'clients'):
                        v = obj.get(k)
                        if isinstance(v, list):
                            items = v
                            break

                for item in items or []:
                    email = None
                    inbound_id = None
                    if isinstance(item, str):
                        email = item
                    elif isinstance(item, dict):
                        email = item.get('email') or item.get('user') or item.get('username')
                        inbound_id = item.get('inboundId')
                        if inbound_id is None:
                            inbound_id = item.get('inbound_id')

                    email_l = (str(email or '').strip().lower())
                    if not email_l:
                        continue

                    if inbound_id is not None:
                        try:
                            inbound_id_norm = int(inbound_id)
                        except Exception:
                            inbound_id_norm = str(inbound_id)
                        index['pairs'].add((inbound_id_norm, email_l))
                    else:
                        index['emails'].add(email_l)

                try:
                    app.logger.info(
                        f"[onlines] {normalized_type} {method} {ep} -> "
                        f"{len(index['pairs'])} pairs, {len(index['emails'])} emails"
                    )
                except Exception:
                    pass
                return index, None
            except Exception as e:
                last_error = str(e)
                continue

        # If we tried endpoints but none worked, return a hint (caller still treats it best-effort).
        if candidates:
            hint = last_error or (f"HTTP {last_status}" if last_status is not None else "No response")
            try:
                app.logger.warning(f"[onlines] all endpoints failed ({normalized_type}): {hint}")
            except Exception:
                pass
            return index, f"Failed to fetch onlines ({normalized_type}): {hint}"

        return index, None
    except Exception as e:
        return index, str(e)


def _pick_first_value(payload: dict, keys: list[str]):
    for key in keys:
        if key in payload and payload.get(key) not in (None, ''):
            return payload.get(key)
    return None


def _normalize_server_status_payload(payload: dict) -> dict:
    """Extract useful info from the panel /status API response.

    Note: The /status endpoint returns system stats (CPU, mem, disk, xray info).
    It does NOT return xui_version or online_count - those come from elsewhere.
    """
    if not isinstance(payload, dict):
        return {}

    xray_info = payload.get('xray') if isinstance(payload.get('xray'), dict) else {}

    # 'panelVersion' is the 3x-ui v3+ field for the panel version (e.g. "3.2.8").
    xui_version = _pick_first_value(payload, ['xui_version', 'xuiVersion', 'xui', 'panelVersion'])
    if not xui_version and isinstance(payload.get('version'), str):
        xui_version = payload.get('version')

    xray_version = _pick_first_value(payload, ['xray_version', 'xrayVersion'])
    if not xray_version and isinstance(xray_info, dict):
        xray_version = _pick_first_value(xray_info, ['version', 'xray_version', 'xrayVersion'])

    # Xray state: running / stop / error (Sanaei uses lowercase, Alireza uses capitalized)
    xray_state = None
    if isinstance(xray_info, dict):
        raw_state = _pick_first_value(xray_info, ['state', 'State'])
        if raw_state:
            xray_state = str(raw_state).lower()  # normalize to lowercase

    xray_core = _pick_first_value(payload, ['core', 'xray_core', 'xrayCore', 'arch', 'architecture'])
    if not xray_core and isinstance(xray_info, dict):
        xray_core = _pick_first_value(xray_info, ['core', 'arch', 'architecture'])

    online = _pick_first_value(payload, ['online', 'onlineCount', 'online_count'])
    try:
        online_count = int(online) if online is not None else None
    except Exception:
        online_count = None

    return {
        'xui_version': xui_version,
        'xray_version': xray_version,
        'xray_state': xray_state,
        'xray_core': xray_core,
        'online_count': online_count
    }


def fetch_server_status(session_obj, host, panel_type='auto'):
    base, webpath = extract_base_and_webpath(host)
    timeout_sec = 5
    normalized_type = (panel_type or 'auto').strip().lower()

    endpoints = []
    panel_api = get_panel_api(normalized_type)
    if normalized_type != 'auto' and panel_api and panel_api.server_status:
        endpoints.append((panel_api.server_status, normalized_type))
    else:
        try:
            all_apis = PanelAPI.query.all()
            # Release the read lock before starting network I/O
            db.session.commit()
        except Exception:
            all_apis = []

        def _api_sort_key(api: 'PanelAPI'):
            pt = (getattr(api, 'panel_type', '') or '').lower()
            if pt == 'sanaei':
                return (0, pt)
            if pt == 'alireza':
                return (1, pt)
            return (2, pt)

        for api in sorted(all_apis, key=_api_sort_key):
            ep = getattr(api, 'server_status', None)
            pt = (getattr(api, 'panel_type', None) or '').strip().lower()
            if ep and pt:
                endpoints.append((ep, pt))

        endpoints.extend([
            ('/panel/api/server/status', 'sanaei'),
            ('/xui/API/server/status', 'alireza'),
        ])

    # Add non-API fallback paths (some older panel versions only expose these)
    if normalized_type in ('alireza', 'alireza0', 'xui', 'x-ui', 'auto', ''):
        endpoints.append(('/server/status', 'alireza'))

    seen = set()
    deduped = []
    for ep, pt in endpoints:
        if not ep:
            continue
        key = (ep, pt)
        if key in seen:
            continue
        seen.add(key)
        deduped.append((ep, pt))

    last_error = None
    for ep, detected_type in deduped:
        try:
            url = ep if ep.startswith('http') else f"{base}{webpath}{ep}"
            resp = session_obj.get(url, verify=False, timeout=timeout_sec, allow_redirects=False)

            # Redirect usually means session expired -> redirected to login page
            if resp.status_code in (301, 302, 303, 307, 308):
                last_error = f"Redirect {resp.status_code} (session may have expired)"
                continue

            if resp.status_code == 404:
                # Sanaei returns 404 for unauthenticated API calls, or endpoint doesn't exist
                last_error = f"HTTP 404 (endpoint may not exist in this panel version)"
                continue

            if resp.status_code != 200:
                last_error = f"HTTP {resp.status_code}"
                continue

            data, err = _safe_response_json(resp)
            if err:
                last_error = err
                continue
            if isinstance(data, dict) and data.get('success') is False:
                last_error = data.get('msg') or data.get('message') or 'Status failed'
                continue

            payload = None
            if isinstance(data, dict):
                obj_val = data.get('obj')
                # Handle null/None obj (e.g. Alireza panel lazy-load: status not ready yet)
                if obj_val is not None and isinstance(obj_val, dict):
                    payload = obj_val
                elif obj_val is None:
                    # obj is null, status not ready yet - return empty but successful
                    return {}, None, detected_type
                else:
                    payload = data.get('data') or data

            normalized = _normalize_server_status_payload(payload if isinstance(payload, dict) else {})
            return normalized, None, detected_type
        except requests.exceptions.Timeout:
            last_error = f"Connection timeout ({timeout_sec}s)"
            continue
        except requests.exceptions.ConnectionError as e:
            last_error = f"Connection error: {str(e)[:100]}"
            continue
        except Exception as e:
            last_error = str(e)[:150]
            continue

    return None, last_error or 'Failed to fetch status', 'auto'


def fetch_direct_link_from_subscription(sub_url: str, fallback_func=None, fallback_args=None) -> str:
    """
    Fetch the direct config link from the upstream X-UI subscription endpoint.
    Returns the first config line, or falls back to manual generation if fetch fails.
    """
    direct_link = None
    try:
        resp = requests.get(
            sub_url, 
            headers={'User-Agent': 'v2rayng'}, 
            timeout=5, 
            verify=False,
            allow_redirects=False
        )
        if resp.status_code == 200:
            raw_content = resp.content or b''
            try:
                decoded = base64.b64decode(raw_content).decode('utf-8')
            except Exception:
                decoded = raw_content.decode('utf-8', errors='ignore')
            configs = [line.strip() for line in decoded.splitlines() if line.strip()]
            if configs:
                direct_link = configs[0]
    except Exception:
        pass
    
    # Fallback to manual generation
    if not direct_link and fallback_func and fallback_args:
        try:
            direct_link = fallback_func(*fallback_args)
        except Exception:
            pass
    
    return direct_link


def generate_client_link(client, inbound, server_host):
    """Generate share links for vmess / vless / trojan / shadowsocks."""

    def _as_json(obj, default=None):
        if default is None:
            default = {}
        if isinstance(obj, dict):
            return obj
        if isinstance(obj, str):
            try:
                return json.loads(obj)
            except Exception:
                return default
        return default

    def _parse_host(server_host, inbound_port):
        host_value = server_host or ''
        if host_value and not host_value.startswith(('http://', 'https://')):
            host_value = f"http://{host_value}"
        parsed = urlparse(host_value)
        host = parsed.hostname or parsed.path or ''
        port_val = inbound_port or parsed.port
        return host, port_val

    def _extract_stream_parts(stream_settings):
        network = (stream_settings.get('network') or 'tcp').lower()
        security = (stream_settings.get('security') or 'none').lower()

        ws = stream_settings.get('wsSettings') or {}
        grpc = stream_settings.get('grpcSettings') or {}
        tcp = stream_settings.get('tcpSettings') or {}
        h2 = stream_settings.get('httpSettings') or {}

        path = ws.get('path') or h2.get('path') or ''
        host_header = (ws.get('headers') or {}).get('Host') or (ws.get('headers') or {}).get('host') or ''
        if not host_header:
            host_header = h2.get('host') or ''

        service_name = grpc.get('serviceName') or grpc.get('service_name') or ''
        mode = grpc.get('multiMode') and 'multi' or 'gun'

        header = (tcp.get('header') or {})
        header_type = header.get('type') or ''
        if header_type == 'http':
            hosts = header.get('request', {}).get('headers', {}).get('Host') or []
            host_header = ','.join(hosts) if isinstance(hosts, list) else hosts

        tls_settings = stream_settings.get('tlsSettings') or {}
        reality_settings = stream_settings.get('realitySettings') or {}
        sni = tls_settings.get('serverName') or (reality_settings.get('serverNames') or [None])[0]
        alpn_list = tls_settings.get('alpn') or []
        alpn = ','.join(alpn_list) if isinstance(alpn_list, list) else alpn_list

        fp = reality_settings.get('fingerprint') or stream_settings.get('fingerprint')
        pbk = reality_settings.get('publicKey')
        sid = reality_settings.get('shortId') or reality_settings.get('shortIds') or ''

        return {
            "network": network,
            "security": security,
            "path": path,
            "host_header": host_header,
            "service_name": service_name,
            "grpc_mode": mode,
            "header_type": header_type,
            "sni": sni,
            "alpn": alpn,
            "fp": fp,
            "pbk": pbk,
            "sid": sid,
        }

    try:
        protocol = (inbound.get('protocol') or '').lower()
        settings = _as_json(inbound.get('settings'))
        stream_settings = _as_json(inbound.get('streamSettings'))
        stream = _extract_stream_parts(stream_settings)

        host, port = _parse_host(server_host, inbound.get('port'))
        remark = quote(client.get('email') or inbound.get('remark') or 'client')
        uuid = client.get('id') or client.get('uuid') or client.get('password') or ''
        flow = client.get('flow') or settings.get('flow') or ''

        if protocol == 'vless':
            query = {
                "encryption": "none",
                "type": stream["network"],
                "security": None if stream["security"] == 'none' else stream["security"],
                "sni": stream["sni"],
                "alpn": stream["alpn"],
                "fp": stream["fp"],
                "pbk": stream["pbk"],
                "sid": stream["sid"],
                "flow": flow or None,
            }
            if stream["network"] == 'ws':
                query.update({"path": stream["path"], "host": stream["host_header"]})
            elif stream["network"] == 'grpc':
                query.update({"type": "grpc", "serviceName": stream["service_name"], "mode": stream["grpc_mode"]})
            elif stream["network"] == 'tcp' and stream["header_type"] == 'http':
                query.update({"type": "http", "host": stream["host_header"]})

            q = {k: v for k, v in query.items() if v not in (None, '', [])}
            return f"vless://{uuid}@{host}:{port}?{urlencode(q)}#{remark}"

        if protocol == 'vmess':
            aid = client.get('alterId', client.get('aid', 0)) or 0
            vmess_obj = {
                "v": "2",
                "ps": client.get('email') or inbound.get('remark') or host,
                "add": host,
                "port": str(port),
                "id": uuid,
                "aid": str(aid),
                "scy": "auto",
                "net": stream["network"],
                "type": stream["header_type"] or "none",
                "host": stream["host_header"],
                "path": stream["path"] if stream["network"] == 'ws' else '',
                "tls": "" if stream["security"] == 'none' else stream["security"],
                "sni": stream["sni"] or "",
                "alpn": stream["alpn"] or "",
                "fp": stream["fp"] or "",
                "pbk": stream["pbk"] or "",
                "sid": stream["sid"] or "",
                "serviceName": stream["service_name"] if stream["network"] == 'grpc' else "",
            }
            payload = base64.b64encode(json.dumps(vmess_obj, ensure_ascii=False).encode()).decode()
            return f"vmess://{payload}"

        if protocol == 'trojan':
            password = client.get('password') or uuid
            query = {
                "type": stream["network"],
                "security": None if stream["security"] == 'none' else stream["security"],
                "sni": stream["sni"],
                "alpn": stream["alpn"],
                "host": stream["host_header"],
            }
            if stream["network"] == 'ws':
                query.update({"path": stream["path"]})
            elif stream["network"] == 'grpc':
                query.update({"serviceName": stream["service_name"], "mode": stream["grpc_mode"]})
            q = {k: v for k, v in query.items() if v not in (None, '', [])}
            q_str = f"?{urlencode(q)}" if q else ''
            return f"trojan://{password}@{host}:{port}{q_str}#{remark}"

        if protocol == 'shadowsocks':
            method = settings.get('method') or client.get('method')
            password = client.get('password') or uuid
            if method and password:
                userinfo = base64.b64encode(f"{method}:{password}".encode()).decode()
                query = {}
                if stream["network"] == 'ws':
                    plugin = f"v2ray-plugin;path={stream['path'] or '/'};host={stream['host_header'] or host}"
                    if stream["security"] != 'none':
                        plugin += ";tls"
                    query["plugin"] = plugin
                elif stream["network"] == 'grpc':
                    plugin = f"grpc;serviceName={stream['service_name']}"
                    query["plugin"] = plugin
                q = f"?{urlencode(query)}" if query else ''
                return f"ss://{userinfo}@{host}:{port}{q}#{remark}"
            return None

        return None
    except Exception as exc:
        app.logger.debug(f"Link gen failed: {exc}")
        return None

def find_client(inbounds, inbound_id, email):
    for inbound in inbounds:
        if inbound.get('id') != inbound_id:
            continue
        settings = _json_field(inbound.get('settings'), {})
        for client in settings.get('clients', []):
            if client.get('email') == email:
                return client, inbound
    return None, None

def process_inbounds(inbounds, server, user, allowed_map='*', assignments=None, app_base_url=None, online_index=None):
    processed = []
    stats = {"total_inbounds": 0, "active_inbounds": 0, "total_clients": 0, "online_clients": 0, "active_clients": 0, "inactive_clients": 0, "not_started_clients": 0, "unlimited_expiry_clients": 0, "unlimited_volume_clients": 0, "upload_raw": 0, "download_raw": 0, "remaining_raw": 0}
    dashboard_thresholds = _get_dashboard_status_thresholds()
    panel_lang = _get_panel_ui_lang()
    
    assignments = assignments or {}
    online_index = online_index or {"pairs": set(), "emails": set()}
    online_pairs = online_index.get('pairs') if isinstance(online_index, dict) else set()
    online_emails = online_index.get('emails') if isinstance(online_index, dict) else set()

    owned_emails = set()
    if user.role == 'reseller':
        ownerships = ClientOwnership.query.filter_by(reseller_id=user.id, server_id=server.id).all()
        owned_emails = {o.client_email.lower() for o in ownerships if o.client_email}

    # ── Hoist server-level values out of the per-client loop (computed once) ──
    _parsed_host = urlparse(server.host)
    _hostname = _parsed_host.hostname
    _scheme = _parsed_host.scheme
    _final_port = server.sub_port if server.sub_port else _parsed_host.port
    _port_str = f":{_final_port}" if _final_port else ""
    _base_sub = f"{_scheme}://{_hostname}{_port_str}"
    _s_path = (server.sub_path or '').strip('/')
    _j_path = (server.json_path or '').strip('/')
    if app_base_url:
        _app_base = app_base_url
    else:
        try:
            _app_base = request.url_root.rstrip('/')
        except RuntimeError:
            _app_base = ""  # background thread (no request context)
    _is_sanaei = (server.panel_type == 'sanaei')
    _server_id = server.id
    # On v3 the same client (by email) is mirrored across several inbounds.
    # Count each person ONCE for all aggregate stats so totals aren't inflated.
    _is_v3 = server_is_v3(server)
    _v3_seen_emails = set()

    for inbound in inbounds:
        try:
            inbound_id_raw = inbound.get('id')
            try:
                inbound_id = int(inbound_id_raw)
            except (TypeError, ValueError):
                inbound_id = inbound_id_raw

            if user.role == 'reseller':
                accessible = is_inbound_accessible(server.id, inbound_id, allowed_map, assignments)
                if not accessible:
                    continue

            settings = _json_field(inbound.get('settings'), {})
            clients = settings.get('clients', [])
            client_stats = inbound.get('clientStats', [])

            # Build an email -> stats lookup ONCE per inbound (was O(clients*stats))
            stats_by_email = {}
            for _st in client_stats:
                _e = _st.get('email')
                if _e is not None and _e not in stats_by_email:
                    stats_by_email[_e] = _st

            processed_clients = []
            seen_client_keys = set()
            for client in clients:
                email = client.get('email', '')
                email_l = (str(email or '').strip().lower())
                client_uuid = (client.get('id') or '').strip().lower()
                dedup_key = (email_l, client_uuid)
                if dedup_key != ('', '') and dedup_key in seen_client_keys:
                    continue
                seen_client_keys.add(dedup_key)

                if user.role == 'reseller' and email.lower() not in owned_emails:
                    continue

                # v3: only the first inbound where this email appears feeds the stats.
                if _is_v3 and email_l:
                    _count_stat = email_l not in _v3_seen_emails
                    if _count_stat:
                        _v3_seen_emails.add(email_l)
                else:
                    _count_stat = True
                
                sub_id = client.get('subId', '')
                sub_url = ""
                json_url = ""
                dash_sub_url = ""

                if sub_id or (_is_sanaei and client.get('id')):
                    final_id = sub_id if sub_id else client.get('id')
                    sub_url = f"{_base_sub}/{_s_path}/{final_id}"
                    json_url = f"{_base_sub}/{_j_path}/{final_id}"
                    dash_sub_url = f"{_app_base}/s/{_server_id}/{final_id}"

                _stat = stats_by_email.get(email)
                client_up = _stat.get('up', 0) if _stat else 0
                client_down = _stat.get('down', 0) if _stat else 0

                total_bytes = client.get('totalGB', 0) or 0
                remaining_bytes = max(total_bytes - (client_up + client_down), 0) if total_bytes > 0 else None
                total_formatted = format_bytes_gb_tb(total_bytes) if total_bytes > 0 else "Unlimited"

                if _count_stat and total_bytes <= 0:
                    stats["unlimited_volume_clients"] += 1
                
                volume_status = ""
                if remaining_bytes is not None:
                    remaining_formatted = format_bytes_gb_tb(remaining_bytes)
                    if remaining_bytes <= 0:
                        remaining_formatted = "Suspended"
                        volume_status = "suspended"
                    elif remaining_bytes < int(float(dashboard_thresholds.get('low_volume_gb', 1.0)) * (1024 ** 3)):
                        remaining_formatted = f"{remaining_formatted} Low"
                        volume_status = "low"
                else:
                    remaining_formatted = "Unlimited"
                    # Use existing purple badge style (expiry-start-after) for unlimited volume
                    volume_status = "expiry-start-after"

                expiry_raw = client.get('expiryTime', 0)
                expiry_info = format_remaining_days(expiry_raw, lang=panel_lang)
                account_state = _compute_client_service_state(
                    enabled=bool(client.get('enable', True)),
                    total_bytes=int(total_bytes or 0),
                    remaining_bytes=(None if remaining_bytes is None else int(remaining_bytes)),
                    expiry_ts=int(expiry_raw or 0),
                    expiry_info=expiry_info,
                    thresholds=dashboard_thresholds,
                    lang=panel_lang,
                )

                if expiry_info.get('type') == 'start_after_use':
                    stats["not_started_clients"] += 1

                if expiry_info.get('type') == 'unlimited':
                    stats["unlimited_expiry_clients"] += 1

                # Online status (best-effort; depends on panel API support)
                inbound_id_norm = None
                try:
                    inbound_id_norm = int(inbound.get('id'))
                except Exception:
                    inbound_id_norm = str(inbound.get('id'))
                is_online = False
                try:
                    if email_l:
                        is_online = ((inbound_id_norm, email_l) in (online_pairs or set())) or (email_l in (online_emails or set()))
                except Exception:
                    is_online = False

                client_data = {
                    "email": email,
                    "comment": (client.get('comment') or '').strip(),
                    "id": client.get('id', ''),
                    "subId": sub_id,
                    "enable": client.get('enable', True),
                    "is_online": bool(is_online),
                    "totalGB": total_bytes,
                    "totalGB_formatted": total_formatted,
                    "remaining_bytes": remaining_bytes if remaining_bytes is not None else -1,
                    "remaining_formatted": remaining_formatted,
                    "volume_status": volume_status,
                    "service_state": account_state.get('key', 'active'),
                    "service_state_label": account_state.get('label', 'فعاله'),
                    "service_state_emoji": account_state.get('emoji', '✅'),
                    "service_state_tag": account_state.get('tag', 'ok'),
                    "expiryTime": expiry_info['text'],
                    "expiryTimestamp": expiry_raw,
                    "expiryType": expiry_info['type'],
                    "up": client_up,
                    "down": client_down,
                    "up_formatted": format_bytes(client_up),
                    "down_formatted": format_bytes(client_down),
                    "sub_url": sub_url,
                    "json_url": json_url,
                    "dash_sub_url": dash_sub_url,
                    "server_id": server.id,
                    "inbound_id": inbound.get('id'),
                    "link": sub_url,  # Use subscription URL - client apps will fetch correct configs from panel
                    "raw_client": client  # Store original object for faster updates
                }
                processed_clients.append(client_data)

                if _count_stat:
                    stats["total_clients"] += 1
                    if is_online:
                        stats["online_clients"] += 1
                    if client.get('enable', True): stats["active_clients"] += 1
                    else: stats["inactive_clients"] += 1
                    stats["upload_raw"] += client_up
                    stats["download_raw"] += client_down
                    # Accumulate remaining for active limited-volume clients only
                    if client.get('enable', True) and remaining_bytes is not None and remaining_bytes >= 0:
                        stats["remaining_raw"] += int(remaining_bytes)
            
            # استخراج network و security از settings
            streamSettings = settings.get('streamSettings', {})
            network = streamSettings.get('network', 'tcp')
            security = streamSettings.get('security', 'none')
            
            # Remaining = sum of active+usable clients only:
            # enabled, not expired, not disabled — active / expiring_soon / volume_low
            _ACTIVE_STATES = {'active', 'expiring_soon', 'volume_low'}
            _inbound_remaining_raw = sum(
                c['remaining_bytes'] for c in processed_clients
                if c.get('enable', True)
                and c.get('service_state', 'active') in _ACTIVE_STATES
                and c.get('remaining_bytes', -1) >= 0
            )
            _active_count = sum(1 for _c in processed_clients if _c.get('enable', True))
            processed.append({
                "id": inbound.get('id'),
                "remark": inbound.get('remark', ''),
                "port": inbound.get('port', ''),
                "protocol": inbound.get('protocol', ''),
                "network": network,
                "security": security,
                "clients": processed_clients,
                "client_count": len(processed_clients),
                "active_count": _active_count,
                "enable": inbound.get('enable', False),
                "server_id": server.id,
                "server_name": server.name,
                "total_up": format_bytes(inbound.get('up', 0)),
                "total_down": format_bytes(inbound.get('down', 0)),
                "up_raw": inbound.get('up', 0),
                "down_raw": inbound.get('down', 0),
                "remaining_total_raw": _inbound_remaining_raw,
                "remaining_total": format_bytes(_inbound_remaining_raw) if _inbound_remaining_raw > 0 else None,
            })
            
            # total_clients is now counted per-client above (v3-deduplicated).
            if inbound.get('enable', False): stats["active_inbounds"] += 1
            
        except Exception as e:
            continue
            
    stats["total_inbounds"] = len(processed)
    stats["total_upload"] = format_bytes(stats["upload_raw"])
    stats["total_download"] = format_bytes(stats["download_raw"])
    stats["total_traffic"] = format_bytes(stats["upload_raw"] + stats["download_raw"])
    stats["total_remaining"] = format_bytes(stats["remaining_raw"])
    stats["limited_clients"] = stats["total_clients"] - stats["unlimited_volume_clients"]

    return processed, stats

# --- ROUTES ---

def _login_fail(msg: str):
    """Return appropriate login failure response."""
    if request.is_json:
        return jsonify({"success": False, "error": msg})
    return render_template('login.html', error=msg)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if 'admin_id' in session:
        return redirect(url_for('dashboard'))
    if 'client_id' in session:
        return redirect(url_for('client_portal'))

    if request.method == 'POST':
        data = request.form if request.form else request.json
        raw_input = (data.get('username') or '').strip()
        password = data.get('password') or ''

        # Determine auth path: Iranian mobile → client portal, otherwise → admin
        mobile = _extract_iran_mobile_from_text(raw_input)

        if mobile:
            # ── Client portal auth ─────────────────────────────
            client = ClientPortalUser.query.filter_by(mobile=mobile, enabled=True).first()
            if not client:
                app.logger.warning(f"Login — unknown client mobile {mobile} from {request.remote_addr}")
                return _login_fail("Invalid credentials")

            if client.is_locked():
                remaining = max(1, int((client.locked_until - datetime.utcnow()).total_seconds() / 60) + 1)
                return _login_fail(f"Account locked. Try again in {remaining} minute(s).")

            if not client.check_password(password):
                client.record_failed()
                db.session.commit()
                app.logger.warning(f"Login — wrong password for client {mobile} from {request.remote_addr} (attempt {client.failed_attempts})")
                if client.is_locked():
                    return _login_fail("Account locked after 5 failed attempts. Try again in 15 minutes.")
                left = 5 - (client.failed_attempts or 0)
                return _login_fail(f"Invalid credentials ({left} attempts remaining)")

            client.reset_failed()
            client.last_login = datetime.utcnow()
            db.session.commit()
            session.permanent = True
            session['client_id'] = client.id
            session['client_mobile'] = client.mobile
            session['client_display_name'] = client.display_name or client.mobile

            if client.must_change_password:
                dest = url_for('client_change_password')
            else:
                dest = url_for('client_portal')
            return jsonify({"success": True, "redirect": dest}) if request.is_json else redirect(dest)

        else:
            # ── Admin auth ─────────────────────────────────────
            username = _normalize_username(raw_input)
            admin = Admin.query.filter(
                func.lower(Admin.username) == username,
                Admin.enabled == True
            ).first()
            if admin and admin.check_password(password):
                session.permanent = True
                session['admin_id'] = admin.id
                session['admin_username'] = admin.username
                session['role'] = admin.role
                session['is_superadmin'] = (admin.role == 'superadmin' or admin.is_superadmin)
                admin.last_login = datetime.utcnow()
                db.session.commit()
                return jsonify({"success": True}) if request.is_json else redirect(url_for('dashboard'))

            app.logger.warning(f"Failed login for '{raw_input}' from {request.remote_addr}")
            return _login_fail("Invalid credentials")

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# ── Client Portal ─────────────────────────────────────────────────────────────

@app.route('/client-login')
def client_login_page():
    return redirect(url_for('login'))


@app.route('/client/logout')
def client_logout():
    session.pop('client_id', None)
    session.pop('client_mobile', None)
    session.pop('client_display_name', None)
    return redirect(url_for('login'))


@app.route('/client/change-password', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def client_change_password():
    if 'client_id' not in session:
        return redirect(url_for('login'))
    user = db.session.get(ClientPortalUser, session['client_id'])
    if not user or not user.enabled:
        session.pop('client_id', None)
        return redirect(url_for('login'))

    error = None
    if request.method == 'POST':
        new_pw = request.form.get('new_password', '')
        confirm_pw = request.form.get('confirm_password', '')
        if len(new_pw) < 8:
            error = 'رمز عبور باید حداقل ۸ کاراکتر باشد'
        elif new_pw != confirm_pw:
            error = 'تکرار رمز عبور مطابقت ندارد'
        elif new_pw in (user.mobile, user.mobile.lstrip('+'), user.mobile[3:]):
            error = 'رمز عبور نمی‌تواند همان شماره موبایل باشد'
        else:
            user.set_password(new_pw)
            user.must_change_password = False
            db.session.commit()
            return redirect(url_for('client_portal'))

    return render_template('change_password_client.html', error=error, mobile=user.mobile)


@app.route('/client/portal')
@client_portal_required
def client_portal():
    user = db.session.get(ClientPortalUser, session['client_id'])
    if not user or not user.enabled:
        session.pop('client_id', None)
        return redirect(url_for('login'))
    return render_template('client_portal.html', user=user)


@app.route('/')
@login_required
def dashboard():
    user = db.session.get(Admin, session['admin_id'])
    servers = get_accessible_servers(user)
    
    base_cost_day = get_config('cost_per_day', 0)
    base_cost_gb = get_config('cost_per_gb', 0)
    base_cost_day_unlimited = get_config('cost_per_day_unlimited', 0)

    # Calculate user-specific costs
    user_cost_day = calculate_reseller_price(user, base_price=base_cost_day, cost_type='day')
    user_cost_gb = calculate_reseller_price(user, base_price=base_cost_gb, cost_type='gb')
    user_cost_day_unlimited = calculate_reseller_price(user, base_price=base_cost_day_unlimited, cost_type='day')

    # Get active bank cards for payment forms
    bank_cards = BankCard.query.filter_by(is_active=True).all()

    return render_template('dashboard.html',
                         servers=servers,
                         server_count=len(servers),
                         admin_username=user.username,
                         is_superadmin=(user.role == 'superadmin' or user.is_superadmin),
                         role=user.role,
                         credit=user.credit,
                         base_cost_day=user_cost_day,
                         base_cost_gb=user_cost_gb,
                         base_cost_day_unlimited=user_cost_day_unlimited,
                         bank_cards=bank_cards)

@app.route('/servers')
@login_required
def servers_page():
    return render_template('servers.html',
                         admin_username=session.get('admin_username'),
                         is_superadmin=session.get('is_superadmin', False),
                         role=session.get('role', 'admin'))


@app.route('/monitor')
@login_required
def monitor_page():
    return render_template('monitor.html',
                         admin_username=session.get('admin_username'),
                         is_superadmin=session.get('is_superadmin', False),
                         role=session.get('role', 'admin'))


@app.route('/royalty')
@login_required
def royalty_page():
    return render_template('royalty.html',
                         admin_username=session.get('admin_username'),
                         is_superadmin=session.get('is_superadmin', False),
                         role=session.get('role', 'admin'))


@app.route('/api/royalty/idle', methods=['GET'])
@login_required
def royalty_idle_clients():
    """List ACTIVE accounts that used NO traffic over the last `days` window.

    An account is "idle" when its current cumulative usage (up+down) equals the
    usage recorded at the start of the window — i.e. no bytes moved.
    Supports server_id and reseller_id filters.
    """
    days = _parse_int(request.args.get('days'), 1, min_value=1, max_value=365)
    server_filter = request.args.get('server_id')
    reseller_filter = request.args.get('reseller_id')
    try:
        server_filter = int(server_filter) if server_filter not in (None, '', 'all') else None
    except Exception:
        server_filter = None
    try:
        reseller_filter = int(reseller_filter) if reseller_filter not in (None, '', 'all') else None
    except Exception:
        reseller_filter = None

    user = db.session.get(Admin, session['admin_id'])
    is_reseller = bool(user and user.role == 'reseller')

    window_start = datetime.utcnow() - timedelta(days=days)

    # 1) Earliest snapshot per (server_id, sub_id) at/after window_start → baseline usage
    baseline = {}  # (server_id, sub_id) -> total_bytes
    try:
        rows = db.session.execute(text(
            """
            SELECT server_id, sub_id, total_bytes FROM (
                SELECT server_id, sub_id, total_bytes,
                       ROW_NUMBER() OVER (PARTITION BY server_id, sub_id ORDER BY recorded_at ASC) AS rn
                FROM usage_snapshots
                WHERE recorded_at >= :start
            ) t WHERE rn = 1
            """
        ), {'start': window_start}).fetchall()
        for r in rows:
            baseline[(int(r[0]), str(r[1]))] = int(r[2] or 0)
    except Exception as exc:
        app.logger.warning(f"royalty baseline query failed: {exc}")
        return jsonify({'success': False, 'error': 'Usage history not available yet. Try a smaller window.'}), 200

    # 2) Reseller ownership maps (for filtering + labeling)
    email_map, uuid_map = _get_ownership_maps()

    # 3) Walk current cached clients and pick the idle ones
    idle = []
    snapshot = GLOBAL_SERVER_DATA.get('inbounds') or []
    for inbound in snapshot:
        try:
            sid = int(inbound.get('server_id'))
        except Exception:
            continue
        if server_filter is not None and sid != server_filter:
            continue
        server_name = inbound.get('server_name') or ''
        for c in (inbound.get('clients') or []):
            if not c.get('enable', True):
                continue
            sub_id = str(c.get('subId') or '').strip()
            if not sub_id:
                continue
            base = baseline.get((sid, sub_id))
            if base is None:
                continue  # no history at window start → can't classify
            current_total = int(c.get('up', 0) or 0) + int(c.get('down', 0) or 0)
            if current_total != base:
                continue  # had traffic → not idle

            # Ownership / reseller resolution
            uu = str(c.get('id') or '').strip().lower()
            em = (c.get('email') or '').strip().lower()
            owner = (uuid_map.get((sid, uu)) if uu else None) or (email_map.get((sid, em)) if em else None)
            owner_id = owner.get('id') if owner else None
            owner_username = owner.get('username') if owner else None

            if is_reseller:
                if owner_id != user.id:
                    continue
            elif reseller_filter is not None:
                if reseller_filter == 0:
                    if owner_id is not None:
                        continue  # only unassigned/system
                elif owner_id != reseller_filter:
                    continue

            idle.append({
                'email': c.get('email') or '',
                'comment': c.get('comment') or '',
                'server_id': sid,
                'server_name': server_name,
                'inbound_id': inbound.get('id'),
                'client_uuid': str(c.get('id') or ''),
                'sub_url': c.get('sub_url') or '',
                'dash_sub_url': c.get('dash_sub_url') or '',
                'expiryTime': c.get('expiryTime') or '',
                'remaining_formatted': c.get('remaining_formatted') or '',
                'total_used_formatted': format_bytes(current_total),
                'owner_username': owner_username,
                'is_online': bool(c.get('is_online')),
            })

    # Sort: by server then email
    idle.sort(key=lambda x: (x.get('server_name') or '', (x.get('email') or '').lower()))

    return jsonify({
        'success': True,
        'days': days,
        'count': len(idle),
        'clients': idle,
        'generated_at': datetime.utcnow().isoformat(),
    })


MERGER_MAX_UPLOAD_BYTES = 200 * 1024 * 1024
MERGER_DIR_NAME = 'merger'


def _merger_user_is_allowed():
    return bool(session.get('is_superadmin') or session.get('role') == 'superadmin')


def _merger_base_dir():
    path = os.path.join(app.instance_path, MERGER_DIR_NAME)
    os.makedirs(path, exist_ok=True)
    return path


def _merger_job_dir(job_id):
    safe_job = re.sub(r'[^a-f0-9-]', '', str(job_id or '').lower())
    if not safe_job:
        raise ValueError('Invalid merger job')
    path = os.path.abspath(os.path.join(_merger_base_dir(), safe_job))
    base = os.path.abspath(_merger_base_dir())
    if not (path == base or path.startswith(base + os.sep)):
        raise ValueError('Invalid merger job path')
    return path


def _merger_json_load(raw, default=None):
    if default is None:
        default = {}
    if isinstance(raw, (dict, list)):
        return raw
    if raw is None:
        return copy.deepcopy(default)
    try:
        parsed = json.loads(raw)
        return parsed if parsed is not None else copy.deepcopy(default)
    except Exception:
        return copy.deepcopy(default)


def _merger_json_dump(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'))


def _merger_table_names(conn):
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    return {str(row[0]) for row in rows}


def _merger_table_columns(conn, table_name):
    try:
        return [str(row[1]) for row in conn.execute(f'PRAGMA table_info("{table_name}")').fetchall()]
    except Exception:
        return []


def _merger_row_to_dict(row):
    return {key: row[key] for key in row.keys()}


def _merger_client_email(client):
    if not isinstance(client, dict):
        return ''
    return str(client.get('email') or client.get('remark') or client.get('id') or '').strip()


def _merger_bool(value):
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in ('1', 'true', 'yes', 'on')


def _merger_normalize_settings_for_export(settings_raw):
    settings = _merger_json_load(settings_raw, {})
    if not isinstance(settings, dict):
        return settings
    clients = settings.get('clients')
    if isinstance(clients, list):
        for client in clients:
            if isinstance(client, dict) and 'enable' in client:
                client['enable'] = _merger_bool(client.get('enable'))
    return settings


def _merger_traffic_rows(conn, inbound_ids):
    tables = _merger_table_names(conn)
    if 'client_traffics' not in tables:
        return {}
    cols = _merger_table_columns(conn, 'client_traffics')
    if 'inbound_id' not in cols:
        return {}

    traffic = defaultdict(dict)
    placeholders = ','.join(['?'] * len(inbound_ids))
    rows = conn.execute(
        f'SELECT * FROM client_traffics WHERE inbound_id IN ({placeholders})',
        [int(v) for v in inbound_ids],
    ).fetchall()
    for row in rows:
        item = _merger_row_to_dict(row)
        email = str(item.get('email') or '').strip()
        if email:
            traffic[int(item.get('inbound_id') or 0)][email] = item
    return traffic


def _merger_analyze_db(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        tables = _merger_table_names(conn)
        if 'inbounds' not in tables:
            raise ValueError('This SQLite database does not contain an inbounds table.')

        inbound_cols = _merger_table_columns(conn, 'inbounds')
        rows = conn.execute('SELECT * FROM inbounds ORDER BY id').fetchall()
        traffic_counts = defaultdict(int)
        if 'client_traffics' in tables and 'inbound_id' in _merger_table_columns(conn, 'client_traffics'):
            for row in conn.execute('SELECT inbound_id, COUNT(*) AS c FROM client_traffics GROUP BY inbound_id').fetchall():
                traffic_counts[int(row['inbound_id'] or 0)] = int(row['c'] or 0)

        inbounds = []
        for row in rows:
            item = _merger_row_to_dict(row)
            settings = _merger_json_load(item.get('settings'), {})
            clients = settings.get('clients') if isinstance(settings, dict) else []
            if not isinstance(clients, list):
                clients = []
            inbounds.append({
                'id': int(item.get('id')),
                'remark': item.get('remark') or item.get('tag') or f"Inbound {item.get('id')}",
                'port': item.get('port'),
                'protocol': item.get('protocol') or '-',
                'enable': bool(item.get('enable')),
                'client_count': len(clients),
                'traffic_rows': traffic_counts[int(item.get('id') or 0)],
                'up': int(item.get('up') or 0) if 'up' in inbound_cols else 0,
                'down': int(item.get('down') or 0) if 'down' in inbound_cols else 0,
                'total': int(item.get('total') or 0) if 'total' in inbound_cols else 0,
            })
        return {
            'inbounds': inbounds,
            'tables': sorted(list(tables)),
            'has_client_traffics': 'client_traffics' in tables,
        }
    finally:
        conn.close()


def _merger_make_unique_email(email, used):
    base = (email or 'client').strip() or 'client'
    if base not in used:
        used.add(base)
        return base, None
    counter = 2
    while True:
        candidate = f'{base}-m{counter}'
        if candidate not in used:
            used.add(candidate)
            return candidate, candidate
        counter += 1


def _merger_export_inbound(row, client_stats=None):
    raw = dict(row)
    export = {}
    camel = {
        'user_id': 'userId',
        'expiry_time': 'expiryTime',
        'stream_settings': 'streamSettings',
    }
    allowed = {
        'id', 'userId', 'up', 'down', 'total', 'remark', 'enable', 'expiryTime',
        'listen', 'port', 'protocol', 'settings', 'streamSettings', 'tag',
        'sniffing', 'allocate',
    }
    json_fields = {'settings', 'stream_settings', 'streamSettings', 'sniffing', 'allocate'}

    for key, value in raw.items():
        out_key = camel.get(key, key)
        if out_key not in allowed:
            continue
        if key == 'settings':
            export[out_key] = _merger_normalize_settings_for_export(value)
        elif key in json_fields or out_key in json_fields:
            export[out_key] = _merger_json_load(value, {})
        elif out_key == 'enable':
            export[out_key] = _merger_bool(value)
        else:
            export[out_key] = value

    if 'settings' in export and isinstance(export['settings'], dict):
        export['settings'] = _merger_json_dump(export['settings'])
    if 'streamSettings' in export and isinstance(export['streamSettings'], dict):
        export['streamSettings'] = _merger_json_dump(export['streamSettings'])
    if 'sniffing' in export and isinstance(export['sniffing'], dict):
        export['sniffing'] = _merger_json_dump(export['sniffing'])
    if 'allocate' in export and isinstance(export['allocate'], dict):
        export['allocate'] = _merger_json_dump(export['allocate'])
    export['clientStats'] = client_stats or []
    return export


def _merger_merge_db(job_id, selected_ids, base_id, final_port, final_remark=None):
    if len(selected_ids) < 2:
        raise ValueError('Select at least two inbounds to merge.')
    selected_ids = [int(v) for v in selected_ids]
    base_id = int(base_id or selected_ids[0])
    if base_id not in selected_ids:
        raise ValueError('Base inbound must be one of the selected inbounds.')
    final_port = int(final_port)
    if final_port < 1 or final_port > 65535:
        raise ValueError('Final port must be between 1 and 65535.')

    job_dir = _merger_job_dir(job_id)
    source_db = os.path.join(job_dir, 'source.db')
    output_db = os.path.join(job_dir, 'merged.db')
    export_path = os.path.join(job_dir, 'merged-inbound.json')
    if not os.path.exists(source_db):
        raise ValueError('Uploaded database was not found. Upload it again.')

    shutil.copy2(source_db, output_db)
    conn = sqlite3.connect(output_db)
    conn.row_factory = sqlite3.Row
    try:
        tables = _merger_table_names(conn)
        if 'inbounds' not in tables:
            raise ValueError('This SQLite database does not contain an inbounds table.')
        inbound_cols = _merger_table_columns(conn, 'inbounds')
        placeholders = ','.join(['?'] * len(selected_ids))
        rows = conn.execute(
            f'SELECT * FROM inbounds WHERE id IN ({placeholders}) ORDER BY id',
            selected_ids,
        ).fetchall()
        by_id = {int(row['id']): _merger_row_to_dict(row) for row in rows}
        missing = [v for v in selected_ids if v not in by_id]
        if missing:
            raise ValueError(f'Inbound not found: {missing[0]}')

        traffic_by_inbound = _merger_traffic_rows(conn, selected_ids)
        merged_clients = []
        duplicate_report = []
        traffic_to_insert = []
        used_emails = set()

        for inbound_id in selected_ids:
            inbound = by_id[inbound_id]
            settings = _merger_json_load(inbound.get('settings'), {})
            clients = settings.get('clients') if isinstance(settings, dict) else []
            if not isinstance(clients, list):
                clients = []
            for client in clients:
                if not isinstance(client, dict):
                    continue
                copied = copy.deepcopy(client)
                original_email = _merger_client_email(copied)
                final_email, renamed = _merger_make_unique_email(original_email, used_emails)
                if final_email != original_email:
                    copied['email'] = final_email
                    duplicate_report.append({
                        'inbound_id': inbound_id,
                        'original': original_email,
                        'renamed': final_email,
                    })
                merged_clients.append(copied)

                traffic_row = traffic_by_inbound.get(int(inbound_id), {}).get(original_email)
                if traffic_row:
                    traffic_copy = dict(traffic_row)
                    traffic_copy['inbound_id'] = base_id
                    traffic_copy['email'] = final_email
                    traffic_copy.pop('id', None)
                    traffic_to_insert.append(traffic_copy)

        base_row = by_id[base_id]
        base_settings = _merger_json_load(base_row.get('settings'), {})
        if not isinstance(base_settings, dict):
            base_settings = {}
        base_settings['clients'] = merged_clients

        updates = {'settings': _merger_json_dump(base_settings)}
        if 'port' in inbound_cols:
            updates['port'] = final_port
        if final_remark and 'remark' in inbound_cols:
            updates['remark'] = str(final_remark).strip()
        if 'up' in inbound_cols:
            updates['up'] = sum(int((by_id[i].get('up') or 0)) for i in selected_ids)
        if 'down' in inbound_cols:
            updates['down'] = sum(int((by_id[i].get('down') or 0)) for i in selected_ids)

        assignments = ', '.join([f'"{key}" = ?' for key in updates.keys()])
        conn.execute(
            f'UPDATE inbounds SET {assignments} WHERE id = ?',
            list(updates.values()) + [base_id],
        )

        delete_ids = [v for v in selected_ids if v != base_id]
        if delete_ids:
            delete_placeholders = ','.join(['?'] * len(delete_ids))
            conn.execute(f'DELETE FROM inbounds WHERE id IN ({delete_placeholders})', delete_ids)

        if 'client_traffics' in tables:
            traffic_cols = [c for c in _merger_table_columns(conn, 'client_traffics') if c != 'id']
            if 'inbound_id' in traffic_cols:
                conn.execute(
                    f'DELETE FROM client_traffics WHERE inbound_id IN ({placeholders})',
                    selected_ids,
                )
            if 'inbound_id' in traffic_cols and traffic_to_insert:
                insert_cols = [c for c in traffic_cols if any(c in row for row in traffic_to_insert)]
                quoted_cols = ', '.join([f'"{c}"' for c in insert_cols])
                insert_sql = (
                    f'INSERT INTO client_traffics ({quoted_cols}) '
                    f'VALUES ({", ".join(["?"] * len(insert_cols))})'
                )
                for row in traffic_to_insert:
                    conn.execute(insert_sql, [row.get(c) for c in insert_cols])

        conn.commit()

        final_row = conn.execute('SELECT * FROM inbounds WHERE id = ?', [base_id]).fetchone()
        client_stats = []
        if 'client_traffics' in tables and 'inbound_id' in _merger_table_columns(conn, 'client_traffics'):
            for stat_row in conn.execute('SELECT * FROM client_traffics WHERE inbound_id = ? ORDER BY id', [base_id]).fetchall():
                raw_stat = _merger_row_to_dict(stat_row)
                client_stats.append({
                    'id': raw_stat.get('id'),
                    'inboundId': raw_stat.get('inbound_id'),
                    'enable': _merger_bool(raw_stat.get('enable')),
                    'email': raw_stat.get('email') or '',
                    'up': raw_stat.get('up') or 0,
                    'down': raw_stat.get('down') or 0,
                    'expiryTime': raw_stat.get('expiry_time', raw_stat.get('expiryTime')) or 0,
                    'total': raw_stat.get('total') or 0,
                    'reset': raw_stat.get('reset') or 0,
                })
        export_payload = _merger_export_inbound(_merger_row_to_dict(final_row), client_stats)
        with open(export_path, 'w', encoding='utf-8') as fh:
            json.dump(export_payload, fh, ensure_ascii=False, indent=2)

        return {
            'base_inbound_id': base_id,
            'final_port': final_port,
            'client_count': len(merged_clients),
            'renamed_duplicates': duplicate_report,
        }
    finally:
        conn.close()


# ── Inbound Transform (protocol / transport / emails / port) ─────────────────
# Offline rebuild of a single inbound inside the uploaded x-ui DB. Lets you do
# what the x-ui panel forbids: change an inbound's protocol while keeping all of
# its clients (their fields are remapped to the target protocol's shape).

MERGER_TRANSFORM_PROTOCOLS = ('vless', 'vmess', 'trojan', 'shadowsocks')
MERGER_SS_METHODS = (
    'chacha20-ietf-poly1305', 'aes-256-gcm', 'aes-128-gcm',
    '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305',
)


def _ss_key_len(method: str) -> int:
    m = (method or '').lower()
    if '128' in m:
        return 16
    return 32  # aes-256-gcm, chacha20-ietf-poly1305, 2022-256 variants


def _ss_password(method: str) -> str:
    return base64.b64encode(os.urandom(_ss_key_len(method))).decode('ascii')


# Protocol families: 'client' protocols share x-ui's per-client quota model and
# transform losslessly. The others use a different user model entirely.
MERGER_CLIENT_FAMILY = ('vless', 'vmess', 'trojan', 'shadowsocks')
MERGER_ACCOUNT_FAMILY = ('socks', 'http')
MERGER_ALL_TARGETS = MERGER_CLIENT_FAMILY + MERGER_ACCOUNT_FAMILY + ('dokodemo-door', 'wireguard')


def _wg_keypair():
    """Return (private_b64, public_b64) Curve25519 keys in WireGuard format."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    priv = X25519PrivateKey.generate()
    priv_raw = priv.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(priv_raw).decode('ascii'), base64.b64encode(pub_raw).decode('ascii')


def _transform_client(src: dict, target_protocol: str, ss_method: str,
                      email_prefix: str, email_suffix: str) -> dict:
    """Remap one client dict from its source shape to the target protocol's shape,
    keeping the cross-protocol fields (quota/expiry/sub/etc.)."""
    src = src if isinstance(src, dict) else {}
    old_email = _merger_client_email(src) or 'client'
    new_email = f'{email_prefix}{old_email}{email_suffix}'

    def _i(v, d=0):
        try:
            return int(v)
        except (TypeError, ValueError):
            return d

    common = {
        'email': new_email,
        'enable': _merger_bool(src.get('enable', True)),
        'limitIp': _i(src.get('limitIp'), 0),
        'totalGB': _i(src.get('totalGB'), 0),
        'expiryTime': _i(src.get('expiryTime'), 0),
        'tgId': src.get('tgId', 0) if src.get('tgId') not in (None, '') else 0,
        'subId': src.get('subId') or '',
        'comment': src.get('comment') or '',
        'reset': _i(src.get('reset'), 0),
    }

    if target_protocol == 'vless':
        common['id'] = src.get('id') or str(uuid.uuid4())
        common['flow'] = src.get('flow') or ''
    elif target_protocol == 'vmess':
        common['id'] = src.get('id') or str(uuid.uuid4())
    elif target_protocol == 'trojan':
        common['password'] = src.get('password') or secrets.token_urlsafe(16)
    elif target_protocol == 'shadowsocks':
        common['method'] = ss_method
        # Reuse an existing SS password only if it already matches the method length.
        existing = src.get('password') or ''
        try:
            existing_len = len(base64.b64decode(existing)) if existing else 0
        except Exception:
            existing_len = 0
        common['password'] = existing if existing_len == _ss_key_len(ss_method) else _ss_password(ss_method)
    return common, old_email, new_email


def _build_inbound_settings(target_protocol: str, clients: list,
                            ss_method: str, existing_settings: dict) -> dict:
    if target_protocol == 'vless':
        return {'clients': clients, 'decryption': 'none', 'fallbacks': []}
    if target_protocol == 'vmess':
        return {'clients': clients}
    if target_protocol == 'trojan':
        return {'clients': clients, 'fallbacks': []}
    if target_protocol == 'shadowsocks':
        return {
            'clients': clients,
            'method': ss_method,
            'password': _ss_password(ss_method),
            'network': 'tcp,udp',
            'ivCheck': False,
        }
    # Fallback: keep existing structure, just swap clients.
    out = dict(existing_settings or {})
    out['clients'] = clients
    return out


def _build_stream_settings(existing: dict, transport: str, security: str,
                           target_protocol: str) -> dict:
    ss = copy.deepcopy(existing) if isinstance(existing, dict) else {}
    ss.setdefault('externalProxy', [])

    # ── Security ──
    if security == 'none':
        ss['security'] = 'none'
        for k in ('tlsSettings', 'realitySettings', 'xtlsSettings'):
            ss.pop(k, None)
    # security == 'keep' → leave as-is

    # ── Transport ──
    if transport != 'keep':
        for k in ('tcpSettings', 'wsSettings', 'grpcSettings', 'httpSettings',
                  'kcpSettings', 'quicSettings', 'httpupgradeSettings'):
            ss.pop(k, None)
        if transport == 'tcp':
            ss['network'] = 'tcp'
            ss['tcpSettings'] = {'acceptProxyProtocol': False, 'header': {'type': 'none'}}
        elif transport == 'tcp_http':
            ss['network'] = 'tcp'
            ss['tcpSettings'] = {
                'acceptProxyProtocol': False,
                'header': {
                    'type': 'http',
                    'request': {'version': '1.1', 'method': 'GET', 'path': ['/'], 'headers': {}},
                    'response': {'version': '1.1', 'status': '200', 'reason': 'OK', 'headers': {}},
                },
            }
        elif transport == 'ws':
            ss['network'] = 'ws'
            ss['wsSettings'] = {'path': '/', 'headers': {}}
        elif transport == 'grpc':
            ss['network'] = 'grpc'
            ss['grpcSettings'] = {'serviceName': '', 'multiMode': False}
        elif transport == 'h2':
            ss['network'] = 'http'
            ss['httpSettings'] = {'path': '/', 'host': []}
    else:
        # Keeping the transport, but Shadowsocks doesn't use TCP http-header
        # obfuscation — normalize it to avoid an unusable config.
        if target_protocol == 'shadowsocks' and (ss.get('network') == 'tcp'):
            tcp = ss.get('tcpSettings') or {}
            if isinstance(tcp.get('header'), dict) and tcp['header'].get('type') == 'http':
                ss['tcpSettings'] = {'acceptProxyProtocol': False, 'header': {'type': 'none'}}
    return ss


def _merger_transform_db(job_id, inbound_id, opts):
    job_dir = _merger_job_dir(job_id)
    source_db = os.path.join(job_dir, 'source.db')
    output_db = os.path.join(job_dir, 'merged.db')
    export_path = os.path.join(job_dir, 'merged-inbound.json')
    if not os.path.exists(source_db):
        raise ValueError('Uploaded database was not found. Upload it again.')

    inbound_id = int(inbound_id)
    target_protocol = (opts.get('protocol') or 'keep').strip().lower()
    ss_method = (opts.get('ss_method') or 'chacha20-ietf-poly1305').strip()
    transport = (opts.get('transport') or 'keep').strip().lower()
    security = (opts.get('security') or 'keep').strip().lower()
    email_prefix = str(opts.get('email_prefix') or '')
    email_suffix = str(opts.get('email_suffix') or '')
    new_port = opts.get('port')
    new_remark = opts.get('remark')

    if target_protocol not in ('keep',) + MERGER_ALL_TARGETS:
        raise ValueError('Unsupported target protocol.')
    if target_protocol == 'shadowsocks' and ss_method not in MERGER_SS_METHODS:
        raise ValueError('Unsupported Shadowsocks method.')
    if new_port is not None and str(new_port).strip() != '':
        new_port = int(new_port)
        if new_port < 1 or new_port > 65535:
            raise ValueError('Port must be between 1 and 65535.')
    else:
        new_port = None

    shutil.copy2(source_db, output_db)
    conn = sqlite3.connect(output_db)
    conn.row_factory = sqlite3.Row
    try:
        tables = _merger_table_names(conn)
        if 'inbounds' not in tables:
            raise ValueError('This SQLite database does not contain an inbounds table.')
        inbound_cols = _merger_table_columns(conn, 'inbounds')

        row = conn.execute('SELECT * FROM inbounds WHERE id = ?', [inbound_id]).fetchone()
        if not row:
            raise ValueError(f'Inbound {inbound_id} not found.')
        inbound = _merger_row_to_dict(row)

        source_protocol = (inbound.get('protocol') or 'vless').lower()
        final_protocol = source_protocol if target_protocol == 'keep' else target_protocol

        settings = _merger_json_load(inbound.get('settings'), {})
        src_clients = settings.get('clients') if isinstance(settings, dict) else []
        if not isinstance(src_clients, list):
            src_clients = []

        rename_map = {}     # old_email -> new_email  (only for client-family)
        client_count = 0
        drop_traffic = False  # for non-client families, the old per-client rows no longer apply

        def _renamed_email(c):
            old = _merger_client_email(c) or 'client'
            return old, f'{email_prefix}{old}{email_suffix}'

        if final_protocol in MERGER_CLIENT_FAMILY:
            new_clients = []
            for c in src_clients:
                tc, old_email, new_email = _transform_client(c, final_protocol, ss_method, email_prefix, email_suffix)
                new_clients.append(tc)
                if old_email:
                    rename_map[old_email] = new_email
            new_settings = _build_inbound_settings(final_protocol, new_clients, ss_method, settings if isinstance(settings, dict) else {})
            client_count = len(new_clients)

        elif final_protocol in MERGER_ACCOUNT_FAMILY:
            # socks / http → username/password accounts (no quota/expiry)
            accounts = []
            for c in src_clients:
                _, new_email = _renamed_email(c)
                accounts.append({'user': new_email, 'pass': secrets.token_urlsafe(12)})
            if final_protocol == 'socks':
                new_settings = {'auth': 'password', 'accounts': accounts, 'udp': True, 'ip': ''}
            else:  # http
                new_settings = {'accounts': accounts, 'allowTransparent': False}
            client_count = len(accounts)
            drop_traffic = True

        elif final_protocol == 'dokodemo-door':
            addr = str(opts.get('dokodemo_address') or '127.0.0.1').strip() or '127.0.0.1'
            try:
                dport = int(opts.get('dokodemo_port') or 0)
            except (TypeError, ValueError):
                dport = 0
            if dport <= 0:
                dport = int(new_port or inbound.get('port') or 0)
            new_settings = {
                'address': addr,
                'port': dport,
                'network': 'tcp,udp',
                'followRedirect': False,
                'portMap': {},
            }
            client_count = 0
            drop_traffic = True

        elif final_protocol == 'wireguard':
            server_priv, _server_pub = _wg_keypair()
            peers = []
            for i, c in enumerate(src_clients):
                p_priv, p_pub = _wg_keypair()
                peers.append({
                    'privateKey': p_priv,
                    'publicKey': p_pub,
                    'psk': '',
                    'allowedIPs': [f'10.0.0.{(i % 250) + 2}/32'],
                    'keepAlive': 0,
                })
            new_settings = {'mtu': 1420, 'secretKey': server_priv, 'peers': peers, 'noKernelTun': False}
            client_count = len(peers)
            drop_traffic = True
        else:
            # Fallback: keep clients shape unchanged
            new_settings = settings if isinstance(settings, dict) else {}

        existing_stream = _merger_json_load(inbound.get('streamSettings') or inbound.get('stream_settings'), {})
        new_stream = _build_stream_settings(existing_stream, transport, security, final_protocol)

        updates = {
            'protocol': final_protocol,
            'settings': _merger_json_dump(new_settings),
        }
        if 'streamSettings' in inbound_cols:
            updates['streamSettings'] = _merger_json_dump(new_stream)
        elif 'stream_settings' in inbound_cols:
            updates['stream_settings'] = _merger_json_dump(new_stream)
        if new_port is not None and 'port' in inbound_cols:
            updates['port'] = new_port
            if 'tag' in inbound_cols:
                updates['tag'] = f'inbound-{new_port}'
        if new_remark is not None and str(new_remark).strip() != '' and 'remark' in inbound_cols:
            updates['remark'] = str(new_remark).strip()

        assignments = ', '.join([f'"{k}" = ?' for k in updates.keys()])
        conn.execute(f'UPDATE inbounds SET {assignments} WHERE id = ?',
                     list(updates.values()) + [inbound_id])

        # Traffic rows: rename for the client family, drop for the others
        # (socks/http accounts, dokodemo forwarder and wireguard peers have no
        # per-client traffic rows, so leaving the old ones would show ghosts).
        renamed_traffic = 0
        if 'client_traffics' in tables:
            tcols = _merger_table_columns(conn, 'client_traffics')
            if 'inbound_id' in tcols:
                if drop_traffic:
                    conn.execute('DELETE FROM client_traffics WHERE inbound_id = ?', [inbound_id])
                elif 'email' in tcols:
                    for old_email, new_email in rename_map.items():
                        if old_email == new_email:
                            continue
                        cur = conn.execute(
                            'UPDATE client_traffics SET email = ? WHERE inbound_id = ? AND email = ?',
                            [new_email, inbound_id, old_email])
                        renamed_traffic += cur.rowcount or 0

        conn.commit()

        final_row = conn.execute('SELECT * FROM inbounds WHERE id = ?', [inbound_id]).fetchone()
        client_stats = []
        if 'client_traffics' in tables and 'inbound_id' in _merger_table_columns(conn, 'client_traffics'):
            for stat_row in conn.execute('SELECT * FROM client_traffics WHERE inbound_id = ? ORDER BY id', [inbound_id]).fetchall():
                raw_stat = _merger_row_to_dict(stat_row)
                client_stats.append({
                    'id': raw_stat.get('id'),
                    'inboundId': raw_stat.get('inbound_id'),
                    'enable': _merger_bool(raw_stat.get('enable')),
                    'email': raw_stat.get('email') or '',
                    'up': raw_stat.get('up') or 0,
                    'down': raw_stat.get('down') or 0,
                    'expiryTime': raw_stat.get('expiry_time', raw_stat.get('expiryTime')) or 0,
                    'total': raw_stat.get('total') or 0,
                    'reset': raw_stat.get('reset') or 0,
                })
        export_payload = _merger_export_inbound(_merger_row_to_dict(final_row), client_stats)
        with open(export_path, 'w', encoding='utf-8') as fh:
            json.dump(export_payload, fh, ensure_ascii=False, indent=2)

        return {
            'inbound_id': inbound_id,
            'source_protocol': source_protocol,
            'final_protocol': final_protocol,
            'client_count': client_count,
            'emails_renamed': sum(1 for o, n in rename_map.items() if o != n),
            'traffic_rows_updated': renamed_traffic,
            'quota_preserved': final_protocol in MERGER_CLIENT_FAMILY,
            'final_port': new_port if new_port is not None else inbound.get('port'),
        }
    finally:
        conn.close()


@app.route('/merger')
@login_required
def merger_page():
    if not _merger_user_is_allowed():
        return redirect(url_for('dashboard'))
    return render_template('merger.html',
                         admin_username=session.get('admin_username'),
                         is_superadmin=session.get('is_superadmin', False),
                         role=session.get('role', 'admin'))


@app.route('/api/merger/analyze', methods=['POST'])
@login_required
def merger_analyze():
    if not _merger_user_is_allowed():
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    upload = request.files.get('database')
    if not upload or not upload.filename:
        return jsonify({'success': False, 'error': 'Upload an x-ui SQLite database file.'}), 400
    if request.content_length and request.content_length > MERGER_MAX_UPLOAD_BYTES:
        return jsonify({'success': False, 'error': 'Database file is too large.'}), 413

    job_id = str(uuid.uuid4())
    job_dir = _merger_job_dir(job_id)
    os.makedirs(job_dir, exist_ok=True)
    source_db = os.path.join(job_dir, 'source.db')
    upload.save(source_db)

    try:
        analysis = _merger_analyze_db(source_db)
    except Exception as exc:
        shutil.rmtree(job_dir, ignore_errors=True)
        return jsonify({'success': False, 'error': str(exc)}), 400

    return jsonify({'success': True, 'job_id': job_id, **analysis})


@app.route('/api/merger/merge', methods=['POST'])
@login_required
def merger_merge():
    if not _merger_user_is_allowed():
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    data = request.get_json(silent=True) or {}
    try:
        result = _merger_merge_db(
            data.get('job_id'),
            data.get('inbound_ids') or [],
            data.get('base_inbound_id'),
            data.get('final_port'),
            data.get('remark'),
        )
    except Exception as exc:
        return jsonify({'success': False, 'error': str(exc)}), 400

    job_id = str(data.get('job_id') or '')
    return jsonify({
        'success': True,
        **result,
        'downloads': {
            'database': url_for('merger_download', job_id=job_id, kind='db'),
            'inbound_export': url_for('merger_download', job_id=job_id, kind='export'),
        }
    })


@app.route('/api/merger/transform', methods=['POST'])
@login_required
def merger_transform():
    if not _merger_user_is_allowed():
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    data = request.get_json(silent=True) or {}
    job_id = str(data.get('job_id') or '')
    try:
        result = _merger_transform_db(
            job_id,
            data.get('inbound_id'),
            {
                'protocol': data.get('protocol'),
                'ss_method': data.get('ss_method'),
                'transport': data.get('transport'),
                'security': data.get('security'),
                'port': data.get('port'),
                'remark': data.get('remark'),
                'email_prefix': data.get('email_prefix'),
                'email_suffix': data.get('email_suffix'),
                'dokodemo_address': data.get('dokodemo_address'),
                'dokodemo_port': data.get('dokodemo_port'),
            },
        )
    except Exception as exc:
        return jsonify({'success': False, 'error': str(exc)}), 400

    return jsonify({
        'success': True,
        **result,
        'downloads': {
            'database': url_for('merger_download', job_id=job_id, kind='db'),
            'inbound_export': url_for('merger_download', job_id=job_id, kind='export'),
        }
    })


@app.route('/api/merger/download/<job_id>/<kind>')
@login_required
def merger_download(job_id, kind):
    if not _merger_user_is_allowed():
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    job_dir = _merger_job_dir(job_id)
    if kind == 'db':
        path = os.path.join(job_dir, 'merged.db')
        filename = 'x-ui-merged.db'
    elif kind == 'export':
        path = os.path.join(job_dir, 'merged-inbound.json')
        filename = 'x-ui-merged-inbound.json'
    else:
        return jsonify({'success': False, 'error': 'Invalid download type'}), 404
    if not os.path.exists(path):
        return jsonify({'success': False, 'error': 'Merged output not found'}), 404
    return send_file(path, as_attachment=True, download_name=filename)


@app.route('/healthz', methods=['GET'])
def healthz():
    """Lightweight health endpoint for reverse-proxy / uptime checks."""
    db_ok = True
    try:
        db.session.execute(text('SELECT 1'))
        db.session.rollback()
    except Exception:
        db_ok = False
    status = 'ok' if db_ok else 'degraded'
    code = 200 if db_ok else 503
    return jsonify({
        'success': db_ok,
        'status': status,
        'db': 'ok' if db_ok else 'unreachable',
        'version': APP_VERSION,
        'uptime_seconds': int(max(0, time.time() - APP_START_TS)),
        'timestamp_utc': datetime.utcnow().isoformat() + 'Z',
    }), code


@app.route('/api/monitor/settings', methods=['GET'])
@login_required
def get_monitor_settings():
    return jsonify({
        'success': True,
        'settings': _get_monitor_settings(),
        'timezone': _get_app_timezone_name(),
        'timezone_options': _get_standard_timezone_options(),
    })


@app.route('/api/monitor/settings', methods=['POST'])
@login_required
def save_monitor_settings():
    try:
        payload = request.get_json() or {}
    except Exception:
        payload = {}

    timezone_name = (payload.get('timezone') or '').strip()
    if timezone_name and not _is_valid_timezone_name(timezone_name):
        return jsonify({'success': False, 'error': 'Invalid timezone. Example: Asia/Tehran'}), 400

    normalized = _normalize_monitor_settings(payload)
    try:
        if timezone_name:
            _set_system_setting_value(GENERAL_TIMEZONE_SETTING_KEY, timezone_name)
        _set_system_setting_value(
            MONITOR_SETTINGS_KEY,
            json.dumps(normalized, ensure_ascii=False)
        )
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        app.logger.error('save_monitor_settings: DB commit failed: %s', exc)
        return jsonify({'success': False, 'error': f'Database error: {exc}'}), 500
    return jsonify({
        'success': True,
        'settings': normalized,
        'timezone': _get_app_timezone_name(),
        'timezone_options': _get_standard_timezone_options(),
    })


@app.route('/api/monitor/alerts', methods=['GET'])
@login_required
def get_monitor_alerts():
    user = db.session.get(Admin, session['admin_id'])
    settings = _get_monitor_settings()
    filters = settings.get('filters', {})

    now_utc = datetime.utcnow()

    warning_days = int(filters.get('warning_days', 3) or 3)
    warning_gb = float(filters.get('warning_gb', 2.0) or 2.0)
    hide_days = int(filters.get('hide_days', 7) or 7)
    debug = bool(filters.get('debug'))

    inbounds = GLOBAL_SERVER_DATA.get('inbounds') or []

    allowed_map, assignments = ('*', {})
    owned_emails_by_server = defaultdict(set)
    reseller_owned_email_pairs = set()
    reseller_owned_uuid_pairs = set()
    if user and user.role == 'reseller':
        allowed_map, assignments = get_reseller_access_maps(user)
        ownerships = ClientOwnership.query.filter_by(reseller_id=user.id).all()
        for own in ownerships:
            try:
                sid = int(own.server_id)
            except Exception:
                continue
            email_l = (own.client_email or '').strip().lower()
            if email_l:
                owned_emails_by_server[sid].add(email_l)
    elif user:
        server_ids = set()
        for inbound in inbounds:
            try:
                sid = int(inbound.get('server_id'))
            except Exception:
                continue
            server_ids.add(sid)

        if server_ids:
            ownerships = ClientOwnership.query.filter(ClientOwnership.server_id.in_(list(server_ids))).all()
            for own in ownerships:
                try:
                    sid = int(own.server_id)
                except Exception:
                    continue

                email_l = (own.client_email or '').strip().lower()
                if email_l:
                    reseller_owned_email_pairs.add((sid, email_l))

                client_uuid_l = str(own.client_uuid or '').strip().lower()
                if client_uuid_l:
                    reseller_owned_uuid_pairs.add((sid, client_uuid_l))

    status_labels = {
        'ended': 'Ended',
        'expired': 'Expired',
        'low': 'Low data',
        'soon': 'Expiring soon',
        'disabled': 'Disabled (manual)',
        'ok': 'OK'
    }
    status_order = {
        'ended': 0,
        'expired': 1,
        'low': 2,
        'soon': 3,
        'disabled': 4,
        'ok': 5
    }

    alerts = []

    for inbound in inbounds:
        sid = inbound.get('server_id')
        inbound_id = inbound.get('id')

        if sid is None:
            continue

        if user and user.role == 'reseller':
            if not is_inbound_accessible(sid, inbound_id, allowed_map, assignments):
                continue

        for client in (inbound.get('clients') or []):
            email = (client.get('email') or '').strip()
            email_l = email.lower()
            client_uuid_l = str(client.get('id') or '').strip().lower()

            try:
                sid_norm = int(sid)
            except Exception:
                sid_norm = None

            is_reseller_owned = False
            if sid_norm is not None:
                if (sid_norm, email_l) in reseller_owned_email_pairs:
                    is_reseller_owned = True
                elif client_uuid_l and (sid_norm, client_uuid_l) in reseller_owned_uuid_pairs:
                    is_reseller_owned = True

            if user and user.role == 'reseller':
                if not owned_emails_by_server:
                    continue
                if sid_norm is None:
                    continue
                if email_l not in owned_emails_by_server.get(sid_norm, set()):
                    continue

            enabled = bool(client.get('enable', True))
            # IMPORTANT: We do NOT skip disabled clients here. Sanaei-style panels
            # auto-disable a client the instant its time or traffic runs out, so
            # filtering by the enable flag alone would hide exactly the users we
            # most need to follow up with. Instead, every client is categorized by
            # the REAL reason below (ended / expired / manual-disable).

            total_bytes = int(client.get('totalGB') or 0)
            remaining_bytes = client.get('remaining_bytes')
            if remaining_bytes is None or remaining_bytes == -1:
                if total_bytes > 0:
                    try:
                        used_bytes = int(client.get('up') or 0) + int(client.get('down') or 0)
                        remaining_bytes = max(total_bytes - used_bytes, 0)
                    except Exception:
                        remaining_bytes = None
                else:
                    remaining_bytes = None

            remaining_gb = None
            if remaining_bytes is not None:
                try:
                    remaining_gb = float(remaining_bytes) / (1024 ** 3)
                except Exception:
                    remaining_gb = None

            expiry_ts = int(client.get('expiryTimestamp') or 0)
            expiry_info = format_remaining_days(expiry_ts)

            status = None
            status_rank = -1

            # Traffic-based reason (applies whether or not the panel already disabled it)
            if total_bytes > 0 and remaining_bytes is not None:
                if remaining_bytes <= 0:
                    status = 'ended'
                    status_rank = 4
                elif remaining_gb is not None and remaining_gb < warning_gb:
                    status = 'low'
                    status_rank = 2

            # Time-based reason
            if expiry_ts and expiry_info.get('type') == 'expired':
                if status_rank < 3:
                    status = 'expired'
                    status_rank = 3
            elif expiry_ts and expiry_info.get('type') in ('today', 'soon'):
                if int(expiry_info.get('days') or 0) <= warning_days and status_rank < 1:
                    status = 'soon'
                    status_rank = 1

            # A disabled client whose time AND traffic are both still fine was
            # switched off by an operator — its own "manual disable" category,
            # kept separate from the auto-disabled (ended/expired) accounts.
            # 'low'/'soon' are active-user warnings, so they don't apply once off.
            if not enabled and status in (None, 'low', 'soon'):
                status = 'disabled'
                status_rank = 0

            # Hide long-expired garbage (date-based, independent of enable flag).
            if expiry_info.get('type') == 'expired' and not debug:
                try:
                    days_ago = abs(int(expiry_info.get('days') or 0))
                except Exception:
                    days_ago = 0
                if hide_days and days_ago > hide_days:
                    continue

            if not status and not debug:
                continue

            if not status:
                status = 'ok'

            expiry_date = None
            if expiry_ts and expiry_ts > 0:
                try:
                    expiry_dt = datetime.utcfromtimestamp(expiry_ts / 1000)
                    expiry_date = format_jalali(expiry_dt)
                except Exception:
                    expiry_date = None

            alerts.append({
                'server_id': sid,
                'server_name': inbound.get('server_name'),
                'inbound_id': inbound_id,
                'email': email,
                'comment': (client.get('comment') or '').strip(),
                'status': status,
                'status_label': status_labels.get(status, status),
                'remaining': client.get('remaining_formatted') or 'Unlimited',
                'time_left': expiry_info.get('text'),
                'expiry_date': expiry_date,
                'enabled': enabled,
                'is_reseller_owned': is_reseller_owned,
            })

    alerts.sort(key=lambda row: (
        status_order.get(row.get('status') or 'ok', 9),
        str(row.get('server_name') or ''),
        str(row.get('email') or '')
    ))

    return jsonify({
        'success': True,
        'settings': settings,
        'timezone': _get_app_timezone_name(),
        'generated_at': now_utc.isoformat(),
        'generated_at_jalali': format_jalali(now_utc),
        'alerts': alerts
    })


@app.route('/api/monitor/refresh', methods=['POST'])
@login_required
def trigger_monitor_refresh():
    # Force refresh of all servers (global mode)
    job = enqueue_refresh_job(mode='full', force=True)
    return jsonify({'success': True, 'job_id': job['id']})


@app.route('/api/monitor/job/<job_id>', methods=['GET'])
@login_required
def get_monitor_job_status(job_id):
    with REFRESH_JOBS_LOCK:
        job = REFRESH_JOBS.get(job_id)
    if not job:
        return jsonify({'success': False, 'error': 'Job not found'})
    return jsonify({'success': True, 'job': job})


@app.route('/admins')
@login_required
def admins_page():
    if session.get('role') == 'reseller':
        return redirect(url_for('dashboard'))
    return render_template('admins.html',
                         admin_username=session.get('admin_username'),
                         is_superadmin=session.get('is_superadmin', False),
                         role=session.get('role', 'admin'))

def fetch_worker(server_dict):
    with app.app_context():
        # Convert dict to object for compatibility with existing functions
        server_obj = SimpleNamespace(**server_dict)
        session_obj, error = get_xui_session(server_obj)
        if error:
            return server_dict['id'], None, None, None, None, error, 'auto'
        
        inbounds, fetch_error, detected_type = fetch_inbounds(session_obj, server_obj.host, server_obj.panel_type)
        # Onlines lives on the web-UI route which needs a cookie login; the v3
        # Bearer-token session can't reach it (404). Use a cookie session when
        # the panel is token-based (v3) but we have username/password.
        onlines_session = session_obj
        if get_server_api_token(server_obj) and getattr(server_obj, 'username', '') and getattr(server_obj, 'password', ''):
            _cookie = get_xui_cookie_session(
                server_obj.host, server_obj.username, server_obj.password,
                server_obj.panel_type, cache_key=f"sid:{server_dict['id']}")
            if _cookie is not None:
                onlines_session = _cookie
        online_index, _ = fetch_onlines(onlines_session, server_obj.host, server_obj.panel_type)
        status_payload, status_error, _status_type = fetch_server_status(session_obj, server_obj.host, server_obj.panel_type)

        # Enrich status_payload with online_count from the onlines endpoint
        # (the /status API does NOT return online_count; it comes from /onlines)
        if online_index:
            online_count = len(online_index.get('pairs', set())) + len(online_index.get('emails', set()))
            if status_payload is None:
                status_payload = {}
            if status_payload.get('online_count') is None and online_count > 0:
                status_payload['online_count'] = online_count

        return server_dict['id'], inbounds, online_index, status_payload, status_error, fetch_error, detected_type


def enrich_inbounds_with_ownership(inbounds):
    """Attach owner fields to inbound clients using the in-memory ownership cache.

    Old approach: built email/uuid sets → huge IN-clause DB query → second iteration.
    New approach: read from _OWNERSHIP_CACHE (rebuilt at most every 30 s); each
    client lookup is O(1) dict access.  No per-request DB query.
    """
    try:
        if not isinstance(inbounds, list) or not inbounds:
            return inbounds

        email_map, uuid_map = _get_ownership_maps()
        if not email_map and not uuid_map:
            return inbounds

        for inbound in inbounds:
            try:
                sid = int(inbound.get('server_id'))
            except Exception:
                continue
            for client in (inbound.get('clients') or []):
                uu = str(client.get('id') or '').strip().lower()
                em = (client.get('email') or '').strip().lower()
                info = uuid_map.get((sid, uu)) if uu else None
                if not info and em:
                    info = email_map.get((sid, em))
                if info and info.get('username'):
                    client['owner_reseller_id'] = info.get('id')
                    client['owner_username']    = info.get('username')
                else:
                    client.pop('owner_reseller_id', None)
                    client.pop('owner_username',    None)

    except Exception:
        app.logger.exception("Failed to enrich inbounds with ownership")
    return inbounds


@app.route('/api/refresh')
@login_required
def api_refresh():
    # Make sure background threads are running (covers gunicorn/uwsgi workers)
    if not os.environ.get('DISABLE_BACKGROUND_THREADS'):
        ensure_background_threads_started()

    force = _parse_bool(request.args.get('force'))
    wait = _parse_bool(request.args.get('wait'))
    server_id = request.args.get('server_id')
    mode = (request.args.get('mode') or 'cache').strip().lower()
    enqueue = request.args.get('enqueue')
    enqueue = _parse_bool(enqueue) if enqueue is not None else (mode in ('full', 'status'))
    wait_timeout = 2.0

    job = None
    if enqueue and mode in ('full', 'status'):
        job = enqueue_refresh_job(mode=mode, server_id=server_id, force=force)

    if wait and job:
        start = time.time()
        while (time.time() - start) < wait_timeout:
            with REFRESH_JOBS_LOCK:
                cur = REFRESH_JOBS.get(job.get('id'))
                if cur and cur.get('state') in ('done', 'error'):
                    job = cur
                    break
            time.sleep(0.15)

    debug_timing = _parse_bool(request.args.get('debug_timing'))
    t0 = time.perf_counter() if debug_timing else None

    data = copy.deepcopy(GLOBAL_SERVER_DATA)
    t_after_copy = time.perf_counter() if debug_timing else None

    never_fetched = not data.get('last_update')

    # Kick off a refresh job only when cache has never been populated (app start / first load)
    if not data.get('inbounds') and never_fetched and not GLOBAL_SERVER_DATA.get('is_updating') and not job:
        job = enqueue_refresh_job(mode='full', server_id=server_id, force=False)

    # Return early with skeleton response only when data was never fetched yet.
    # If last_update is set but inbounds is empty (server has 0 inbounds), fall through
    # so the full (empty) payload is returned and the UI can clear its skeleton.
    if not data.get('inbounds') and never_fetched:
        return jsonify({
            "success": True,
            "inbounds": [],
            "stats": {"total_inbounds": 0, "active_inbounds": 0, "total_clients": 0,
                      "online_clients": 0, "active_clients": 0, "inactive_clients": 0, "not_started_clients": 0, "unlimited_expiry_clients": 0, "unlimited_volume_clients": 0, "total_traffic": "0 B",
                      "total_upload": "0 B", "total_download": "0 B"},
            "servers": (data.get('servers_status') or []),
            "server_count": len(data.get('servers_status') or []),
            "is_updating": bool(GLOBAL_SERVER_DATA.get('is_updating')),
            "refresh_job": _summarize_job(job)
        }), (202 if job and job.get('state') in ('queued', 'running') else 200)

    user = db.session.get(Admin, session['admin_id'])
    
    # === حالت سوپرادمین (یا ادمین معمولی غیر ریسلر) ===
    if user.role != 'reseller':
        # Enrich with ownership using the in-memory cache (O(1) per client, no per-request DB query)
        enrich_inbounds_with_ownership(data.get('inbounds') or [])

        # Admins/superadmins see all cached data
        resp = {
            "success": True,
            "inbounds": data['inbounds'],
            "stats": data['stats'],
            "servers": data['servers_status'],
            "server_count": len(data['servers_status']),
            "last_update": data['last_update'],
            "is_updating": bool(GLOBAL_SERVER_DATA.get('is_updating')),
            "refresh_job": _summarize_job(job),
        }
        if debug_timing and t0 is not None and t_after_copy is not None:
            resp['timing_ms'] = {
                'deepcopy': round((t_after_copy - t0) * 1000.0, 2),
                'total': round((time.perf_counter() - t0) * 1000.0, 2),
            }
        return jsonify(resp), (202 if job and job.get('state') in ('queued', 'running') else 200)

    # === حالت ریسلر ===
    # 1. دریافت دسترسی‌های سرور و اینباند
    allowed_map, assignments = get_reseller_access_maps(user)
    
    # 2. دریافت لیست کلاینت‌های Assign شده به این ریسلر از دیتابیس
    owned_ownerships = (
        db.session.query(
            ClientOwnership.server_id,
            ClientOwnership.inbound_id,
            ClientOwnership.client_email,
            ClientOwnership.client_uuid,
        )
        .filter(ClientOwnership.reseller_id == user.id)
        .all()
    )
    
    exact_matches = set()
    loose_matches = set()
    exact_uuid_matches = set()
    loose_uuid_matches = set()
    
    for server_id_val, inbound_id_val, client_email_val, client_uuid_val in owned_ownerships:
        c_email = (client_email_val or '').lower()
        c_uuid = (client_uuid_val or '').strip().lower()
        sid = int(server_id_val)
        
        if inbound_id_val is not None:
            exact_matches.add((sid, int(inbound_id_val), c_email))
            if c_uuid:
                exact_uuid_matches.add((sid, int(inbound_id_val), c_uuid))
        else:
            loose_matches.add((sid, c_email))
            if c_uuid:
                loose_uuid_matches.add((sid, c_uuid))

    filtered_inbounds = []
    unique_server_ids = set()
    
    # متغیرهای آمار مخصوص ریسلر
    reseller_stats = {
        "total_inbounds": 0,
        "active_inbounds": 0,
        "total_clients": 0,     # فقط کلاینت‌های Assign شده
        "online_clients": 0,
        "active_clients": 0,    # فقط کلاینت‌های Assign شده فعال
        "inactive_clients": 0,  # فقط کلاینت‌های Assign شده غیرفعال
        "not_started_clients": 0,
        "unlimited_expiry_clients": 0,
        "unlimited_volume_clients": 0,
        "upload_raw": 0,        # فقط مصرف کلاینت‌های Assign شده
        "download_raw": 0
    }

    for inbound in data['inbounds']:
        sid = inbound['server_id']
        iid = inbound['id']
        
        # شرط ۱: دسترسی به اینباند (از طریق Allowed Server یا Assignment)
        if not is_inbound_accessible(sid, iid, allowed_map, assignments):
            continue
            
        # اینباند مجاز است
        unique_server_ids.add(sid)
        
        # برای نمایش در لیست: آمار کل اینباند را برای ریسلر صفر می‌کنیم (طبق درخواست)
        inbound['total_up'] = "---"
        inbound['total_down'] = "---"
        
        # شمارش اینباند
        reseller_stats["total_inbounds"] += 1
        if inbound.get('enable'):
            reseller_stats["active_inbounds"] += 1

        # پردازش کلاینت‌ها برای آمار دقیق و فیلتر کردن لیست نمایش
        clients_in_inbound = inbound.get('clients', [])
        filtered_clients_list = []
        
        for client in clients_in_inbound:
            c_email = client.get('email', '').lower()
            c_uuid = str(client.get('id') or '').strip().lower()
            
            # چک می‌کنیم آیا این کلاینت به ریسلر Assign شده؟
            # 1. تطابق دقیق (سرور، اینباند، ایمیل)
            # 2. تطابق بدون اینباند (سرور، ایمیل) - برای رکوردهای قدیمی یا ناقص
            is_assigned = False
            if c_uuid:
                is_assigned = (sid, iid, c_uuid) in exact_uuid_matches or (sid, c_uuid) in loose_uuid_matches
            if not is_assigned:
                is_assigned = (sid, iid, c_email) in exact_matches or (sid, c_email) in loose_matches
            
            if is_assigned:
                # اضافه کردن به لیست فیلتر شده برای نمایش
                filtered_clients_list.append(client)
                
                # محاسبه آمار
                reseller_stats["total_clients"] += 1
                if client.get('is_online'):
                    reseller_stats["online_clients"] += 1
                if client.get('enable'):
                    reseller_stats["active_clients"] += 1
                else:
                    reseller_stats["inactive_clients"] += 1

                if client.get('expiryType') == 'start_after_use':
                    reseller_stats["not_started_clients"] += 1

                if client.get('expiryType') == 'unlimited':
                    reseller_stats["unlimited_expiry_clients"] += 1

                # totalGB_formatted is already normalized in cached payload
                if (client.get('totalGB_formatted') == 'Unlimited'):
                    reseller_stats["unlimited_volume_clients"] += 1
                
                # جمع زدن ترافیک کلاینت‌های خودش
                reseller_stats["upload_raw"] += client.get('up', 0)
                reseller_stats["download_raw"] += client.get('down', 0)

        # جایگزینی لیست کلاینت‌های اینباند با لیست فیلتر شده
        inbound['clients'] = filtered_clients_list
        # آپدیت تعداد کلاینت‌های نمایش داده شده در اینباند
        inbound['client_count'] = len(filtered_clients_list)

        filtered_inbounds.append(inbound)

    # فرمت کردن آمار نهایی
    reseller_stats["total_traffic"] = format_bytes(reseller_stats["upload_raw"] + reseller_stats["download_raw"])
    reseller_stats["total_upload"] = format_bytes(reseller_stats["upload_raw"])
    reseller_stats["total_download"] = format_bytes(reseller_stats["download_raw"])
    
    # فیلتر کردن وضعیت سرورها
    filtered_servers_status = [
        s for s in data['servers_status'] 
        if s['server_id'] in unique_server_ids
    ]

    resp = {
        "success": True,
        "inbounds": filtered_inbounds,
        "stats": reseller_stats,
        "servers": filtered_servers_status,
        "server_count": len(unique_server_ids),
        "last_update": data['last_update'],
        "is_updating": bool(GLOBAL_SERVER_DATA.get('is_updating')),
        "refresh_job": _summarize_job(job),
    }
    if debug_timing and t0 is not None and t_after_copy is not None:
        resp['timing_ms'] = {
            'deepcopy': round((t_after_copy - t0) * 1000.0, 2),
            'total': round((time.perf_counter() - t0) * 1000.0, 2),
        }
    return jsonify(resp), (202 if job and job.get('state') in ('queued', 'running') else 200)


@app.route('/api/refresh/job/<job_id>')
@login_required
@limiter.exempt
def api_refresh_job(job_id):
    with REFRESH_JOBS_LOCK:
        job = REFRESH_JOBS.get(job_id)
        job_copy = copy.deepcopy(job) if job else None
    if not job_copy:
        return jsonify({"success": False, "error": "Job not found"}), 404
    resp = make_response(jsonify({
        "success": True,
        "job": _summarize_job(job_copy),
        "is_updating": bool(GLOBAL_SERVER_DATA.get('is_updating')),
        "last_update": GLOBAL_SERVER_DATA.get('last_update')
    }))
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp

@app.route('/api/servers/list')
@login_required
def api_servers_list():
    user = db.session.get(Admin, session['admin_id'])
    servers = get_accessible_servers(user)
    return jsonify([{
        'id': s.id,
        'name': s.name,
        'panel_type': s.panel_type
    } for s in servers])

@app.route('/api/traffic_check')
@login_required
def api_traffic_check():
    user = db.session.get(Admin, session['admin_id'])
    server_id_param = request.args.get('server_id', 'all')
    end_date_param = request.args.get('end_date')  # YYYY-MM-DD

    end_ts_ms = None
    if end_date_param:
        try:
            dt = datetime.strptime(end_date_param, '%Y-%m-%d')
            dt = dt.replace(hour=23, minute=59, second=59)
            end_ts_ms = int(dt.timestamp() * 1000)
        except Exception:
            return jsonify({"success": False, "error": "Invalid end_date format"}), 400

    accessible_servers = get_accessible_servers(user)
    accessible_ids = {s.id for s in accessible_servers}
    server_names = {s.id: s.name for s in accessible_servers}

    inbounds = GLOBAL_SERVER_DATA.get('inbounds') or []
    result_clients = []
    total_remaining_bytes = 0

    for client in inbounds:
        try:
            sid = int(client.get('server_id', -1))
        except Exception:
            continue
        if sid not in accessible_ids:
            continue
        if server_id_param != 'all':
            try:
                if sid != int(server_id_param):
                    continue
            except Exception:
                continue
        if not client.get('enable', True):
            continue
        remaining_bytes = client.get('remaining_bytes', -1)
        if remaining_bytes is None or remaining_bytes <= 0:
            continue
        expiry_ts = int(client.get('expiryTimestamp') or 0)
        if end_ts_ms is not None:
            if expiry_ts <= 0:
                continue
            if expiry_ts > end_ts_ms:
                continue
        total_remaining_bytes += remaining_bytes
        result_clients.append({
            "email": client.get('email', ''),
            "server_id": sid,
            "server_name": server_names.get(sid, f"Server {sid}"),
            "expiry_text": client.get('expiryTime', ''),
            "expiry_timestamp": expiry_ts,
            "remaining": format_bytes(remaining_bytes),
            "remaining_bytes": remaining_bytes,
            "total": client.get('totalGB_formatted', ''),
            "used": format_bytes(int(client.get('up', 0) or 0) + int(client.get('down', 0) or 0)),
        })

    result_clients.sort(key=lambda x: x['remaining_bytes'], reverse=True)
    return jsonify({
        "success": True,
        "total_remaining_bytes": total_remaining_bytes,
        "total_remaining": format_bytes(total_remaining_bytes),
        "client_count": len(result_clients),
        "clients": result_clients,
    })

@app.route('/api/server/<int:server_id>/refresh')
@login_required
def api_refresh_single_server(server_id):
    user = db.session.get(Admin, session['admin_id'])
    server = Server.query.get_or_404(server_id)
    
    # Check access
    if user.role != 'superadmin':
        if user.allowed_servers != '*' and str(server.id) not in user.allowed_servers.split(','):
             return jsonify({"success": False, "error": "Access denied"}), 403

    # Non-blocking: optionally enqueue a refresh job and return cached data immediately.
    force = _parse_bool(request.args.get('force'))
    wait = _parse_bool(request.args.get('wait'))
    mode = (request.args.get('mode') or 'full').strip().lower()
    enqueue = request.args.get('enqueue')
    enqueue = _parse_bool(enqueue) if enqueue is not None else (mode != 'cache')

    # Multi-worker: pull the freshest shared snapshot so a write-through edit made
    # on another worker is visible here immediately (cheap version check; no-op
    # without Redis). This is what keeps a post-edit cache read from reverting.
    if mode == 'cache':
        try:
            load_snapshot_from_redis()
        except Exception:
            pass

    job = None
    if enqueue and mode in ('full', 'status'):
        job = enqueue_refresh_job(mode='full', server_id=server.id, force=force)

        # Optional short wait for UI actions; cap to keep endpoint snappy.
        if wait and job:
            start = time.time()
            while (time.time() - start) < 2.0:
                with REFRESH_JOBS_LOCK:
                    cur = REFRESH_JOBS.get(job.get('id'))
                    if cur and cur.get('state') in ('done', 'error'):
                        job = cur
                        break
                time.sleep(0.15)

    # Pull this server's cached block (if present)
    cached_inbounds = []
    for inbound in (GLOBAL_SERVER_DATA.get('inbounds') or []):
        try:
            if int(inbound.get('server_id', -1)) == int(server.id):
                cached_inbounds.append(inbound)
        except Exception:
            continue

    cached_stats = None
    cached_status = None
    for st in (GLOBAL_SERVER_DATA.get('servers_status') or []):
        try:
            if int(st.get('server_id', -1)) == int(server.id):
                cached_stats = st.get('stats')
                cached_status = st
                break
        except Exception:
            continue

    global_stats = GLOBAL_SERVER_DATA.get('stats') or {}
    server_count = len(GLOBAL_SERVER_DATA.get('servers_status') or [])
    if user.role != 'reseller':
        cached_inbounds = copy.deepcopy(cached_inbounds)
        enrich_inbounds_with_ownership(cached_inbounds)

    return jsonify({
        "success": True,
        "server_id": server.id,
        "server_name": server.name,
        "inbounds": cached_inbounds,
        "stats": global_stats,
        "server_stats": cached_stats or {},
        "server_status": cached_status or {},
        "server_count": server_count,
        "panel_type": server.panel_type,
        "last_update": GLOBAL_SERVER_DATA.get('last_update'),
        "is_updating": bool(GLOBAL_SERVER_DATA.get('is_updating')),
        "refresh_job": _summarize_job(job)
    }), (202 if job and job.get('state') in ('queued', 'running') else 200)


@app.route('/api/server/<int:server_id>/last-users')
@login_required
def api_server_last_users(server_id):
    """Recent users per inbound (most recent first), from cache only (fast path).
    Resellers only see clients THEY own; admins/superadmins see all."""
    user = db.session.get(Admin, session['admin_id'])
    owned_emails = None  # None = no ownership filter (admin); set = reseller filter
    if user and user.role == 'reseller':
        owned_emails = {
            (o.client_email or '').strip().lower()
            for o in ClientOwnership.query.filter_by(reseller_id=user.id, server_id=server_id).all()
            if o.client_email
        }

    RECENT_N = 8
    recent_users = {}
    for inbound in (GLOBAL_SERVER_DATA.get('inbounds') or []):
        try:
            if int(inbound.get('server_id', -1)) != int(server_id):
                continue
        except Exception:
            continue
        inbound_id = inbound.get('id')
        if inbound_id is None:
            continue

        emails = []
        clients = inbound.get('clients') or []
        if isinstance(clients, list):
            for c in reversed(clients):  # most recent first
                if not isinstance(c, dict):
                    continue
                em = c.get('email')
                if not em:
                    continue
                if owned_emails is not None and str(em).strip().lower() not in owned_emails:
                    continue
                emails.append(em)
                if len(emails) >= RECENT_N:
                    break
        recent_users[str(inbound_id)] = emails

    return jsonify({
        'success': True,
        'server_id': server_id,
        'recent_users': recent_users,
        'last_users': {k: (v[0] if v else None) for k, v in recent_users.items()},
        'last_update': GLOBAL_SERVER_DATA.get('last_update')
    })


@app.route('/api/add-client/inbounds/<int:server_id>')
@login_required
def api_add_client_inbounds(server_id):
    """Lightweight, cache-only inbound list for the Add/Renew client modal.

    Returns minimal per-inbound fields (no client arrays) + the last user, read
    straight from the in-memory snapshot. Tiny payload → the dropdown is ready
    instantly, independent of the heavy dashboard data load.
    """
    user = db.session.get(Admin, session['admin_id'])
    is_reseller = bool(user and user.role == 'reseller')
    allowed_map, assignments = ('*', {})
    owned_emails = None
    if is_reseller:
        allowed_map, assignments = get_reseller_access_maps(user)
        owned_emails = {
            (o.client_email or '').strip().lower()
            for o in ClientOwnership.query.filter_by(reseller_id=user.id, server_id=server_id).all()
            if o.client_email
        }

    RECENT_N = 8
    items = []
    for inbound in (GLOBAL_SERVER_DATA.get('inbounds') or []):
        try:
            if int(inbound.get('server_id', -1)) != int(server_id):
                continue
        except Exception:
            continue

        inbound_id = inbound.get('id')
        if inbound_id is None:
            continue

        if is_reseller:
            try:
                if not is_inbound_accessible(int(server_id), int(inbound_id), allowed_map, assignments):
                    continue
            except Exception:
                continue

        clients = inbound.get('clients') or []
        try:
            active_count = inbound.get('active_count')
            if active_count is None:
                active_count = sum(1 for c in clients if isinstance(c, dict) and c.get('enable'))
        except Exception:
            active_count = 0

        # Recent users (most recent first), role-filtered for resellers.
        recent = []
        if isinstance(clients, list):
            for c in reversed(clients):
                if not isinstance(c, dict):
                    continue
                em = c.get('email')
                if not em:
                    continue
                if owned_emails is not None and str(em).strip().lower() not in owned_emails:
                    continue
                recent.append(em)
                if len(recent) >= RECENT_N:
                    break

        items.append({
            'id': inbound_id,
            'server_id': server_id,
            'remark': inbound.get('remark') or f'Inbound {inbound_id}',
            'protocol': inbound.get('protocol') or '',
            'port': inbound.get('port'),
            'client_count': inbound.get('client_count', len(clients)),
            'active_count': active_count,
            'last_user': (recent[0] if recent else None),
            'recent_users': recent,
        })

    return jsonify({
        'success': True,
        'server_id': server_id,
        'inbounds': items,
        'last_update': GLOBAL_SERVER_DATA.get('last_update'),
    })


@app.route('/settings')
@login_required
def settings_page():
    user = db.session.get(Admin, session['admin_id'])
    if not user.is_superadmin:
        return redirect(url_for('dashboard'))
    whatsapp_cfg = _get_whatsapp_runtime_settings()
    return render_template('settings.html', 
                         current_user=user, 
                         is_superadmin=user.is_superadmin, 
                         app_version=APP_VERSION,
                         admin_username=user.username,
                         role=user.role,
                         whatsapp_deployment_region=whatsapp_cfg.get('deployment_region', 'outside'),
                         whatsapp_enabled=whatsapp_cfg.get('enabled_requested', False),
                         whatsapp_provider=whatsapp_cfg.get('provider', 'baileys'),
                         whatsapp_trigger_renew_success=whatsapp_cfg.get('trigger_renew_success', True),
                         whatsapp_trigger_welcome=whatsapp_cfg.get('trigger_welcome', False),
                         whatsapp_trigger_pre_expiry=whatsapp_cfg.get('trigger_pre_expiry', False),
                         whatsapp_min_interval_seconds=whatsapp_cfg.get('min_interval_seconds', 45),
                         whatsapp_daily_limit=whatsapp_cfg.get('daily_limit', 100),
                         whatsapp_pre_expiry_hours=whatsapp_cfg.get('pre_expiry_hours', 24),
                         whatsapp_retry_count=whatsapp_cfg.get('retry_count', 3),
                         whatsapp_backoff_seconds=whatsapp_cfg.get('backoff_seconds', 30),
                         whatsapp_circuit_breaker=whatsapp_cfg.get('circuit_breaker', True),
                         whatsapp_gateway_url=whatsapp_cfg.get('gateway_url', ''),
                         whatsapp_gateway_api_key=whatsapp_cfg.get('gateway_api_key', ''),
                         whatsapp_gateway_timeout_seconds=whatsapp_cfg.get('gateway_timeout_seconds', 10),
                         whatsapp_template_renew=whatsapp_cfg.get('template_renew', DEFAULT_WHATSAPP_TEMPLATE_RENEW),
                         whatsapp_template_welcome=whatsapp_cfg.get('template_welcome', DEFAULT_WHATSAPP_TEMPLATE_WELCOME),
                         whatsapp_template_pre_expiry=whatsapp_cfg.get('template_pre_expiry', DEFAULT_WHATSAPP_TEMPLATE_PRE_EXPIRY))


@app.route('/api/settings/subscription-page', methods=['GET'])
@user_management_required
def get_subscription_page_settings():
    lang = (_get_or_create_system_setting('subscription_page_lang', 'en') or 'en').strip().lower()
    if lang not in ('fa', 'en'):
        lang = 'en'
    return jsonify({'success': True, 'lang': lang})


@app.route('/api/settings/subscription-page', methods=['POST'])
@user_management_required
def save_subscription_page_settings():
    try:
        data = request.get_json() or {}
    except Exception:
        data = {}

    lang = (data.get('lang') or '').strip().lower()
    if lang not in ('fa', 'en'):
        return jsonify({'success': False, 'error': 'Invalid language. Allowed: fa, en'}), 400

    setting = db.session.get(SystemSetting, 'subscription_page_lang')
    if not setting:
        setting = SystemSetting(key='subscription_page_lang', value=lang)
        db.session.add(setting)
    else:
        setting.value = lang

    db.session.commit()
    return jsonify({'success': True, 'message': 'Subscription page settings saved', 'lang': lang})


@app.route('/api/settings/general', methods=['GET'])
@user_management_required
def get_general_settings():
    thresholds = _get_dashboard_status_thresholds()
    try:
        snapshot_interval = int(_get_or_create_system_setting(
            USAGE_SNAPSHOT_INTERVAL_KEY, str(_USAGE_SNAPSHOT_INTERVAL_DEFAULT_MIN)) or _USAGE_SNAPSHOT_INTERVAL_DEFAULT_MIN)
        snapshot_interval = max(5, min(120, snapshot_interval))
    except Exception:
        snapshot_interval = _USAGE_SNAPSHOT_INTERVAL_DEFAULT_MIN
    # Last snapshot timestamp (across all servers/subs)
    try:
        last_snap = (UsageSnapshot.query
                     .order_by(UsageSnapshot.recorded_at.desc())
                     .with_entities(UsageSnapshot.recorded_at)
                     .first())
        last_snapshot_at = (last_snap.recorded_at.isoformat() + 'Z') if last_snap else None
        total_snapshots = UsageSnapshot.query.count()
    except Exception:
        last_snapshot_at = None
        total_snapshots = 0
    panel_domain = (_get_or_create_system_setting(PANEL_DOMAIN_SETTING_KEY, '') or '').strip()
    ssl_cert = (db.session.get(SystemSetting, 'ssl_cert_path') or SystemSetting(key='', value='')).value or ''
    has_ssl  = bool(ssl_cert and os.path.isfile(ssl_cert))

    return jsonify({
        'success': True,
        'timezone': _get_app_timezone_name(),
        'timezone_options': _get_standard_timezone_options(),
        'panel_lang': _get_panel_ui_lang(),
        'near_expiry_days': thresholds.get('near_expiry_days', 3),
        'near_expiry_hours': thresholds.get('near_expiry_hours', 0),
        'low_volume_gb': thresholds.get('low_volume_gb', 1.0),
        'snapshot_interval_minutes': snapshot_interval,
        'last_snapshot_at': last_snapshot_at,
        'total_snapshots': total_snapshots,
        'panel_domain': panel_domain,
        'is_ip': _is_ip_address(panel_domain),
        'has_ssl': has_ssl,
    })


@app.route('/api/settings/general', methods=['POST'])
@user_management_required
def save_general_settings():
    try:
        data = request.get_json() or {}
    except Exception:
        data = {}

    tz_name = (data.get('timezone') or '').strip()
    if not tz_name:
        tz_name = DEFAULT_APP_TIMEZONE

    tz_name = _normalize_timezone_name(tz_name) or tz_name

    if not _is_valid_timezone_name(tz_name):
        return jsonify({
            'success': False,
            'error': 'Invalid timezone. Example: Asia/Tehran'
        }), 400

    panel_lang = _normalize_ui_lang(data.get('panel_lang'), default='en')

    near_expiry_days = _parse_int(data.get('near_expiry_days'), 3, min_value=0, max_value=365)
    near_expiry_hours = _parse_int(data.get('near_expiry_hours'), 0, min_value=0, max_value=23)

    try:
        low_volume_gb = float(data.get('low_volume_gb', 1.0) or 1.0)
    except Exception:
        low_volume_gb = 1.0
    low_volume_gb = max(0.01, min(low_volume_gb, 1024.0))

    snapshot_interval = _parse_int(data.get('snapshot_interval_minutes'), _USAGE_SNAPSHOT_INTERVAL_DEFAULT_MIN, min_value=5, max_value=120)

    # Domain update + nginx reload
    new_domain = (data.get('panel_domain') or '').strip()
    old_domain = (_get_or_create_system_setting(PANEL_DOMAIN_SETTING_KEY, '') or '').strip()
    nginx_updated = False
    nginx_error = ''

    if new_domain and new_domain != old_domain:
        cert_path = (db.session.get(SystemSetting, 'ssl_cert_path') or SystemSetting(key='', value='')).value or ''
        key_path  = (db.session.get(SystemSetting, 'ssl_key_path')  or SystemSetting(key='', value='')).value or ''
        use_ssl   = bool(cert_path and key_path
                         and os.path.isfile(cert_path) and os.path.isfile(key_path)
                         and not _is_ip_address(new_domain))
        ok, nginx_error = _apply_nginx_config(
            new_domain,
            cert_path if use_ssl else '',
            key_path  if use_ssl else '',
        )
        nginx_updated = ok
        if not ok:
            app.logger.warning(f"nginx update failed when changing domain to {new_domain}: {nginx_error}")

    _set_system_setting_value(GENERAL_TIMEZONE_SETTING_KEY, tz_name)
    _set_system_setting_value(PANEL_UI_LANG_SETTING_KEY, panel_lang)
    _set_system_setting_value(GENERAL_EXPIRY_WARNING_DAYS_KEY, str(near_expiry_days))
    _set_system_setting_value(GENERAL_EXPIRY_WARNING_HOURS_KEY, str(near_expiry_hours))
    _set_system_setting_value(GENERAL_LOW_VOLUME_WARNING_GB_KEY, str(low_volume_gb))
    _set_system_setting_value(USAGE_SNAPSHOT_INTERVAL_KEY, str(snapshot_interval))
    if new_domain:
        _set_system_setting_value(PANEL_DOMAIN_SETTING_KEY, new_domain)
    db.session.commit()

    is_ip    = _is_ip_address(new_domain or old_domain)
    protocol = 'http' if (is_ip or not nginx_updated) else 'https'
    panel_url = f'{protocol}://{new_domain or old_domain}' if (new_domain or old_domain) else ''

    return jsonify({
        'success': True,
        'message': 'General settings saved',
        'timezone': tz_name,
        'timezone_options': _get_standard_timezone_options(),
        'panel_lang': panel_lang,
        'near_expiry_days': near_expiry_days,
        'near_expiry_hours': near_expiry_hours,
        'low_volume_gb': low_volume_gb,
        'snapshot_interval_minutes': snapshot_interval,
        'panel_domain': new_domain or old_domain,
        'is_ip': is_ip,
        'nginx_updated': nginx_updated,
        'nginx_error': nginx_error,
        'panel_url': panel_url,
    })


@app.route('/api/client/direct-link/<int:server_id>/<sub_id>')
@login_required
@limiter.limit("60 per minute")
def get_client_direct_link(server_id, sub_id):
    """
    Fetch the direct config link(s) from the upstream X-UI subscription endpoint.
    This returns the actual config links as generated by the panel itself.
    """
    user = db.session.get(Admin, session['admin_id'])
    server = db.session.get(Server, server_id)

    normalized_sub_id = str(sub_id).strip()

    # Basic hardening: keep the identifier path-safe (the upstream URL embeds it in the path)
    if any(c in normalized_sub_id for c in ('/', '\\', '?', '#', '@', ':')) or '..' in normalized_sub_id:
        return jsonify({"success": False, "error": "Invalid subscription ID"}), 400
    
    if not server:
        return jsonify({"success": False, "error": "Server not found"}), 404

    # Try to resolve sub_id -> client UUID/email from in-memory cache (important for resellers).
    # We generate subscription URLs using `client.subId`, while ownership is stored by `client_uuid`.
    resolved_client_uuid = None
    resolved_client_email = None
    try:
        cached_inbounds = GLOBAL_SERVER_DATA.get('inbounds', []) or []
        server_inbounds = [i for i in cached_inbounds if int(i.get('server_id', -1)) == int(server_id)]
        for inbound in server_inbounds:
            for client in inbound.get('clients', []):
                c_sub_id = str(client.get('subId') or '').strip()
                c_uuid = str(client.get('id') or '').strip()
                if normalized_sub_id and (normalized_sub_id == c_sub_id or normalized_sub_id == c_uuid):
                    resolved_client_uuid = c_uuid or None
                    resolved_client_email = (client.get('email') or '').strip() or None
                    break
            if resolved_client_uuid or resolved_client_email:
                break
    except Exception:
        resolved_client_uuid = None
        resolved_client_email = None
    
    # Check permission
    if user.role == 'reseller':
        ownership = None

        lookup_uuid = resolved_client_uuid or normalized_sub_id
        if lookup_uuid:
            ownership = ClientOwnership.query.filter_by(
                reseller_id=user.id,
                server_id=server_id,
                client_uuid=lookup_uuid
            ).first()

        if not ownership and resolved_client_email:
            ownership = ClientOwnership.query.filter(
                ClientOwnership.reseller_id == user.id,
                ClientOwnership.server_id == server_id,
                func.lower(ClientOwnership.client_email) == resolved_client_email.lower()
            ).first()

        if not ownership:
            return jsonify({"success": False, "error": "Access denied"}), 403
    
    # Build subscription URL
    host_value = server.host
    if host_value and not host_value.startswith(('http://', 'https://')):
        host_value = f"http://{host_value}"
    parsed_host = urlparse(host_value or '')
    hostname = parsed_host.hostname or parsed_host.path or ''
    scheme = parsed_host.scheme or 'http'
    final_port = server.sub_port if server.sub_port else parsed_host.port
    port_str = f":{final_port}" if final_port else ''
    sub_path = (server.sub_path or '/sub/').strip('/')
    base_sub = f"{scheme}://{hostname}{port_str}"
    safe_sub_id = quote(normalized_sub_id)
    sub_url = f"{base_sub}/{sub_path}/{safe_sub_id}" if sub_path else f"{base_sub}/{safe_sub_id}"
    
    try:
        resp = requests.get(
            sub_url, 
            headers={'User-Agent': 'v2rayng'}, 
            timeout=10, 
            verify=False,
            allow_redirects=False
        )
        if resp.status_code == 200:
            raw_content = resp.content or b''
            try:
                decoded = base64.b64decode(raw_content).decode('utf-8')
            except Exception:
                decoded = raw_content.decode('utf-8', errors='ignore')
            configs = [line.strip() for line in decoded.splitlines() if line.strip()]
            return jsonify({
                "success": True,
                "configs": configs,
                "direct_link": configs[0] if configs else None,
                "sub_url": sub_url
            })
        else:
            return jsonify({
                "success": False, 
                "error": f"Panel returned status {resp.status_code}",
                "sub_url": sub_url
            }), 502
    except Exception as e:
        app.logger.error(f"Failed to fetch direct link: {e}")
        return jsonify({
            "success": False, 
            "error": str(e),
            "sub_url": sub_url
        }), 500


@app.route('/api/clients/search')
@login_required
@limiter.limit("60 per minute")
def global_client_search():
    user = db.session.get(Admin, session['admin_id'])
    query = (request.args.get('email') or '').strip().lower()
    if not query:
        return jsonify({"success": False, "error": "Query parameter 'email' is required"}), 400

    try:
        limit = int(request.args.get('limit', 500))
    except ValueError:
        limit = 500
    limit = max(1, min(limit, 5000))

    # --- اصلاح حرفه‌ای: جستجو در کش (RAM) به جای درخواست مجدد ---
    
    # اگر کش خالی است (برنامه تازه اجرا شده)، پیام مناسب بدهد
    if not GLOBAL_SERVER_DATA.get('inbounds'):
        return jsonify({"success": True, "results": [], "errors": ["System is starting up, please wait..."]})

    matches = []
    
    # دریافت دسترسی‌های کاربر برای فیلتر کردن نتایج
    accessible_servers = get_accessible_servers(user)
    accessible_server_ids = {s.id for s in accessible_servers}
    
    # تنظیمات دسترسی ریسلر
    allowed_map = '*'
    assignments = {}
    if user.role == 'reseller':
        allowed_map, assignments = get_reseller_access_maps(user)

    # جستجو در داده‌های موجود در رم
    for inbound in GLOBAL_SERVER_DATA['inbounds']:
        sid = inbound.get('server_id')
        iid = inbound.get('id')

        # 1. بررسی دسترسی به سرور
        if sid not in accessible_server_ids:
            continue

        # 2. بررسی دسترسی به اینباند (مخصوص ریسلرها)
        if user.role == 'reseller':
            if not is_inbound_accessible(sid, iid, allowed_map, assignments):
                continue

        # 3. جستجو در کلاینت‌های این اینباند
        clients = inbound.get('clients', [])
        for client in clients:
            c_email = (client.get('email') or '').lower()
            c_comment = (client.get('comment') or '').lower()
            if query not in c_email and query not in c_comment:
                continue
            # کلاینت پیدا شد
            matches.append({
                "server_id": sid,
                "server_name": inbound.get('server_name'),
                "panel_type": next((s.panel_type for s in accessible_servers if s.id == sid), 'auto'),
                "inbound_id": iid,
                "inbound": {
                    "id": iid,
                    "remark": inbound.get('remark', ''),
                    "port": inbound.get('port', ''),
                    "protocol": inbound.get('protocol', ''),
                    "enable": inbound.get('enable', False)
                },
                "client": client
            })

            if len(matches) >= limit:
                break
        
        if len(matches) >= limit:
            break

    return jsonify({"success": True, "results": matches, "errors": []})

@app.route('/api/client/<int:server_id>/<int:inbound_id>/toggle', methods=['POST'])
@login_required
def toggle_client(server_id, inbound_id):
    user = db.session.get(Admin, session['admin_id'])
    if not user:
        return jsonify({"success": False, "error": "User not found"}), 401

    server = Server.query.get_or_404(server_id)

    try:
        data = request.get_json() or {}
        email = data.get('email')
        enable = data.get('enable', True)
        if not email:
            return jsonify({"success": False, "error": "Email required"}), 400
    except Exception:
        return jsonify({"success": False, "error": "Invalid JSON"}), 400

    ok, error_message, status_code = _toggle_client_core(user, server, inbound_id, email, enable)
    if ok:
        response = {"success": True}
        if user.role == 'reseller':
            response["remaining_credit"] = user.credit
        return jsonify(response)
    return jsonify({"success": False, "error": error_message}), status_code


def _get_cached_raw_client(server_id: int, inbound_id: int, email: str):
    target_client = None
    cached_inbounds = GLOBAL_SERVER_DATA.get('inbounds') or []
    for ib in cached_inbounds:
        try:
            if int(ib.get('server_id', -1)) == int(server_id) and int(ib.get('id', -1)) == int(inbound_id):
                for c in ib.get('clients', []):
                    if c.get('email') == email and 'raw_client' in c:
                        target_client = copy.deepcopy(c['raw_client'])
                        break
        except (ValueError, TypeError):
            continue
        if target_client:
            break
    return target_client


def _user_can_afford(user, price: int) -> tuple[bool, str | None]:
    """Check if user can afford price, respecting negative credit allowance.
    Returns (ok, error_message_or_None).
    """
    if price <= 0:
        return True, None
    cur = getattr(user, 'credit', 0) or 0
    allow_neg = getattr(user, 'allow_negative_credit', False) or False
    neg_limit = getattr(user, 'negative_credit_limit', 0) or 0
    min_bal = -(abs(neg_limit)) if allow_neg else 0
    if cur - price < min_bal:
        shortfall = (cur - price) - min_bal
        return False, (
            f"موجودی کافی نیست — اعتبار فعلی: {cur:,} T، "
            f"هزینه: {price:,} T، "
            f"کسری: {abs(shortfall):,} T"
            f" (Insufficient credit: balance {cur:,} T, cost {price:,} T)"
        )
    return True, None


def _has_client_access(user, server_id: int, email: str, inbound_id: int | None = None, client_uuid: str | None = None) -> bool:
    if not user:
        return False
    if user.role != 'reseller':
        return True

    email_l = (email or '').strip().lower()
    cu = (client_uuid or '').strip()
    if not cu and inbound_id is not None:
        try:
            raw = _get_cached_raw_client(int(server_id), int(inbound_id), email)
            cu = (raw.get('id') or '').strip() if isinstance(raw, dict) else ''
        except Exception:
            cu = ''

    q = ClientOwnership.query.filter(
        ClientOwnership.reseller_id == user.id,
        ClientOwnership.server_id == server_id,
    )
    key_filters = []
    if cu:
        key_filters.append(ClientOwnership.client_uuid == cu)
    if email_l:
        key_filters.append(func.lower(ClientOwnership.client_email) == email_l)
    if key_filters:
        q = q.filter(or_(*key_filters))
    return bool(q.first())


def _toggle_client_core(user, server, inbound_id: int, email: str, enable: bool):
    """Core implementation for toggling a client; returns (ok, error, status_code)."""
    price = 0
    description = f"Toggle client {email} to {enable}"

    if not _has_client_access(user, server.id, email, inbound_id=inbound_id):
        return False, "Access denied", 403

    if user.role == 'reseller':
        ok, err = _user_can_afford(user, price)
        if not ok:
            return False, err, 402

    target_client = _get_cached_raw_client(server.id, inbound_id, email)

    session_obj, error = get_xui_session(server)
    if error:
        return False, error, 400

    try:
        if not target_client:
            inbounds, fetch_err, detected_type = fetch_inbounds(session_obj, server.host, server.panel_type)
            if fetch_err:
                return False, fetch_err, 400

            persist_detected_panel_type(server, detected_type)
            target_client, _ = find_client(inbounds, inbound_id, email)
            if not target_client:
                return False, "Client not found", 404

        target_client['enable'] = bool(enable)
        client_identifier = target_client.get('id') or target_client.get('password') or target_client.get('email')

        # v3: enable/disable via the first-class client update (legacy updateClient is 404).
        if server_is_v3(server):
            ok, _vr, verr = v3_update_client(server, session_obj, email, target_client)
            if ok:
                patch_cached_client(server.id, email, enable=bool(enable))
                return True, None, 200
            return False, f"v3 toggle failed: {verr}", 502

        payload = {
            "id": inbound_id,
            "settings": json.dumps({"clients": [target_client]})
        }

        replacements = {
            'id': inbound_id,
            'inbound_id': inbound_id,
            'inboundId': inbound_id,
            'clientId': client_identifier,
            'client_id': client_identifier,
            'email': email
        }

        templates = collect_endpoint_templates(server.panel_type, 'client_update', CLIENT_UPDATE_FALLBACKS)
        errors = []
        for template in templates:
            full_url = build_panel_url(server.host, template, replacements)
            if not full_url:
                continue
            try:
                resp = session_obj.post(full_url, json=payload, verify=False, timeout=10)
            except Exception as exc:
                errors.append(f"{template}: {exc}")
                continue

            if resp.status_code == 200:
                try:
                    resp_json = resp.json()
                    if isinstance(resp_json, dict) and resp_json.get('success') is False:
                        errors.append(f"{template}: success false")
                        continue
                except ValueError:
                    pass
                if user.role == 'reseller' and price > 0:
                    user.credit -= price
                    log_transaction(user.id, -price, 'renew', description or f"Renew client {email}", server_id=server.id)
                    db.session.commit()
                patch_cached_client(server.id, email, enable=bool(enable))
                return True, None, 200

            errors.append(f"{template}: {resp.status_code}")
            if resp.status_code != 404:
                break

        app.logger.warning(f"Toggle failed for {email}: {'; '.join(errors)}")
        return False, "Client update endpoint returned error", 400
    except Exception as exc:
        app.logger.error(f"Toggle error: {str(exc)}")
        return False, str(exc), 400

@app.route('/api/client/<int:server_id>/<int:inbound_id>/reset', methods=['POST'])
@login_required
def reset_client_traffic(server_id, inbound_id):
    user = db.session.get(Admin, session['admin_id'])
    if not user:
        return jsonify({"success": False, "error": "User not found"}), 401
    
    server = Server.query.get_or_404(server_id)
    
    try:
        data = request.get_json() or {}
    except:
        return jsonify({"success": False, "error": "Invalid JSON"}), 400

    email = data.get('email')
    if not email:
        return jsonify({"success": False, "error": "Email required"}), 400
    try:
        volume_gb = int(data.get('volume_gb', 0) or 0)
    except (ValueError, TypeError):
        return jsonify({"success": False, "error": "Invalid volume value"}), 400
    if volume_gb < 0:
        volume_gb = 0
    
    base_cost_gb = get_config('cost_per_gb', 0)
    user_cost_gb = calculate_reseller_price(user, base_price=base_cost_gb, cost_type='gb')
    
    is_free = bool(data.get('is_free', False))
    if is_free:
        charge_amount = 0
    else:
        charge_amount = volume_gb * user_cost_gb if volume_gb > 0 else 0

    if user.role == 'reseller':
        if not _has_client_access(user, server_id, email, inbound_id=inbound_id):
            return jsonify({"success": False, "error": "Access denied"}), 403
        if not is_free and user_cost_gb > 0 and volume_gb <= 0:
            return jsonify({"success": False, "error": "Billable volume required"}), 400
        ok, err = _user_can_afford(user, charge_amount)
        if not ok:
            return jsonify({"success": False, "error": err}), 402

    session_obj, error = get_xui_session(server)
    if error: return jsonify({"success": False, "error": error}), 400

    def _apply_volume_cap_after_reset(target_client):
        """After a successful traffic reset, set totalGB if caller specified a volume cap."""
        if volume_gb <= 0:
            return
        target_client['totalGB'] = volume_gb * 1024 * 1024 * 1024
        try:
            if server_is_v3(server):
                v3_update_client(server, session_obj, email, target_client)
            elif 'id' not in target_client:
                # Shadowsocks: need full inbound update
                _ibs_r, _fe_r, _ = fetch_inbounds(session_obj, server.host, server.panel_type)
                _full_ib_r = None
                if not _fe_r:
                    for _ib_r in (_ibs_r or []):
                        if _ib_r.get('id') == inbound_id:
                            _full_ib_r = _ib_r
                            break
                if _full_ib_r:
                    _fs_r = _json_field(_full_ib_r.get('settings'), {})
                    _fs_r['clients'] = [
                        target_client if c.get('email') == email else c
                        for c in _fs_r.get('clients', [])
                    ]
                    _push_full_inbound(server, session_obj, _full_ib_r, _fs_r)
            else:
                client_id = target_client.get('id', target_client.get('password', email))
                up = {'id': inbound_id, 'settings': json.dumps({'clients': [target_client]})}
                rpl = {'id': inbound_id, 'inbound_id': inbound_id, 'inboundId': inbound_id,
                       'clientId': client_id, 'client_id': client_id, 'email': email}
                for tpl in collect_endpoint_templates(server.panel_type, 'client_update', CLIENT_UPDATE_FALLBACKS):
                    url2 = build_panel_url(server.host, tpl, rpl)
                    if not url2:
                        continue
                    r2 = session_obj.post(url2, json=up, verify=False, timeout=10)
                    if r2.status_code == 200:
                        break
        except Exception as exc:
            app.logger.warning(f"apply_volume_cap_after_reset failed for {email}: {exc}")

    try:
        # v3: reset the first-class client by email (legacy resetClientTraffic is 404).
        if server_is_v3(server):
            ok, _vr, verr = v3_reset_client(server, session_obj, email)
            if not ok:
                return jsonify({"success": False, "error": f"v3 reset failed: {verr}"}), 502

            if volume_gb > 0:
                inbounds_r, _, _ = fetch_inbounds(session_obj, server.host, server.panel_type)
                target_r, _ = find_client(inbounds_r, inbound_id, email)
                if target_r:
                    _apply_volume_cap_after_reset(target_r)

            if charge_amount > 0:
                sender_card = data.get('sender_card', '') or ''
                card_id = data.get('card_id')
                if user.role == 'reseller':
                    user.credit -= charge_amount
                    log_transaction(user.id, -charge_amount, 'reset_traffic', "Reset traffic (Credit Usage)", server_id=server.id, sender_card=sender_card, card_id=card_id, category='usage', client_email=email)
                else:
                    log_transaction(user.id, charge_amount, 'reset_traffic', "Reset traffic (Income)", server_id=server.id, sender_card=sender_card, card_id=card_id, category='income', client_email=email)
                db.session.commit()
            patch_cached_client(server.id, email, up=0, down=0,
                                total_gb_bytes=(volume_gb * 1024 * 1024 * 1024 if volume_gb > 0 else None))
            response = {"success": True}
            if user.role == 'reseller':
                response["remaining_credit"] = user.credit
            return jsonify(response)

        templates = collect_endpoint_templates(server.panel_type, 'client_reset_traffic', CLIENT_RESET_FALLBACKS)
        replacements = {
            'id': inbound_id,
            'inbound_id': inbound_id,
            'inboundId': inbound_id,
            'email': email
        }
        errors = []
        for template in templates:
            full_url = build_panel_url(server.host, template, replacements)
            if not full_url:
                continue
            requires_path_email = (':email' in template) or ('{email}' in template)
            payload = None if requires_path_email else {"email": email}
            try:
                if payload is None:
                    resp = session_obj.post(full_url, verify=False, timeout=10)
                else:
                    resp = session_obj.post(full_url, json=payload, verify=False, timeout=10)
            except Exception as exc:
                errors.append(f"{template}: {exc}")
                continue

            if resp.status_code == 200:
                try:
                    resp_json = resp.json()
                    if isinstance(resp_json, dict) and resp_json.get('success') is False:
                        errors.append(f"{template}: success false")
                        continue
                except ValueError:
                    pass

                if volume_gb > 0:
                    inbounds_r, _, _ = fetch_inbounds(session_obj, server.host, server.panel_type)
                    target_r, _ = find_client(inbounds_r, inbound_id, email)
                    if target_r:
                        _apply_volume_cap_after_reset(target_r)

                if charge_amount > 0:
                    sender_card = data.get('sender_card', '') or ''
                    card_id = data.get('card_id')
                    if user.role == 'reseller':
                        user.credit -= charge_amount
                        log_transaction(user.id, -charge_amount, 'reset_traffic', "Reset traffic (Credit Usage)", server_id=server.id, sender_card=sender_card, card_id=card_id, category='usage', client_email=email)
                    else:
                        log_transaction(user.id, charge_amount, 'reset_traffic', "Reset traffic (Income)", server_id=server.id, sender_card=sender_card, card_id=card_id, category='income', client_email=email)
                    db.session.commit()

                patch_cached_client(server.id, email, up=0, down=0,
                                    total_gb_bytes=(volume_gb * 1024 * 1024 * 1024 if volume_gb > 0 else None))
                response = {"success": True}
                if user.role == 'reseller':
                    response["remaining_credit"] = user.credit
                return jsonify(response)

            errors.append(f"{template}: {resp.status_code}")
            if resp.status_code != 404:
                break

        app.logger.warning(f"Reset traffic failed for {email}: {'; '.join(errors)}")
        return jsonify({"success": False, "error": "Reset endpoint returned error"}), 400
    except Exception as e:
        app.logger.error(f"Reset error: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/api/client/<int:server_id>/<int:inbound_id>/<email>/edit', methods=['POST'])
@login_required
def edit_client(server_id, inbound_id, email):
    user = db.session.get(Admin, session['admin_id'])
    if not user:
        return jsonify({"success": False, "error": "User not found"}), 401
    
    server = Server.query.get_or_404(server_id)
    
    # Check ownership for resellers
    if user.role == 'reseller':
        if not _has_client_access(user, server_id, email, inbound_id=inbound_id):
            return jsonify({"success": False, "error": "Access denied"}), 403
    
    try:
        data = request.get_json() or {}
        new_email = data.get('new_email', '').strip()
        new_total_gb = data.get('totalGB')
        new_expiry_time = data.get('expiryTime')
        new_comment = data.get('comment')
    except:
        return jsonify({"success": False, "error": "Invalid data"}), 400

    if not new_email:
        return jsonify({"success": False, "error": "New email is required"}), 400
        
    session_obj, error = get_xui_session(server)
    if error:
        return jsonify({"success": False, "error": error}), 400
        
    try:
        inbounds, fetch_err, detected_type = fetch_inbounds(session_obj, server.host, server.panel_type)
        if fetch_err:
            return jsonify({"success": False, "error": "Failed to fetch inbounds"}), 400

        persist_detected_panel_type(server, detected_type)
            
        target_client, fetched_inbound_row_edit = find_client(inbounds, inbound_id, email)
        if not target_client:
            return jsonify({"success": False, "error": "Client not found"}), 404

        # Check for duplicate email on the same server (excluding current client)
        if new_email != email:
            for ib in inbounds:
                settings = _json_field(ib.get('settings'), {})
                clients = settings.get('clients', [])
                for c in clients:
                    if c.get('email') == new_email:
                        return jsonify({"success": False, "error": f"Client with email '{new_email}' already exists on this server."}), 400

        # Extract ID before modification to ensure we target the correct client
        client_id = target_client.get('id', target_client.get('password', email))

        # Update email
        target_client['email'] = new_email

        # Comment can be edited by anyone
        if new_comment is not None:
            target_client['comment'] = new_comment

        # Only superadmin can edit volume and expiry
        if user.is_superadmin:
            if new_total_gb is not None:
                try:
                    target_client['totalGB'] = int(float(new_total_gb) * 1024 * 1024 * 1024)
                except (ValueError, TypeError):
                    pass
            if new_expiry_time is not None:
                try:
                    target_client['expiryTime'] = int(new_expiry_time)
                except (ValueError, TypeError):
                    pass

        # v3: use first-class client endpoint (legacy updateClient is 404 on v3)
        if server_is_v3(server):
            ok_v3, _vr, verr = v3_update_client(server, session_obj, email, target_client)
            if not ok_v3:
                detail = verr or 'panel rejected update'
                app.logger.warning(f"v3 edit client failed for {email}: {detail}")
                return jsonify({"success": False, "error": f"پنل خطا برگرداند: {detail}"}), 502
            success = True
        elif 'id' not in target_client:
            # Shadowsocks clients have no UUID — use full inbound update.
            _full_ib_edit = fetched_inbound_row_edit
            if _full_ib_edit is None:
                return jsonify({"success": False, "error": "shadowsocks: could not get full inbound for update"}), 400
            _full_settings_edit = _json_field(_full_ib_edit.get('settings'), {})
            _full_settings_edit['clients'] = [
                target_client if c.get('email') == email else c
                for c in _full_settings_edit.get('clients', [])
            ]
            _ok_push_edit, _push_err_edit = _push_full_inbound(server, session_obj, _full_ib_edit, _full_settings_edit)
            if not _ok_push_edit:
                detail = _push_err_edit or 'shadowsocks inbound update failed'
                app.logger.warning(f"Edit client failed for {email}: {detail}")
                return jsonify({"success": False, "error": f"آپدیت ناموفق بود — {detail}"}), 400
            success = True
        else:
            update_payload = {
                "id": inbound_id,
                "settings": json.dumps({"clients": [target_client]})
            }

            replacements = {
                'id': inbound_id,
                'inbound_id': inbound_id,
                'inboundId': inbound_id,
                'clientId': client_id,
                'client_id': client_id,
                'email': email
            }

            templates = collect_endpoint_templates(server.panel_type, 'client_update', CLIENT_UPDATE_FALLBACKS)
            errors = []
            success = False

            for template in templates:
                full_url = build_panel_url(server.host, template, replacements)
                if not full_url:
                    continue
                try:
                    resp = session_obj.post(full_url, json=update_payload, verify=False, timeout=10)
                except Exception as exc:
                    errors.append(f"{template}: {exc}")
                    continue

                if resp.status_code == 200:
                    try:
                        resp_json = resp.json()
                        if isinstance(resp_json, dict) and resp_json.get('success') is False:
                            panel_msg = resp_json.get('msg') or resp_json.get('message') or 'success=false'
                            errors.append(f"{template}: {panel_msg}")
                            continue
                    except ValueError:
                        pass

                    success = True
                    break

                errors.append(f"{template}: HTTP {resp.status_code}")

            if not success:
                detail = '; '.join(errors) or 'no endpoint succeeded'
                app.logger.warning(f"Edit client failed for {email}: {detail}")
                return jsonify({"success": False, "error": f"آپدیت ناموفق بود — {detail}"}), 400

        if success:
            # Update ownership if exists
            email_l = (email or '').strip().lower()
            ownerships = ClientOwnership.query.filter(
                ClientOwnership.server_id == server_id,
                or_(
                    ClientOwnership.client_uuid == str(client_id),
                    func.lower(ClientOwnership.client_email) == email_l,
                )
            ).all()
            for own in ownerships:
                own.client_email = new_email
                if (not (own.client_uuid or '').strip()) and str(client_id):
                    own.client_uuid = str(client_id)
            db.session.commit()

            # Write-through cache: reflect the edit instantly (no panel re-fetch).
            try:
                _tg = None
                _ex = None
                if user.is_superadmin:
                    if new_total_gb is not None:
                        _tg = int(float(new_total_gb) * 1024 * 1024 * 1024)
                    if new_expiry_time is not None:
                        _ex = int(new_expiry_time)
                patch_cached_client(
                    server_id, email, client_uuid=str(client_id) if client_id else None,
                    new_email=(new_email if new_email != email else None),
                    comment=(new_comment if new_comment is not None else None),
                    total_gb_bytes=_tg, expiry_ts=_ex)
            except Exception:
                pass

            return jsonify({"success": True})

    except Exception as e:
        app.logger.error(f"Edit client error: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 400


@app.route('/api/client/<int:server_id>/<email>/inbounds', methods=['POST'])
@login_required
def set_client_inbounds(server_id, email):
    """Change which inbounds a v3 client is assigned to (add/replace/remove)."""
    user = db.session.get(Admin, session['admin_id'])
    if not user:
        return jsonify({"success": False, "error": "User not found"}), 401

    server = Server.query.get_or_404(server_id)
    if not server_is_v3(server):
        return jsonify({"success": False,
                        "error": "Editing inbound assignment requires a 3x-ui v3 panel (API token)."}), 400

    data = request.get_json(silent=True) or {}
    mode = (data.get('mode') or 'set').lower()
    inbound_ids = data.get('inbound_ids') or []
    client_uuid = (data.get('client_uuid') or '').strip()

    ok, err, status, info = _reconcile_client_inbounds(
        user, server, email, client_uuid, inbound_ids, mode)
    if ok:
        return jsonify({"success": True, "info": info or {}})
    code = status if (isinstance(status, int) and status >= 400) else 400
    return jsonify({"success": False, "error": err or "Failed"}), code


@app.route('/api/client/<int:server_id>/<int:inbound_id>/<email>/delete', methods=['POST'])
@login_required
def delete_client(server_id, inbound_id, email):
    try:
        user = db.session.get(Admin, session['admin_id'])
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 401

        server = Server.query.get_or_404(server_id)

        ok, error_message, status_code = _delete_client_core(user, server, inbound_id, email)
        if ok:
            return jsonify({"success": True})
        return jsonify({"success": False, "error": error_message}), status_code
    except Exception as exc:
        app.logger.error(f"Unhandled delete_client error: {exc}", exc_info=True)
        return jsonify({"success": False, "error": f"Server error: {exc}"}), 500


def _delete_client_core(user, server, inbound_id: int, email: str):
    """Core implementation for deleting a client; returns (ok, error, status_code)."""
    if not _has_client_access(user, server.id, email, inbound_id=inbound_id):
        return False, "Access denied", 403

    target_client = _get_cached_raw_client(server.id, inbound_id, email)

    session_obj, error = get_xui_session(server)
    if error:
        return False, error, 400

    _delete_inbound_row = None
    try:
        if not target_client:
            inbounds, fetch_err, detected_type = fetch_inbounds(session_obj, server.host, server.panel_type)
            if fetch_err:
                return False, "Failed to fetch inbounds", 400

            persist_detected_panel_type(server, detected_type)
            target_client, _delete_inbound_row = find_client(inbounds, inbound_id, email)
            if not target_client:
                return False, "Client not found", 404

        client_id = target_client.get('id', target_client.get('password', email))

        # v3: delete the first-class client by email (legacy delClient is 404).
        if server_is_v3(server):
            ok, _vr, verr = v3_delete_client(server, session_obj, email)
            if not ok:
                return False, f"v3 delete failed: {verr}", 502
            email_l = (email or '').strip().lower()
            cu = str(client_id) if client_id else ''
            q = ClientOwnership.query.filter(ClientOwnership.server_id == server.id)
            kf = []
            if cu:
                kf.append(ClientOwnership.client_uuid == cu)
            if email_l:
                kf.append(func.lower(ClientOwnership.client_email) == email_l)
            if kf:
                q.filter(or_(*kf)).delete(synchronize_session=False)
            db.session.commit()
            invalidate_ownership_cache()
            try:
                log_transaction(user.id, 0, 'delete_client', f"Deleted client {email}", server_id=server.id, client_email=email)
            except Exception:
                pass
            remove_cached_client(server.id, email, client_uuid=str(client_id) if client_id else None)
            return True, None, 200

        # Shadowsocks clients have no UUID — delClient/:clientId won't work.
        # Remove the client from the full inbound settings and push.
        if 'id' not in target_client:
            _full_ib_del = _delete_inbound_row
            if _full_ib_del is None:
                _ibs_del, _fe_del, _ = fetch_inbounds(session_obj, server.host, server.panel_type)
                if not _fe_del:
                    for _ib_del in (_ibs_del or []):
                        if _ib_del.get('id') == inbound_id:
                            _full_ib_del = _ib_del
                            break
            if _full_ib_del is None:
                return False, "shadowsocks: could not fetch full inbound for delete", 400
            _fs_del = _json_field(_full_ib_del.get('settings'), {})
            _fs_del['clients'] = [c for c in _fs_del.get('clients', []) if c.get('email') != email]
            _ok_del, _err_del = _push_full_inbound(server, session_obj, _full_ib_del, _fs_del)
            if not _ok_del:
                detail = _err_del or 'shadowsocks inbound delete failed'
                app.logger.warning(f"Delete client failed for {email}: {detail}")
                return False, detail, 400
            success = True
        else:
            replacements = {
                'id': inbound_id,
                'inbound_id': inbound_id,
                'inboundId': inbound_id,
                'clientId': client_id,
                'client_id': client_id,
                'email': email
            }

            templates = collect_endpoint_templates(server.panel_type, 'client_delete', CLIENT_DELETE_FALLBACKS)
            errors = []
            success = False

            for template in templates:
                full_url = build_panel_url(server.host, template, replacements)
                if not full_url:
                    continue
                try:
                    resp = session_obj.post(full_url, verify=False, timeout=10)
                except Exception as exc:
                    errors.append(f"{template}: {exc}")
                    continue

                if resp.status_code == 200:
                    try:
                        resp_json = resp.json()
                        if isinstance(resp_json, dict) and resp_json.get('success') is False:
                            panel_msg = resp_json.get('msg') or resp_json.get('message') or 'success=false'
                            errors.append(f"{template}: {panel_msg}")
                            continue
                    except ValueError:
                        pass

                    success = True
                    break

                errors.append(f"{template}: HTTP {resp.status_code}")

            if not success:
                detail = '; '.join(errors) or 'no endpoint succeeded'
                app.logger.warning(f"Delete client failed for {email}: {detail}")
                return False, detail, 400

        if success:
            email_l = (email or '').strip().lower()
            ClientOwnership.query.filter(
                ClientOwnership.server_id == server.id,
                or_(
                    ClientOwnership.client_uuid == str(client_id),
                    func.lower(ClientOwnership.client_email) == email_l,
                )
            ).delete(synchronize_session=False)
            db.session.commit()
            invalidate_ownership_cache()

            try:
                log_transaction(user.id, 0, 'delete_client', f"Deleted client {email}", server_id=server.id, client_email=email)
            except Exception:
                pass

            remove_cached_client(server.id, email, client_uuid=str(client_id) if client_id else None,
                                 inbound_id=inbound_id)
            return True, None, 200

    except Exception as exc:
        app.logger.error(f"Delete client error: {str(exc)}")
        return False, str(exc), 400


@app.route('/api/volume-rule-presets', methods=['GET'])
@login_required
def list_volume_rule_presets():
    """Return volume-filter presets visible to the current user (own + global)."""
    user = db.session.get(Admin, session['admin_id'])
    q = VolumeRulePreset.query
    if user and user.role == 'reseller':
        q = q.filter((VolumeRulePreset.owner_id == user.id) | (VolumeRulePreset.owner_id == None))  # noqa: E711
    presets = q.order_by(VolumeRulePreset.created_at.desc()).all()
    return jsonify({'success': True, 'presets': [p.to_dict() for p in presets]})


@app.route('/api/volume-rule-presets', methods=['POST'])
@login_required
def save_volume_rule_preset():
    """Create or overwrite (by same name + owner) a volume-filter preset."""
    user = db.session.get(Admin, session['admin_id'])
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    rules = data.get('rules')
    if not name:
        return jsonify({'success': False, 'error': 'Name is required'}), 400
    if not isinstance(rules, list) or not rules:
        return jsonify({'success': False, 'error': 'At least one rule is required'}), 400

    rules_json = json.dumps(rules, ensure_ascii=False)
    # Overwrite an existing preset with the same name for this owner
    existing = VolumeRulePreset.query.filter_by(name=name, owner_id=user.id).first()
    if existing:
        existing.rules = rules_json
        preset = existing
    else:
        preset = VolumeRulePreset(name=name, rules=rules_json, owner_id=user.id)
        db.session.add(preset)
    db.session.commit()
    return jsonify({'success': True, 'preset': preset.to_dict()})


@app.route('/api/volume-rule-presets/<int:preset_id>', methods=['DELETE'])
@login_required
def delete_volume_rule_preset(preset_id):
    user = db.session.get(Admin, session['admin_id'])
    preset = db.session.get(VolumeRulePreset, preset_id)
    if not preset:
        return jsonify({'success': False, 'error': 'Preset not found'}), 404
    # Only the owner (or superadmin) can delete
    if preset.owner_id != user.id and not session.get('is_superadmin', False):
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    db.session.delete(preset)
    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/client/bulk', methods=['POST'])
@login_required
def bulk_client_action():
    user = db.session.get(Admin, session['admin_id'])
    if not user:
        return jsonify({"success": False, "error": "User not found"}), 401

    try:
        payload = request.get_json() or {}
    except Exception:
        return jsonify({"success": False, "error": "Invalid JSON"}), 400

    wait_for_completion = _parse_bool(request.args.get('wait')) or _parse_bool(payload.get('wait'))

    action = payload.get('action')
    clients = payload.get('clients')
    data = payload.get('data') or {}
    conditions = payload.get('conditions') or {}

    allowed_actions = {'enable', 'disable', 'delete', 'assign_owner', 'unassign_owner', 'add_days', 'add_volume', 'volume_policy', 'volume_multiplier', 'set_start_after_use', 'set_inbounds'}
    if action not in allowed_actions:
        return jsonify({"success": False, "error": "Invalid action"}), 400
    if not isinstance(clients, list) or len(clients) == 0:
        return jsonify({"success": False, "error": "Clients list required"}), 400

    if action == 'set_inbounds':
        if not isinstance(data, dict):
            return jsonify({"success": False, "error": "Invalid data"}), 400
        _mode = str(data.get('inbound_mode') or 'set').strip().lower()
        if _mode not in ('set', 'add', 'remove'):
            return jsonify({"success": False, "error": "inbound_mode must be set, add or remove"}), 400
        if not isinstance(data.get('inbound_ids'), list) or len(data.get('inbound_ids') or []) == 0:
            return jsonify({"success": False, "error": "inbound_ids required"}), 400

    reseller_id = None
    if action in ('assign_owner', 'unassign_owner'):
        if session.get('role') == 'reseller':
            return jsonify({"success": False, "error": "Access denied"}), 403

    if action in ('add_days', 'add_volume', 'volume_policy', 'volume_multiplier'):
        # Basic payload validation here; deep validation happens in the worker.
        if not isinstance(data, dict):
            return jsonify({"success": False, "error": "Invalid data"}), 400
        if action == 'add_days':
            if 'days_delta' not in data:
                return jsonify({"success": False, "error": "days_delta required"}), 400
        if action == 'add_volume':
            if 'volume_gb_delta' not in data:
                return jsonify({"success": False, "error": "volume_gb_delta required"}), 400
        if action == 'volume_policy':
            if not isinstance(data.get('volume_rules'), list) or len(data.get('volume_rules') or []) == 0:
                return jsonify({"success": False, "error": "volume_rules required"}), 400
        if action == 'volume_multiplier':
            try:
                factor = float(data.get('factor', 0) or 0)
            except (TypeError, ValueError):
                factor = 0
            if factor <= 0:
                return jsonify({"success": False, "error": "factor must be > 0"}), 400
            mode = str(data.get('mode') or 'set_remaining').strip().lower()
            if mode not in ('set_remaining', 'reset_and_set'):
                return jsonify({"success": False, "error": "mode must be set_remaining or reset_and_set"}), 400
            # Optional skip_min_gb / skip_max_gb — must be non-negative if provided
            for _skk in ('skip_min_gb', 'skip_max_gb'):
                _skv = data.get(_skk)
                if _skv is not None:
                    try:
                        _skf = float(_skv)
                    except (TypeError, ValueError):
                        return jsonify({"success": False, "error": f"{_skk} must be a number"}), 400
                    if _skf < 0:
                        return jsonify({"success": False, "error": f"{_skk} must be >= 0"}), 400

    if conditions is not None and not isinstance(conditions, dict):
        return jsonify({"success": False, "error": "Invalid conditions"}), 400

    if action == 'assign_owner':
        reseller_id = data.get('reseller_id')
        try:
            reseller_id = int(reseller_id)
        except (TypeError, ValueError):
            reseller_id = None
        if not reseller_id:
            return jsonify({"success": False, "error": "reseller_id required"}), 400
        reseller = db.session.get(Admin, reseller_id)
        if not reseller or reseller.role != 'reseller':
            return jsonify({"success": False, "error": "Invalid reseller"}), 400

    # Enqueue as an async job so the UI can show progress.
    # The (potentially huge) client list is kept in memory only — never written
    # to the shared JSON file — so disk writes stay tiny and fast at any scale.
    job_id = secrets.token_hex(8)
    job = {
        'id': job_id,
        'state': 'queued',
        'action': action,
        'data': data,
        'conditions': conditions,
        'user_id': user.id,
        'created_at': _utc_iso_now(),
        'created_at_ts': time.time(),
        'started_at': None,
        'finished_at': None,
        'progress': {
            'total': len(clients),
            'processed': 0,
            'success': 0,
            'failed': 0,
            'skipped': 0,
        },
        'errors': [],
        'report_rows': [],
        'report_rules': data.get('volume_rules') if action == 'volume_policy' else None,
        'error': None,
    }
    with BULK_JOBS_LOCK:
        _load_bulk_jobs_locked()
        BULK_JOBS[job_id] = job
        BULK_JOBS_CLIENTS[job_id] = clients
        _save_bulk_jobs_locked()
        _prune_bulk_jobs_locked()

    if wait_for_completion:
        _run_bulk_job(job_id)
        with BULK_JOBS_LOCK:
            _load_bulk_jobs_locked()
            done_job = BULK_JOBS.get(job_id)
            summary = _summarize_bulk_job(done_job) if done_job else None
        return jsonify({'success': True, 'job_id': job_id, 'done': True, 'job': summary})

    t = threading.Thread(target=_run_bulk_job, args=(job_id,), daemon=True)
    t.start()
    return jsonify({'success': True, 'job_id': job_id})


@app.route('/api/client/bulk/job/<job_id>', methods=['GET'])
@login_required
@limiter.exempt
def bulk_client_job(job_id):
    user = db.session.get(Admin, session['admin_id'])
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 401

    with BULK_JOBS_LOCK:
        _load_bulk_jobs_locked()
        job = BULK_JOBS.get(job_id)
        if not job:
            return jsonify({'success': False, 'error': 'Job not found'}), 404

        # Simple access control: only the job owner or superadmin can view
        try:
            if int(job.get('user_id') or 0) != int(user.id) and not session.get('is_superadmin', False):
                return jsonify({'success': False, 'error': 'Access denied'}), 403
        except Exception:
            if not session.get('is_superadmin', False):
                return jsonify({'success': False, 'error': 'Access denied'}), 403

        return jsonify({'success': True, 'job': _summarize_bulk_job(job)})


@app.route('/api/client/<email>/last-renewal', methods=['GET'])
@login_required
def client_last_renewal(email):
    """Return the most recent renewal transaction(s) for a client email so the
    operator can avoid charging the same account twice."""
    user = db.session.get(Admin, session['admin_id'])
    if not user:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401

    email_l = (email or '').strip()
    if not email_l:
        return jsonify({'success': True, 'renewals': []})

    # Match space-insensitively: v3 renames spaced emails on the panel, so old
    # transactions may be stored under the spaced email while the modal now
    # queries with the clean one (or vice versa). Normalize both sides.
    email_norm = email_l.replace(' ', '').lower()

    q = Transaction.query.filter(
        func.replace(func.lower(Transaction.client_email), ' ', '') == email_norm,
        Transaction.type == 'renew',
    )
    # Resellers only see their own transactions
    if user.role == 'reseller':
        q = q.filter(Transaction.admin_id == user.id)

    rows = q.order_by(Transaction.created_at.desc()).limit(3).all()

    renewals = []
    now = datetime.utcnow()
    for t in rows:
        created = t.created_at
        days_ago = None
        hours_ago = None
        if created:
            delta = now - created
            days_ago = delta.days
            hours_ago = int(delta.total_seconds() // 3600)
        card_label = ''
        try:
            if t.card:
                card_label = t.card.label or t.card.masked_card() or ''
        except Exception:
            card_label = ''
        renewals.append({
            'id': t.id,
            'amount': t.amount,
            'date_jalali': format_jalali(created) if created else None,
            'date_iso': created.isoformat() if created else None,
            'days_ago': days_ago,
            'hours_ago': hours_ago,
            'sender_card': t.sender_card or '',
            'dest_card': card_label,
            'description': t.description or '',
            'admin_username': (t.admin.username if getattr(t, 'admin', None) else ''),
        })

    # Gift history: gift renewals carry the Royalty marker in their description.
    # (gifts are conventionally given once, so the operator should be warned.)
    last_gift = None
    gift_count = 0
    try:
        gq = Transaction.query.filter(
            func.replace(func.lower(Transaction.client_email), ' ', '') == email_norm,
            or_(
                Transaction.description.like('%هدیه رویالتی%'),
                Transaction.description.like('%for Royalty%'),
            ),
        )
        if user.role == 'reseller':
            gq = gq.filter(Transaction.admin_id == user.id)
        gift_rows = gq.order_by(Transaction.created_at.desc()).all()
        gift_count = len(gift_rows)
        if gift_rows:
            g = gift_rows[0]
            gb = None
            m = re.search(r'\+\s*(\d+)\s*(?:GB|گیگ)', g.description or '')
            if m:
                try:
                    gb = int(m.group(1))
                except Exception:
                    gb = None
            gcreated = g.created_at
            last_gift = {
                'date_jalali': format_jalali(gcreated) if gcreated else None,
                'days_ago': (now - gcreated).days if gcreated else None,
                'gift_gb': gb,
                'admin_username': (g.admin.username if getattr(g, 'admin', None) else ''),
            }
    except Exception:
        last_gift = None
        gift_count = 0

    return jsonify({'success': True, 'renewals': renewals, 'last_gift': last_gift, 'gift_count': gift_count})


@app.route('/api/client/<int:server_id>/<int:inbound_id>/<email>/renew', methods=['POST'])
@login_required
def renew_client(server_id, inbound_id, email):
    """Renew client expiry and/or volume"""
    t0 = time.perf_counter()
    renewal_trace_id = secrets.token_hex(4)
    timing = {
        "total_ms": None,
        "used_cache_client": False,
        "login_ms": None,
        "fetch_inbounds_ms": None,
        "update_post_ms": None,
        "reset_traffic_ms": None,
        "verify_fetch_ms": None,
        "update_endpoint": None,
        "update_status": None,
    }

    def _finish(payload: dict, status_code: int = 200):
        try:
            timing["total_ms"] = int((time.perf_counter() - t0) * 1000)
        except Exception:
            timing["total_ms"] = None
        if isinstance(payload, dict):
            payload.setdefault("trace_id", renewal_trace_id)
            payload.setdefault("timing", timing)
        # Log only slow renews (keeps logs clean)
        try:
            if timing.get("total_ms") is not None and timing["total_ms"] >= 2000:
                app.logger.info(
                    f"Renew timing: trace={renewal_trace_id}, server={server_id}, inbound={inbound_id}, email={email}, timing={timing}"
                )
        except Exception:
            pass
        return jsonify(payload), status_code

    user = db.session.get(Admin, session['admin_id'])
    if not user:
        return _finish({"success": False, "error": "User not found"}, 401)

    server = db.session.get(Server, server_id)
    if not server:
        return _finish({"success": False, "error": "Server not found"}, 404)

    try:
        data = request.get_json() or {}
    except Exception:
        return _finish({"success": False, "error": "Invalid request data"}, 400)

    start_after_first_use = bool(data.get('start_after_first_use', False))
    reset_traffic = bool(data.get('reset_traffic', False))
    is_free = bool(data.get('free', False))
    mode = (data.get('mode') or 'custom').lower()
    if mode not in ('package', 'custom'):
        mode = 'custom'

    price = 0
    days_to_add = 0
    volume_gb_to_add = 0
    volume_provided = False
    description = ""

    try:
        if mode == 'package':
            pkg_id = data.get('package_id')
            package = db.session.get(Package, pkg_id) if pkg_id else None
            if not package or not getattr(package, 'enabled', True):
                return _finish({"success": False, "error": "Invalid package selected"}, 400)
            days_to_add = int(package.days or 0)
            volume_gb_to_add = int(package.volume or 0)
            volume_provided = True
            price = calculate_reseller_price(user, package=package)
            description = f"Renew Package: {package.name} - {email}"
            if days_to_add < 0:
                return _finish({"success": False, "error": "Package is misconfigured (negative days)"}, 400)
        else:
            days_to_add = int(data.get('days', 0))
            raw_volume = data.get('volume', None)
            if raw_volume is None:
                volume_provided = False
                volume_gb_to_add = 0
            elif isinstance(raw_volume, str) and raw_volume.strip() == '':
                volume_provided = False
                volume_gb_to_add = 0
            else:
                volume_provided = True
                volume_gb_to_add = int(raw_volume)
            if volume_gb_to_add < 0:
                volume_gb_to_add = 0
            if days_to_add < 0:
                days_to_add = 0
            # 0 days or 0 volume means unlimited; allowed for unlimited users
            
            reseller_context_id = user.id if user.role == 'reseller' else None
            price, _cpg, _cpd, _tier = _calculate_minimum_price(
                volume_gb_to_add,
                days_to_add,
                reseller_id=reseller_context_id,
                server_id=server_id,
                user=user,
            )
            days_label = f"{days_to_add} Days" if days_to_add > 0 else "Unlimited Days"
            if not volume_provided:
                vol_label = "Keep Volume"
            else:
                vol_label = f"{volume_gb_to_add} GB" if volume_gb_to_add > 0 else "Unlimited Volume"
            description = f"Renew Custom: {days_label}, {vol_label} - {email}"
    except (ValueError, TypeError) as e:
        return _finish({"success": False, "error": f"Invalid data: {e}"}, 400)
    except Exception as e:
        app.logger.error(f"Renew price-calc error (trace={renewal_trace_id}): {e}", exc_info=True)
        return _finish({"success": False, "error": f"Server error during price calculation: {e}"}, 500)

    if is_free:
        price = 0

    # Gift volume: added on top of the renewal volume, free of charge.
    try:
        gift_volume_gb = int(data.get('gift_volume_gb') or 0)
        if gift_volume_gb < 0:
            gift_volume_gb = 0
    except (TypeError, ValueError):
        gift_volume_gb = 0

    if gift_volume_gb > 0:
        volume_gb_to_add += gift_volume_gb
        volume_provided = True
        _is_fa = (session.get('panel_lang') or _get_panel_ui_lang() or 'en') == 'fa'
        gift_note = f"+{gift_volume_gb} گیگ هدیه رویالتی" if _is_fa else f"+{gift_volume_gb} GB for Royalty"
        description = f"{description} ({gift_note})"

    try:
        if user.role == 'reseller':
            if not _has_client_access(user, server_id, email, inbound_id=inbound_id):
                return _finish({"success": False, "error": "Access denied"}, 403)
            ok, err = _user_can_afford(user, price)
            if not ok:
                return _finish({"success": False, "error": err}, 402)
    except Exception as e:
        app.logger.error(f"Renew access-check error (trace={renewal_trace_id}): {e}", exc_info=True)
        return _finish({"success": False, "error": f"Server error during access check: {e}"}, 500)

    # Optimization: Try to find client in global cache first to avoid slow fetch_inbounds
    # NOTE: cached display rows include usage stats while `raw_client` often does not.
    target_client = None
    cached_client_row = None
    fetched_inbound_row = None
    stats_up = 0
    stats_down = 0
    cached_inbounds = GLOBAL_SERVER_DATA.get('inbounds') or []
    for ib in cached_inbounds:
        try:
            if int(ib.get('server_id', -1)) == int(server.id) and int(ib.get('id', -1)) == int(inbound_id):
                for c in ib.get('clients', []):
                    if c.get('email') == email and 'raw_client' in c:
                        target_client = copy.deepcopy(c['raw_client'])
                        cached_client_row = c
                        timing["used_cache_client"] = True
                        break
        except (ValueError, TypeError):
            continue
        if target_client: break

    t_login0 = time.perf_counter()
    session_obj, error = get_xui_session(server)
    timing["login_ms"] = int((time.perf_counter() - t_login0) * 1000)
    if error:
        return _finish({"success": False, "error": error}, 400)
    
    try:
        if not target_client:
            # Fallback to fetching from panel if not in cache
            t_fetch0 = time.perf_counter()
            inbounds, fetch_err, detected_type = fetch_inbounds(session_obj, server.host, server.panel_type)
            timing["fetch_inbounds_ms"] = int((time.perf_counter() - t_fetch0) * 1000)
            if fetch_err:
                return _finish({"success": False, "error": "Failed to fetch inbounds"}, 400)

            persist_detected_panel_type(server, detected_type)
            target_client, fetched_inbound_row = find_client(inbounds, inbound_id, email)
            if not target_client:
                return _finish({"success": False, "error": "Client not found"}, 404)

            # Try to capture traffic usage from the inbound's clientStats.
            # Many panels do NOT include up/down in the client settings list.
            try:
                for st in (fetched_inbound_row or {}).get('clientStats', []) or []:
                    if (st.get('email') or '') == email:
                        stats_up = int(st.get('up') or 0)
                        stats_down = int(st.get('down') or 0)
                        break
            except Exception:
                stats_up = 0
                stats_down = 0

        # If we used cached raw_client, merge in traffic/cap fields from the cached row.
        # This avoids undercounting usage when `raw_client` is missing one direction
        # OR contains a stale smaller number.
        # NOTE: cached_client_row.expiryTime is a human string; use expiryTimestamp instead.
        if cached_client_row and isinstance(target_client, dict):
            try:
                cached_up = int(cached_client_row.get('up') or 0)
            except Exception:
                cached_up = 0
            try:
                cur_up = int(target_client.get('up') or 0)
            except Exception:
                cur_up = 0
            if cached_up > cur_up:
                target_client['up'] = cached_up

            try:
                cached_down = int(cached_client_row.get('down') or 0)
            except Exception:
                cached_down = 0
            try:
                cur_down = int(target_client.get('down') or 0)
            except Exception:
                cur_down = 0
            if cached_down > cur_down:
                target_client['down'] = cached_down

            try:
                if target_client.get('totalGB') in (None, '', 0) and cached_client_row.get('totalGB') not in (None, ''):
                    target_client['totalGB'] = cached_client_row.get('totalGB')
            except Exception:
                pass
            try:
                if target_client.get('expiryTime') in (None, '', 0) and cached_client_row.get('expiryTimestamp') not in (None, ''):
                    target_client['expiryTime'] = cached_client_row.get('expiryTimestamp')
            except Exception:
                pass

        try:
            current_expiry_ms = int(target_client.get('expiryTime') or 0)
        except (TypeError, ValueError):
            current_expiry_ms = 0

        # Snapshot current remaining values for message rendering.
        # IMPORTANT: keep rounding consistent with UI (format_remaining_days uses floor .days).
        remaining_days_before = 0
        try:
            expiry_info_before = format_remaining_days(current_expiry_ms)
            raw_days = int(expiry_info_before.get('days') or 0)
            if raw_days > 0:
                remaining_days_before = raw_days
            elif expiry_info_before.get('type') == 'start_after_use' and raw_days >= 0:
                remaining_days_before = raw_days
            else:
                remaining_days_before = 0
        except Exception:
            remaining_days_before = 0

        try:
            current_total_bytes = int(target_client.get('totalGB') or 0)
        except (TypeError, ValueError):
            current_total_bytes = 0

        try:
            used_up = int(target_client.get('up') or 0)
        except (TypeError, ValueError):
            used_up = 0
        try:
            used_down = int(target_client.get('down') or 0)
        except (TypeError, ValueError):
            used_down = 0

        # If the raw client doesn't carry traffic fields (common), fall back to clientStats.
        # Some panels only include one direction (up/down) in the client settings list.
        # Prefer clientStats when it provides missing OR higher values to avoid undercounting usage.
        try:
            if stats_up or stats_down:
                try:
                    su = int(stats_up or 0)
                except Exception:
                    su = 0
                try:
                    sd = int(stats_down or 0)
                except Exception:
                    sd = 0

                if su:
                    used_up = max(int(used_up or 0), su)
                if sd:
                    used_down = max(int(used_down or 0), sd)
        except Exception:
            pass
        used_bytes = max(0, used_up + used_down)

        remaining_gb_before = 0
        remaining_gb_before_exact = 0.0
        has_limited_volume = current_total_bytes > 0
        if has_limited_volume:
            remaining_bytes = current_total_bytes - used_bytes
            if remaining_bytes < 0:
                remaining_bytes = 0

            # Keep an exact value for renewal message (e.g. 45.11GB).
            remaining_gb_before_exact = (
                remaining_bytes / float(1024 * 1024 * 1024) if remaining_bytes > 0 else 0.0
            )

            # Keep a coarse integer variant for legacy template placeholders.
            gb_float = remaining_gb_before_exact
            rounded_gb = int(gb_float + 0.5) if gb_float > 0 else 0
            remaining_gb_before = max(1, rounded_gb) if remaining_bytes > 0 else 0
        
        # Calculate new expiry
        if days_to_add == 0:
            # 0 days = unlimited expiry
            new_expiry = 0
        elif start_after_first_use:
            new_expiry = -1 * (days_to_add * 86400000)
        else:
            current_expiry = target_client.get('expiryTime', 0)
            # If the client is not started yet (negative expiry), keep it not-started
            # and add days to the pending duration.
            try:
                current_expiry_int = int(current_expiry or 0)
            except (TypeError, ValueError):
                current_expiry_int = 0

            if current_expiry_int < 0:
                new_expiry = current_expiry_int - (days_to_add * 86400000)
            elif current_expiry_int > 0:
                # Add days in milliseconds (avoids DST/timezone edge cases)
                new_expiry = int(current_expiry_int) + int(days_to_add * 86400000)
            else:
                new_expiry = int(time.time() * 1000) + int(days_to_add * 86400000)
        
        # Update volume
        current_volume = current_total_bytes
        
        if reset_traffic:
            target_client['up'] = 0
            target_client['down'] = 0
            # If resetting, keep cap unless user explicitly provided a new cap.
            if not volume_provided:
                new_volume = current_volume
            else:
                # 0 = unlimited, >0 = set exact cap
                if volume_gb_to_add > 0:
                    new_volume = volume_gb_to_add * 1024 * 1024 * 1024
                else:
                    new_volume = 0  # unlimited
        else:
            # When adding volume:
            # - If volume not provided: keep existing cap
            # - If provided: 0 means set to unlimited, >0 means add to current
            if not volume_provided:
                new_volume = current_volume
            elif volume_gb_to_add == 0:
                new_volume = 0  # unlimited
            elif volume_gb_to_add > 0:
                # If current is unlimited (0), keep unlimited.
                if current_volume == 0:
                    new_volume = 0
                else:
                    new_volume = current_volume + (volume_gb_to_add * 1024 * 1024 * 1024)
            else:
                new_volume = current_volume
        
        # Check if client was disabled before we re-enable it (for notification)
        _was_disabled = not target_client.get('enable', True)

        # Update client — always re-enable so disabled-due-to-traffic clients go active immediately
        target_client['expiryTime'] = new_expiry
        target_client['totalGB'] = new_volume
        target_client['enable'] = True

        client_id = target_client.get('id', target_client.get('password', email))

        update_payload = {
            "id": inbound_id,
            "settings": json.dumps({"clients": [target_client]})
        }

        replacements = {
            'id': inbound_id,
            'inbound_id': inbound_id,
            'inboundId': inbound_id,
            'clientId': client_id,
            'client_id': client_id,
            'email': email
        }

        _is_v3 = server_is_v3(server)
        # Shadowsocks clients have no UUID 'id' field — updateClient/:clientId won't work.
        _is_shadowsocks_no_id = (not _is_v3) and ('id' not in target_client)

        class _SyntheticOK:  # lets the v3 path reuse the legacy post-success block
            status_code = 200
            @staticmethod
            def json():
                return {"success": True}

        templates = collect_endpoint_templates(server.panel_type, 'client_update', CLIENT_UPDATE_FALLBACKS)
        errors = []
        t_update0 = time.perf_counter()
        for template in templates:
            full_url = build_panel_url(server.host, template, replacements)
            if not full_url:
                continue
            if _is_v3:
                # v3: first-class client update by email (legacy updateClient is 404)
                ok, _vr, verr = v3_update_client(server, session_obj, email, target_client)
                if not ok:
                    errors.append(f"v3 update: {verr}")
                    break
                # v3 renames the client to the space-free email on the panel during
                # the update, so every later lookup (reset, verify) and the success
                # message must use the clean email — otherwise find_client returns
                # client_not_found and the message shows the old spaced email.
                email = _v3_sanitize_email(email)
                resp = _SyntheticOK()
            elif _is_shadowsocks_no_id:
                # Shadowsocks clients have no UUID — use full inbound update instead.
                _full_ib = fetched_inbound_row
                if _full_ib is None:
                    # Came from cache; re-fetch to get the complete inbound object.
                    _ibs_fresh, _fe2, _ = fetch_inbounds(session_obj, server.host, server.panel_type)
                    if not _fe2:
                        for _ib in (_ibs_fresh or []):
                            if _ib.get('id') == inbound_id:
                                _full_ib = _ib
                                break
                if _full_ib is None:
                    errors.append("shadowsocks: could not fetch full inbound for update")
                    break
                _full_settings = _json_field(_full_ib.get('settings'), {})
                _full_settings['clients'] = [
                    target_client if c.get('email') == email else c
                    for c in _full_settings.get('clients', [])
                ]
                _ok_push, _push_err = _push_full_inbound(server, session_obj, _full_ib, _full_settings)
                if not _ok_push:
                    errors.append(f"shadowsocks inbound update: {_push_err}")
                    break
                resp = _SyntheticOK()
            else:
                try:
                    resp = session_obj.post(full_url, json=update_payload, verify=False, timeout=10)
                except Exception as exc:
                    errors.append(f"{template}: {exc}")
                    continue
            if resp.status_code == 200:
                timing["update_post_ms"] = int((time.perf_counter() - t_update0) * 1000)
                timing["update_endpoint"] = template
                timing["update_status"] = resp.status_code
                try:
                    resp_json = resp.json()
                    if isinstance(resp_json, dict) and resp_json.get('success') is False:
                        errors.append(f"{template}: success false")
                        continue
                except ValueError:
                    pass
                
                # If reset_traffic was requested, we must call the specific reset endpoint
                # because updateClient usually ignores 'up'/'down' fields.
                if reset_traffic and _is_v3:
                    t_reset0 = time.perf_counter()
                    v3_reset_client(server, session_obj, email)
                    timing["reset_traffic_ms"] = int((time.perf_counter() - t_reset0) * 1000)
                elif reset_traffic:
                    reset_templates = collect_endpoint_templates(server.panel_type, 'client_reset_traffic', CLIENT_RESET_FALLBACKS)
                    t_reset0 = time.perf_counter()
                    for r_template in reset_templates:
                        r_url = build_panel_url(server.host, r_template, replacements)
                        if not r_url: continue
                        
                        # Some panels need email in body, some in URL. Try both if needed.
                        requires_path_email = (':email' in r_template) or ('{email}' in r_template)
                        r_payload = None if requires_path_email else {"email": email}
                        
                        try:
                            if r_payload is None:
                                session_obj.post(r_url, verify=False, timeout=5)
                            else:
                                session_obj.post(r_url, json=r_payload, verify=False, timeout=5)
                            # We don't strictly check success here as the main update succeeded, 
                            # but we try our best to reset traffic.
                        except:
                            pass
                    timing["reset_traffic_ms"] = int((time.perf_counter() - t_reset0) * 1000)

                sender_card = data.get('sender_card', '') or ''
                card_id = data.get('card_id')
                if is_free:
                    if user.role == 'reseller':
                        log_transaction(user.id, 0, 'renew', f"User Renewal (Free) - {description}", server_id=server.id, sender_card=sender_card, card_id=card_id, category='usage', client_email=email)
                    else:
                        log_transaction(user.id, 0, 'renew', f"User Renewal (Free) - {description}", server_id=server.id, sender_card=sender_card, card_id=card_id, category='income', client_email=email)
                    db.session.commit()
                elif price > 0:
                    if user.role == 'reseller':
                        user.credit -= price
                        log_transaction(user.id, -price, 'renew', f"User Renewal (Credit Usage) - {description}", server_id=server.id, sender_card=sender_card, card_id=card_id, category='usage', client_email=email)
                    else:
                        log_transaction(user.id, price, 'renew', f"User Renewal (Income) - {description}", server_id=server.id, sender_card=sender_card, card_id=card_id, category='income', client_email=email)
                    db.session.commit()

                # Post-update verify (best-effort): fetch inbounds and confirm expiry/volume.
                verify = {
                    "attempted": True,
                    "ok": None,
                    "error": None,
                    "expected": {
                        "expiryTime": new_expiry,
                        "totalGB": new_volume,
                    },
                    "observed": {
                        "expiryTime": None,
                        "totalGB": None,
                    },
                }
                try:
                    t_v0 = time.perf_counter()
                    v_inbounds, v_err, _ = fetch_inbounds(session_obj, server.host, server.panel_type)
                    timing["verify_fetch_ms"] = int((time.perf_counter() - t_v0) * 1000)
                    if v_err or not v_inbounds:
                        verify["ok"] = False
                        verify["error"] = v_err or "verify_fetch_failed"
                    else:
                        v_client, v_inbound = find_client(v_inbounds, inbound_id, email)
                        if not v_client:
                            verify["ok"] = False
                            verify["error"] = "client_not_found_after_update"
                        else:
                            try:
                                verify["observed"]["expiryTime"] = int(v_client.get('expiryTime') or 0)
                            except Exception:
                                verify["observed"]["expiryTime"] = None
                            try:
                                verify["observed"]["totalGB"] = int(v_client.get('totalGB') or 0)
                            except Exception:
                                verify["observed"]["totalGB"] = None

                            # Compute service state for immediate UI update
                            try:
                                v_up = 0
                                v_down = 0
                                for st in (v_inbound.get('clientStats', []) if v_inbound else []):
                                    if st.get('email') == email:
                                        v_up = st.get('up', 0)
                                        v_down = st.get('down', 0)
                                        break
                                
                                v_total = verify["observed"]["totalGB"] or 0
                                v_remaining = max(v_total - (v_up + v_down), 0) if v_total > 0 else None
                                v_expiry = verify["observed"]["expiryTime"] or 0
                                v_expiry_info = format_remaining_days(v_expiry, lang=_get_panel_ui_lang())
                                
                                v_state = _compute_client_service_state(
                                    enabled=bool(v_client.get('enable', True)),
                                    total_bytes=v_total,
                                    remaining_bytes=v_remaining,
                                    expiry_ts=v_expiry,
                                    expiry_info=v_expiry_info,
                                    thresholds=_get_dashboard_status_thresholds(),
                                    lang=_get_panel_ui_lang()
                                )
                                verify["observed"]["service_state_label"] = v_state.get('label')
                                verify["observed"]["service_state_emoji"] = v_state.get('emoji')
                                verify["observed"]["service_state_tag"] = v_state.get('tag')
                                verify["observed"]["up"] = v_up
                                verify["observed"]["down"] = v_down
                                verify["observed"]["enable"] = bool(v_client.get('enable', True))
                            except Exception as e:
                                app.logger.error(f"Error computing service state in renew verify: {e}")

                            ok_exp = (verify["observed"]["expiryTime"] == int(new_expiry or 0))
                            ok_vol = (verify["observed"]["totalGB"] == int(new_volume or 0))
                            verify["ok"] = bool(ok_exp and ok_vol)
                except Exception as exc:
                    verify["ok"] = False
                    verify["error"] = str(exc)

                # Build copyable success text (dynamic template)
                now_utc = datetime.utcnow()

                # Message values:
                # - If start_after_first_use: show the package/custom amount (days_to_add)
                # - If reset_traffic: show the package/custom amount (volume_gb_to_add)
                # - Otherwise: show remaining_before + added (days/GB)
                if days_to_add <= 0:
                    msg_days = '♾️'
                    days_label = "♾️"
                elif start_after_first_use:
                    msg_days = days_to_add
                    days_label = f"{msg_days} Days"
                else:
                    msg_days = int(remaining_days_before) + int(days_to_add)
                    days_label = f"{msg_days} Days"

                if not volume_provided:
                    # No volume change: show remaining (or unlimited)
                    if not has_limited_volume:
                        msg_volume = '♾️'
                        volume_label = "♾️"
                    else:
                        msg_volume = int(remaining_gb_before)
                        volume_label = f"{remaining_gb_before_exact:.2f}GB"
                elif volume_gb_to_add == 0:
                    msg_volume = '♾️'
                    volume_label = "♾️"
                elif reset_traffic:
                    msg_volume = int(volume_gb_to_add)
                    volume_label = f"{msg_volume}GB"
                else:
                    if not has_limited_volume:
                        msg_volume = '♾️'
                        volume_label = "♾️"
                    else:
                        msg_volume = int(remaining_gb_before) + int(volume_gb_to_add)
                        volume_label = f"{(remaining_gb_before_exact + float(volume_gb_to_add)):.2f}GB"

                # `{date}` should represent the new expiry, not "now".
                # - Finite expiry (>0): show Jalali Tehran date+time
                # - Unlimited (0): Persian label
                # - Not started (<0): show "N days after first use"
                if new_expiry == 0:
                    date_label = "نامحدود"
                elif new_expiry < 0:
                    date_label = f"{msg_days} روز بعد از اولین اتصال"
                else:
                    try:
                        expiry_dt_utc = datetime.utcfromtimestamp(int(new_expiry) / 1000)
                    except Exception:
                        expiry_dt_utc = now_utc
                    date_label = format_jalali(expiry_dt_utc) or ''

                # Dashboard link
                app_base = request.url_root.rstrip('/')
                final_id = target_client.get('subId') or target_client.get('id') or ''
                dashboard_link = f"{app_base}/s/{server.id}/{final_id}" if final_id else ""

                active_tpl = RenewTemplate.query.filter_by(is_active=True).first()
                tpl_content = active_tpl.content if active_tpl else DEFAULT_RENEW_TEMPLATE
                _renew_tpl_vars = {
                    'email': email,
                    'days': msg_days,
                    'days_label': days_label,
                    'volume': msg_volume,
                    'volume_label': volume_label,
                    'date': date_label,
                    'server_name': getattr(server, 'name', '') or '',
                    'mode': mode,
                    'dashboard_link': dashboard_link,
                }
                copy_text = _render_text_template(tpl_content, _renew_tpl_vars)

                whatsapp_runtime = _get_whatsapp_runtime_settings()
                _client_comment = (target_client.get('comment') or '') if target_client else ''
                whatsapp_delivery = _send_whatsapp_message('renew_success', email, copy_text, recipient_comment=_client_comment)
                whatsapp_meta = {
                    'enabled': whatsapp_runtime.get('enabled', False),
                    'deployment_region': whatsapp_runtime.get('deployment_region', 'outside'),
                    'provider': whatsapp_runtime.get('provider', 'baileys'),
                    'trigger_renew_success': whatsapp_runtime.get('trigger_renew_success', False),
                    'blocked_reason': whatsapp_runtime.get('blocked_reason') if not whatsapp_runtime.get('enabled', False) else None,
                    'delivery': whatsapp_delivery,
                }

                # Write-through cache: reflect the renewal instantly (no panel re-fetch).
                try:
                    patch_cached_client(
                        server_id, email,
                        client_uuid=str(target_client.get('id')) if target_client and target_client.get('id') else None,
                        total_gb_bytes=int(target_client.get('totalGB') or 0),
                        expiry_ts=int(target_client.get('expiryTime') or 0),
                        enable=(True if _was_disabled else None),
                        up=(0 if reset_traffic else None),
                        down=(0 if reset_traffic else None))
                except Exception:
                    pass

                return _finish({"success": True, "copy_text": copy_text, "tpl_vars": _renew_tpl_vars, "verify": verify, "whatsapp": whatsapp_meta, "was_reactivated": _was_disabled})

            errors.append(f"{template}: {resp.status_code}")
            timing["update_endpoint"] = template
            timing["update_status"] = resp.status_code
            if resp.status_code != 404:
                break

        app.logger.warning(f"Renew failed for {email}: {'; '.join(errors)}")
        return _finish({"success": False, "error": "Client update endpoint returned error"}, 400)
    except Exception as e:
        app.logger.error(f"Renew error: {str(e)}")
        return _finish({"success": False, "error": str(e)}, 400)


@app.route('/api/client/<int:server_id>/<int:inbound_id>/<email>/renew/verify', methods=['POST'])
@login_required
def verify_renew_client(server_id, inbound_id, email):
    """Re-check a client's expiry/volume on the panel after a renew.

    Expected values are optional:
      {"expected_expiryTime": <ms>, "expected_totalGB": <bytes>}
    """
    trace_id = secrets.token_hex(4)
    t0 = time.perf_counter()

    def _finish(payload: dict, status_code: int = 200):
        try:
            payload.setdefault('timing', {})
            payload['timing']['total_ms'] = int((time.perf_counter() - t0) * 1000)
        except Exception:
            payload.setdefault('timing', {})
            payload['timing']['total_ms'] = None
        payload.setdefault('trace_id', trace_id)
        return jsonify(payload), status_code

    user = db.session.get(Admin, session.get('admin_id'))
    if not user:
        return _finish({'success': False, 'error': 'User not found'}, 401)

    server = Server.query.get_or_404(server_id)

    try:
        data = request.get_json() or {}
    except Exception:
        data = {}

    expected_expiry = data.get('expected_expiryTime', None)
    expected_total = data.get('expected_totalGB', None)
    try:
        expected_expiry = None if expected_expiry is None else int(expected_expiry)
    except Exception:
        expected_expiry = None
    try:
        expected_total = None if expected_total is None else int(expected_total)
    except Exception:
        expected_total = None

    # Access control for resellers
    if user.role == 'reseller':
        if not _has_client_access(user, server_id, email, inbound_id=inbound_id):
            return _finish({'success': False, 'error': 'Access denied'}, 403)

    t_login0 = time.perf_counter()
    session_obj, error = get_xui_session(server)
    login_ms = int((time.perf_counter() - t_login0) * 1000)
    if error:
        return _finish({'success': False, 'error': error, 'timing': {'login_ms': login_ms}}, 400)

    verify = {
        'attempted': True,
        'ok': None,
        'error': None,
        'expected': {'expiryTime': expected_expiry, 'totalGB': expected_total},
        'observed': {'expiryTime': None, 'totalGB': None},
    }

    try:
        t_v0 = time.perf_counter()
        inbounds, fetch_err, detected_type = fetch_inbounds(session_obj, server.host, server.panel_type)
        verify_fetch_ms = int((time.perf_counter() - t_v0) * 1000)
        persist_detected_panel_type(server, detected_type)
        if fetch_err or not inbounds:
            verify['ok'] = False
            verify['error'] = fetch_err or 'verify_fetch_failed'
            return _finish({'success': True, 'verify': verify, 'timing': {'login_ms': login_ms, 'verify_fetch_ms': verify_fetch_ms}})

        v_client, _ = find_client(inbounds, inbound_id, email)
        if not v_client and server_is_v3(server):
            # v3 stores the client email without spaces; retry the lookup with
            # the sanitized form so Re-check works after a spaced-email rename.
            _clean = _v3_sanitize_email(email)
            if _clean and _clean != email:
                v_client, _ = find_client(inbounds, inbound_id, _clean)
                if v_client:
                    email = _clean
        if not v_client:
            verify['ok'] = False
            verify['error'] = 'client_not_found'
            return _finish({'success': True, 'verify': verify, 'timing': {'login_ms': login_ms, 'verify_fetch_ms': verify_fetch_ms}})

        try:
            verify['observed']['expiryTime'] = int(v_client.get('expiryTime') or 0)
        except Exception:
            verify['observed']['expiryTime'] = None
        try:
            verify['observed']['totalGB'] = int(v_client.get('totalGB') or 0)
        except Exception:
            verify['observed']['totalGB'] = None

        # If expected values are not provided, we just return observed.
        if expected_expiry is None and expected_total is None:
            verify['ok'] = True
        else:
            ok_exp = True if expected_expiry is None else (verify['observed']['expiryTime'] == expected_expiry)
            ok_vol = True if expected_total is None else (verify['observed']['totalGB'] == expected_total)
            verify['ok'] = bool(ok_exp and ok_vol)

        return _finish({'success': True, 'verify': verify, 'timing': {'login_ms': login_ms, 'verify_fetch_ms': verify_fetch_ms}})
    except Exception as exc:
        verify['ok'] = False
        verify['error'] = str(exc)
        return _finish({'success': True, 'verify': verify, 'timing': {'login_ms': login_ms}})

@app.route('/api/admins', methods=['GET'])
@user_management_required
def get_admins():
    admins = Admin.query.all()
    return jsonify([a.to_dict() for a in admins])

@app.route('/api/admins', methods=['POST'])
@superadmin_required
def add_admin():
    data = request.json
    username = data.get('username', '').strip().lower()
    
    if not username:
        return jsonify({"success": False, "error": "Username is required"}), 400
    
    if ' ' in username:
        return jsonify({"success": False, "error": "Username cannot contain spaces"}), 400
        
    # Check for Persian characters
    if any(u'\u0600' <= c <= u'\u06FF' for c in username):
        return jsonify({"success": False, "error": "Persian characters are not allowed"}), 400

    if Admin.query.filter_by(username=username).first():
        return jsonify({"success": False, "error": "Username exists"}), 400
    
    password = data.get('password')
    is_valid, error_msg = validate_password_strength(password)
    if not is_valid:
        return jsonify({"success": False, "error": error_msg}), 400

    def _clean_telegram_username(v: str | None) -> str:
        val = (v or '').strip()
        if not val:
            return ''
        if val.startswith('@'):
            val = val[1:].strip()
        val = re.sub(r'^(https?://)?(t\.me/|telegram\.me/)', '', val, flags=re.IGNORECASE)
        val = val.strip('/').strip()
        val = re.sub(r'[^0-9a-zA-Z_]', '', val)
        return (val or '')[:100]

    def _clean_whatsapp_number(v: str | None) -> str:
        val = (v or '').strip()
        if not val:
            return ''
        val = re.sub(r'^(https?://)?wa\.me/', '', val, flags=re.IGNORECASE)
        val = val.strip('/').strip()
        val = re.sub(r'[^0-9+]', '', val)
        return (val or '')[:64]

    def _clean_url(v: str | None, *, limit: int = 1000) -> str:
        return (v or '').strip()[:limit]

    new_admin = Admin(
        username=username,
        role=data.get('role', 'reseller'),
        is_superadmin=(data.get('role') == 'superadmin'),
        credit=int(data.get('credit', 0)),
        allow_negative_credit=bool(data.get('allow_negative_credit', False)),
        negative_credit_limit=max(0, int(data.get('negative_credit_limit', 0) or 0)),
        allowed_servers=serialize_allowed_servers(data.get('allowed_servers', [])),
        enabled=data.get('enabled', True),
        discount_percent=int(data.get('discount_percent', 0)),
        custom_cost_per_day=int(data.get('custom_cost_per_day')) if data.get('custom_cost_per_day') is not None else None,
        custom_cost_per_gb=int(data.get('custom_cost_per_gb')) if data.get('custom_cost_per_gb') is not None else None,
        telegram_id=sanitize_html(data.get('telegram_id')),
        support_telegram=_clean_telegram_username(data.get('support_telegram')),
        support_whatsapp=_clean_whatsapp_number(data.get('support_whatsapp')),
        support_sms=_clean_whatsapp_number(data.get('support_sms')),
        channel_telegram=_clean_url(data.get('channel_telegram')),
        channel_whatsapp=_clean_url(data.get('channel_whatsapp')),
    )
    new_admin.set_password(password)
    db.session.add(new_admin)
    db.session.commit()
    return jsonify({"success": True})

@app.route('/api/admins/<int:admin_id>', methods=['PUT'])
@user_management_required
def update_admin(admin_id):
    admin = Admin.query.get_or_404(admin_id)
    data = request.json

    editor = db.session.get(Admin, session.get('admin_id'))
    editor_is_super = bool(editor and (editor.role == 'superadmin' or editor.is_superadmin))
    target_is_super = bool(admin and (admin.role == 'superadmin' or admin.is_superadmin))

    if not editor_is_super and target_is_super:
        return jsonify({"success": False, "error": "Access Denied"}), 403

    def _clean_telegram_username(v: str | None) -> str:
        val = (v or '').strip()
        if not val:
            return ''
        if val.startswith('@'):
            val = val[1:].strip()
        val = re.sub(r'^(https?://)?(t\.me/|telegram\.me/)', '', val, flags=re.IGNORECASE)
        val = val.strip('/').strip()
        val = re.sub(r'[^0-9a-zA-Z_]', '', val)
        return (val or '')[:100]

    def _clean_whatsapp_number(v: str | None) -> str:
        val = (v or '').strip()
        if not val:
            return ''
        val = re.sub(r'^(https?://)?wa\.me/', '', val, flags=re.IGNORECASE)
        val = val.strip('/').strip()
        val = re.sub(r'[^0-9+]', '', val)
        return (val or '')[:64]

    def _clean_url(v: str | None, *, limit: int = 1000) -> str:
        return (v or '').strip()[:limit]

    if 'username' in data:
        new_username = _normalize_username(data.get('username'))
        # Important: if the only difference is casing (e.g. "Salar" -> "salar"),
        # we still want to persist the normalized value so login works.
        if new_username and new_username != (admin.username or ''):
            err = _validate_username(new_username)
            if err:
                return jsonify({"success": False, "error": err}), 400
            existing = Admin.query.filter(
                func.lower(Admin.username) == new_username,
                Admin.id != admin.id
            ).first()
            if existing:
                return jsonify({"success": False, "error": "Username exists"}), 400
            admin.username = new_username

    if data.get('password'):
        is_valid, error_msg = validate_password_strength(data['password'])
        if not is_valid:
            return jsonify({"success": False, "error": error_msg}), 400
        admin.set_password(data['password'])
    if data.get('role'):
        new_role = (data.get('role') or '').strip().lower()
        if new_role:
            if new_role == 'superadmin' and not editor_is_super:
                return jsonify({"success": False, "error": "Access Denied"}), 403
            admin.role = new_role
            admin.is_superadmin = (new_role == 'superadmin')
    if 'credit' in data: admin.credit = int(data['credit'])
    if 'allow_negative_credit' in data: admin.allow_negative_credit = bool(data['allow_negative_credit'])
    if 'negative_credit_limit' in data: admin.negative_credit_limit = max(0, int(data['negative_credit_limit'] or 0))
    if 'allowed_servers' in data: admin.allowed_servers = serialize_allowed_servers(data['allowed_servers'])
    if 'enabled' in data: admin.enabled = data['enabled']
    if 'discount_percent' in data: admin.discount_percent = int(data['discount_percent'])
    if 'custom_cost_per_day' in data: 
        admin.custom_cost_per_day = int(data['custom_cost_per_day']) if data['custom_cost_per_day'] is not None else None
    if 'custom_cost_per_gb' in data: 
        admin.custom_cost_per_gb = int(data['custom_cost_per_gb']) if data['custom_cost_per_gb'] is not None else None
    if 'telegram_id' in data: admin.telegram_id = sanitize_html(data['telegram_id'])
    if 'support_telegram' in data: admin.support_telegram = _clean_telegram_username(data.get('support_telegram'))
    if 'support_whatsapp' in data: admin.support_whatsapp = _clean_whatsapp_number(data.get('support_whatsapp'))
    if 'support_sms' in data: admin.support_sms = _clean_whatsapp_number(data.get('support_sms'))
    if 'channel_telegram' in data: admin.channel_telegram = _clean_url(data.get('channel_telegram'))
    if 'channel_whatsapp' in data: admin.channel_whatsapp = _clean_url(data.get('channel_whatsapp'))
    db.session.commit()

    # Keep session consistent if user edited self
    try:
        if editor and int(editor.id) == int(admin.id):
            session['admin_username'] = admin.username
            session['role'] = admin.role
            session['is_superadmin'] = (admin.role == 'superadmin' or admin.is_superadmin)
    except Exception:
        pass
    return jsonify({"success": True})

@app.route('/api/admins/<int:admin_id>', methods=['DELETE'])
@superadmin_required
def delete_admin(admin_id):
    if admin_id == session['admin_id']:
        return jsonify({"success": False, "error": "Self-delete not allowed"}), 400
    admin = Admin.query.get_or_404(admin_id)
    db.session.delete(admin)
    db.session.commit()
    return jsonify({"success": True})

@app.route('/api/servers', methods=['GET'])
@login_required
def get_servers():
    user = db.session.get(Admin, session['admin_id'])
    if user.role == 'reseller':
        servers = get_accessible_servers(user)
    else:
        servers = Server.query.all()
    status_map = {}
    for st in (GLOBAL_SERVER_DATA.get('servers_status') or []):
        try:
            sid = int(st.get('server_id', -1))
        except Exception:
            continue
        if sid > 0:
            status_map[sid] = st

    payload = []
    for s in servers:
        item = s.to_dict()
        st = status_map.get(int(s.id)) or {}
        item.update({
            'online_count': st.get('online_count'),
            'xui_version': st.get('xui_version'),
            'xray_version': st.get('xray_version'),
            'xray_state': st.get('xray_state'),
            'xray_core': st.get('xray_core'),
            'panel_status_error': st.get('panel_status_error'),
            'panel_status_checked_at': st.get('panel_status_checked_at'),
            'reachable': st.get('reachable'),
            'reachable_error': st.get('reachable_error')
        })
        payload.append(item)

    # Never cache the server list — edits must show immediately, not a stale
    # browser/proxy copy.
    resp = jsonify(payload)
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    return resp

@app.route('/api/servers', methods=['POST'])
@login_required
def add_server():
    if session.get('role') == 'reseller':
        return jsonify({"success": False, "error": "Only admins can add servers"}), 403
    
    data = request.json
    server_password = (data.get('password') or '').strip()
    if not server_password:
        return jsonify({"success": False, "error": "Password is required"}), 400
    _api_token = (data.get('api_token') or '').strip()
    server = Server(
        name=sanitize_html(data['name']),
        host=sanitize_html(data['host']),
        username=sanitize_html(data['username']),
        password=encrypt_server_password(server_password),
        panel_type=data.get('panel_type', 'auto'),
        sub_path=data.get('sub_path', '/sub/'),
        json_path=data.get('json_path', '/json/'),
        sub_port=data.get('sub_port'),
        api_token=encrypt_server_password(_api_token) if _api_token else None,
    )
    db.session.add(server)
    db.session.commit()
    return jsonify({"success": True, "id": server.id})

@app.route('/api/servers/<int:server_id>', methods=['PUT'])
@login_required
def update_server(server_id):
    if session.get('role') == 'reseller':
        return jsonify({"success": False, "error": "Only admins can update servers"}), 403
    
    server = Server.query.get_or_404(server_id)
    data = request.json
    server.name = sanitize_html(data.get('name', server.name))
    server.host = sanitize_html(data.get('host', server.host))
    server.username = sanitize_html(data.get('username', server.username))
    if 'password' in data:
        new_password = (data.get('password') or '').strip()
        if new_password:
            server.password = encrypt_server_password(new_password)
    server.panel_type = data.get('panel_type', server.panel_type)
    server.sub_path = data.get('sub_path', server.sub_path)
    server.json_path = data.get('json_path', server.json_path)
    server.sub_port = data.get('sub_port', server.sub_port)
    server.enabled = data.get('enabled', server.enabled)
    if 'hidden' in data:
        server.hidden = bool(data['hidden'])
    if 'api_token' in data:
        _tok = (data.get('api_token') or '').strip()
        # Non-empty → set/replace; explicit empty string → clear it.
        server.api_token = encrypt_server_password(_tok) if _tok else None
    db.session.commit()
    # Token change alters auth — drop any cached session so the next call re-auths.
    XUI_SESSION_CACHE.pop(server_id, None)
    return jsonify({"success": True})


@app.route('/api/servers/<int:server_id>/hidden', methods=['POST'])
@login_required
def toggle_server_hidden(server_id):
    """Toggle server hidden flag. Hidden servers are skipped in fetching/dashboard but still backed up."""
    if session.get('role') == 'reseller':
        return jsonify({"success": False, "error": "Only admins can toggle server visibility"}), 403
    server = Server.query.get_or_404(server_id)
    server.hidden = not bool(server.hidden)
    db.session.commit()
    if server.hidden:
        # Remove from in-memory cache so it disappears from dashboard immediately
        GLOBAL_SERVER_DATA['inbounds'] = [
            item for item in (GLOBAL_SERVER_DATA.get('inbounds') or [])
            if str(item.get('server_id') or '') != str(server_id)
        ]
        GLOBAL_SERVER_DATA['servers_status'] = [
            item for item in (GLOBAL_SERVER_DATA.get('servers_status') or [])
            if str(item.get('server_id') or '') != str(server_id)
        ]
    return jsonify({"success": True, "hidden": server.hidden})


@app.route('/api/servers/<int:server_id>', methods=['DELETE'])
@login_required
def delete_server(server_id):
    if session.get('role') == 'reseller':
        return jsonify({"success": False, "error": "Only admins can delete servers"}), 403

    server = Server.query.get_or_404(server_id)

    try:
        db.session.execute(
            announcement_servers.delete().where(announcement_servers.c.server_id == server_id)
        )
        ClientOwnership.query.filter_by(server_id=server_id).delete(synchronize_session=False)
        UsageSnapshot.query.filter_by(server_id=server_id).delete(synchronize_session=False)
        RenewalEvent.query.filter_by(server_id=server_id).delete(synchronize_session=False)
        PriceTier.query.filter_by(server_id=server_id).delete(synchronize_session=False)
        Transaction.query.filter_by(server_id=server_id).update(
            {Transaction.server_id: None},
            synchronize_session=False
        )

        db.session.delete(server)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        app.logger.exception("Failed to delete server %s", server_id)
        return jsonify({
            "success": False,
            "error": "Server could not be deleted. Please check related records and try again.",
            "details": str(exc)
        }), 500

    XUI_SESSION_CACHE.pop(server_id, None)
    REFRESH_BACKOFF.pop(server_id, None)
    invalidate_ownership_cache()
    GLOBAL_SERVER_DATA['inbounds'] = [
        item for item in (GLOBAL_SERVER_DATA.get('inbounds') or [])
        if str(item.get('server_id') or '') != str(server_id)
    ]
    GLOBAL_SERVER_DATA['servers_status'] = [
        item for item in (GLOBAL_SERVER_DATA.get('servers_status') or [])
        if str(item.get('id') or item.get('server_id') or '') != str(server_id)
    ]
    return jsonify({"success": True})

@app.route('/api/servers/<int:server_id>/test', methods=['POST'])
@login_required
def test_server_connection(server_id):
    server = Server.query.get_or_404(server_id)
    session_obj, error = get_xui_session(server)
    if error:
        return jsonify({"success": False, "error": error}), 400
    # Actually read data so a wrong API token / unreachable panel is caught here
    # (Bearer auth sets a header without contacting the panel, so we must probe).
    inbounds, fetch_err, detected_type = fetch_inbounds(session_obj, server.host, server.panel_type)
    if fetch_err:
        return jsonify({"success": False, "error": fetch_err}), 400
    return jsonify({
        "success": True,
        "panel_type": detected_type or server.panel_type,
        "inbound_count": len(inbounds or []),
        "auth": "token" if server_is_v3(server) else "login",
    })


@app.route('/api/servers/<int:server_id>/xui-backup', methods=['GET'])
@login_required
def download_server_xui_backup(server_id):
    """Download the X-UI database backup for a single server.

    Used by the bulk-action confirmation modal so the operator can grab a
    safety backup of the panel DB before applying changes.
    """
    server = Server.query.get_or_404(server_id)
    # Resellers cannot pull raw panel DB backups
    if session.get('role') == 'reseller':
        return jsonify({"success": False, "error": "Only admins can download panel backups"}), 403

    session_obj, error = get_xui_session(server)
    if error:
        return jsonify({"success": False, "error": error}), 400

    payload, ext, err = _fetch_xui_backup(session_obj, server)
    if not payload:
        return jsonify({"success": False, "error": err or "Backup failed"}), 502

    safe_name = secure_filename(server.name) or f"server_{server.id}"
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"xui_{safe_name}_{ts}{ext or '.db'}"
    return send_file(
        io.BytesIO(payload),
        mimetype='application/octet-stream',
        as_attachment=True,
        download_name=filename,
    )


@app.route('/api/servers/<int:server_id>/panel-info', methods=['GET'])
@login_required
def get_server_panel_info(server_id):
    """Quick fetch: login → status endpoint → return version/state info.
    Does NOT fetch inbounds. Designed to be called right after adding a server."""
    server = Server.query.get_or_404(server_id)

    session_obj, login_error = get_xui_session(server)
    if login_error:
        return jsonify({"success": False, "error": login_error}), 400

    status_payload, status_error, detected_type = fetch_server_status(
        session_obj, server.host, server.panel_type
    )

    if detected_type and detected_type != 'auto':
        persist_detected_panel_type(server, detected_type)

    info = {
        "success": True,
        "server_id": server.id,
        "panel_type": server.panel_type or detected_type or "auto",
        "xui_version": None,
        "xray_version": None,
        "xray_state": None,
        "xray_core": None,
        "status_error": status_error,
    }

    if status_payload:
        normalized = _normalize_server_status_payload(status_payload)
        info.update({
            "xui_version": normalized.get("xui_version"),
            "xray_version": normalized.get("xray_version"),
            "xray_state": normalized.get("xray_state"),
            "xray_core": normalized.get("xray_core"),
        })

    # Also update in-memory cache so GET /api/servers reflects this immediately
    existing = GLOBAL_SERVER_DATA.get('servers_status') or []
    updated = False
    for st in existing:
        if isinstance(st, dict) and st.get('server_id') == server.id:
            st.update({k: v for k, v in info.items() if k not in ('success', 'status_error')})
            st['panel_status_checked_at'] = datetime.utcnow().isoformat()
            updated = True
            break
    if not updated:
        entry = {k: v for k, v in info.items() if k not in ('success', 'status_error')}
        entry['panel_status_checked_at'] = datetime.utcnow().isoformat()
        entry['panel_status_error'] = status_error
        GLOBAL_SERVER_DATA.setdefault('servers_status', []).append(entry)

    return jsonify(info)

@app.route('/api/assign-client', methods=['POST'])
@user_management_required
def assign_client():
    data = request.json
    server_id = data.get('server_id')
    email = (data.get('email') or '').strip()
    reseller_id = data.get('reseller_id')
    inbound_id = data.get('inbound_id')
    client_uuid = (data.get('client_uuid') or '').strip()

    try:
        server_id = int(server_id)
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "server_id required"}), 400

    if not email:
        return jsonify({"success": False, "error": "email required"}), 400

    # Treat reseller_id=0 / null as "unassign to system"
    try:
        reseller_id_int = int(reseller_id) if reseller_id is not None else 0
    except (TypeError, ValueError):
        reseller_id_int = 0

    email_l = email.lower()

    match_filters = [ClientOwnership.server_id == server_id]
    match_key_filters = []
    if client_uuid:
        match_key_filters.append(ClientOwnership.client_uuid == client_uuid)
    if email_l:
        match_key_filters.append(func.lower(ClientOwnership.client_email) == email_l)
    if match_key_filters:
        match_filters.append(or_(*match_key_filters))

    if reseller_id_int <= 0:
        # Unassign: delete any ownership records for this server+email
        try:
            q = ClientOwnership.query
            for f in match_filters:
                q = q.filter(f)
            q.delete(synchronize_session=False)
            db.session.commit()
            return jsonify({"success": True})
        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "error": str(e)}), 500

    reseller = db.session.get(Admin, reseller_id_int)
    if not reseller or reseller.role != 'reseller':
        return jsonify({"success": False, "error": "Invalid reseller"}), 400

    try:
        inbound_id_int = int(inbound_id) if inbound_id is not None and str(inbound_id).strip() != '' else None
    except (TypeError, ValueError):
        inbound_id_int = None

    # Reassign: ensure uniqueness by removing previous owners for this server+email
    try:
        q = ClientOwnership.query
        for f in match_filters:
            q = q.filter(f)
        q.delete(synchronize_session=False)

        ownership = ClientOwnership(
            reseller_id=reseller_id_int,
            server_id=server_id,
            inbound_id=inbound_id_int,
            client_email=email,
            client_uuid=client_uuid if client_uuid else None
        )
        db.session.add(ownership)

        # Keep reseller "Allowed Servers" in sync with assignments
        try:
            ensure_reseller_allowed_for_assignment(reseller, server_id, inbound_id_int)
        except Exception:
            pass

        db.session.commit()
        invalidate_ownership_cache()
        return jsonify({"success": True})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/resellers/<int:reseller_id>/bulk-assign-inbound', methods=['POST'])
@user_management_required
def bulk_assign_inbound(reseller_id):
    """Assign all existing clients in a cached inbound to a reseller."""
    data = request.json or {}
    try:
        server_id  = int(data['server_id'])
        inbound_id = int(data['inbound_id'])
    except (KeyError, TypeError, ValueError):
        return jsonify({"success": False, "error": "server_id and inbound_id required"}), 400

    reseller = db.session.get(Admin, reseller_id)
    if not reseller or reseller.role != 'reseller':
        return jsonify({"success": False, "error": "Invalid reseller"}), 400

    # Find the inbound in the in-memory cache
    cached_inbounds = GLOBAL_SERVER_DATA.get('inbounds') or []
    target_inbound = None
    for inb in cached_inbounds:
        try:
            if int(inb.get('server_id', -1)) == server_id and int(inb.get('id', -1)) == inbound_id:
                target_inbound = inb
                break
        except (TypeError, ValueError):
            continue

    if not target_inbound:
        return jsonify({"success": False,
                        "error": "Inbound not in cache — refresh server data first"}), 404

    clients = target_inbound.get('clients') or []

    assigned = 0
    skipped  = 0
    try:
        for client in clients:
            email       = (client.get('email') or '').strip()
            client_uuid = (client.get('id')    or '').strip()
            if not email and not client_uuid:
                skipped += 1
                continue

            # Skip if already owned by this reseller on this inbound
            q = ClientOwnership.query.filter_by(
                reseller_id=reseller_id,
                server_id=server_id,
                inbound_id=inbound_id
            )
            if email:
                q = q.filter(func.lower(ClientOwnership.client_email) == email.lower())
            if q.first():
                skipped += 1
                continue

            # Remove any prior ownership of this client on this server
            del_q = ClientOwnership.query.filter(ClientOwnership.server_id == server_id)
            if email:
                del_q = del_q.filter(func.lower(ClientOwnership.client_email) == email.lower())
            elif client_uuid:
                del_q = del_q.filter(ClientOwnership.client_uuid == client_uuid)
            del_q.delete(synchronize_session=False)

            db.session.add(ClientOwnership(
                reseller_id=reseller_id,
                server_id=server_id,
                inbound_id=inbound_id,
                client_email=email or client_uuid,
                client_uuid=client_uuid or None,
            ))
            assigned += 1

        if assigned > 0:
            try:
                ensure_reseller_allowed_for_assignment(reseller, server_id, inbound_id)
            except Exception:
                pass

        db.session.commit()
        invalidate_ownership_cache()
        return jsonify({"success": True, "assigned": assigned, "skipped": skipped})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/client/qrcode', methods=['GET'])
def generate_qrcode():
    """Generate QR code from URL query parameter (GET request)"""
    link = request.args.get('link', '')
    if not link:
        return jsonify({"success": False, "error": "Link required"}), 400
    
    try:
        qr = qrcode.QRCode(version=1, box_size=10, border=2)
        qr.add_data(link)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        qr_base64 = base64.b64encode(buffer.getvalue()).decode()
        return jsonify({"success": True, "qrcode": f"data:image/png;base64,{qr_base64}"})
    except Exception as e:
        app.logger.error(f"QR Code error: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/api/client/<int:server_id>/qrcode', methods=['POST'])
@login_required
def client_qrcode():
    data = request.json
    url = data.get('url')
    if not url: return jsonify({"success": False}), 400
    
    try:
        qr = qrcode.QRCode(version=1, box_size=10, border=2)
        qr.add_data(url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        qr_base64 = base64.b64encode(buffer.getvalue()).decode()
        return jsonify({"success": True, "qrcode": f"data:image/png;base64,{qr_base64}"})
    except:
        return jsonify({"success": False}), 400

@app.route('/api/client/<int:server_id>/<int:inbound_id>/add', methods=['POST'])
@login_required
def add_client(server_id, inbound_id):
    user = db.session.get(Admin, session['admin_id'])
    server = Server.query.get_or_404(server_id)
    allowed_map, assignments = get_reseller_access_maps(user) if user.role == 'reseller' else ('*', {})
    
    data = request.json or {}
    email = data.get('email', '').strip()
    
    if not email: return jsonify({"success": False, "error": "Email is required"})

    mode = data.get('mode', 'custom')
    start_after_first_use = bool(data.get('start_after_first_use', False))
    is_free = bool(data.get('free', False))
    
    if not email: return jsonify({"success": False, "error": "Email is required"})

    price = 0
    days = 0
    volume_gb = 0
    description = ""

    if mode == 'package':
        pkg_id = data.get('package_id')
        package = db.session.get(Package, pkg_id)
        if not package: return jsonify({"success": False, "error": "Invalid Package"}), 400
        
        price = calculate_reseller_price(user, package=package)
        days = package.days
        volume_gb = package.volume
        description = f"Purchase Package: {package.name} - {email}"
        
    else:
        days = int(data.get('days', 30))
        volume_gb = int(data.get('volume', 0))

        reseller_context_id = user.id if user.role == 'reseller' else None
        price, _cpg, _cpd, _tier = _calculate_minimum_price(
            volume_gb,
            days,
            reseller_id=reseller_context_id,
            server_id=server_id,
            user=user,
        )
        days_label = 'Unlimited' if days == 0 else str(days)
        vol_label  = 'Unlimited' if volume_gb == 0 else str(volume_gb)
        description = f"Custom Plan: {days_label} Days, {vol_label} GB - {email}"

    if is_free:
        price = 0

    if user.role == 'reseller':
        if not is_server_accessible(server_id, allowed_map, assignments):
            return jsonify({"success": False, "error": "Access to this server is denied"}), 403
        if not is_inbound_accessible(server_id, inbound_id, allowed_map, assignments):
            return jsonify({"success": False, "error": "Access to this inbound is denied"}), 403
        
        ok, err = _user_can_afford(user, price)
        if not ok:
            return jsonify({"success": False, "error": err}), 402

    session_obj, error = get_xui_session(server)
    if error: return jsonify({"success": False, "error": error})

    try:
        client_uuid = str(uuid.uuid4())
        client_sub_id = ''.join(secrets.choice(string.ascii_letters + string.digits) for i in range(16))
        
        expiry_time = 0
        if start_after_first_use:
            expiry_time = -1 * (days * 86400000)
        elif days > 0:
            expiry_time = int((datetime.now() + timedelta(days=days)).timestamp() * 1000)
            
        new_client = {
            "id": client_uuid,
            "email": email,
            "comment": (data.get('comment') or '').strip(),
            "enable": True,
            "expiryTime": expiry_time,
            "totalGB": volume_gb * 1024 * 1024 * 1024 if volume_gb > 0 else 0,
            "subId": client_sub_id,
            "limitIp": 0,
            "flow": "",
            "tgId": "",
            "reset": 0
        }

        # ── 3x-ui v3+ : assign one client to one OR MANY inbounds in a single call.
        # Only taken when the client sent inbound_ids (v3 multi-assign UI); otherwise
        # the universal single-inbound flow below runs (works on every panel version).
        _req_inbound_ids = data.get('inbound_ids')
        if server_is_v3(server) and isinstance(_req_inbound_ids, list) and _req_inbound_ids:
            try:
                assign_ids = sorted({int(x) for x in _req_inbound_ids if x is not None})
            except Exception:
                assign_ids = []
            if not assign_ids:
                assign_ids = [inbound_id]

            ok, _vr, verr = v3_add_client(server, session_obj, new_client, assign_ids)
            if not ok:
                return jsonify({"success": False, "error": f"v3 add failed: {verr}"}), 502

            # Billing (charged once for the whole client)
            sender_card = data.get('sender_card', '') or ''
            card_id = data.get('card_id')
            if is_free:
                log_transaction(user.id, 0, 'purchase', f"Add User (Free) - {description}", server_id=server.id, sender_card=sender_card, card_id=card_id, category=('usage' if user.role == 'reseller' else 'income'), client_email=email)
            elif price > 0:
                if user.role == 'reseller':
                    user.credit -= price
                    log_transaction(user.id, -price, 'purchase', "Add User (Credit Usage)", server_id=server.id, sender_card=sender_card, card_id=card_id, category='usage', client_email=email)
                else:
                    log_transaction(user.id, price, 'purchase', "Add User (Income)", server_id=server.id, sender_card=sender_card, card_id=card_id, category='income', client_email=email)

            # Ownership row per assigned inbound (price recorded once on the first)
            for _idx, _iid in enumerate(assign_ids):
                db.session.add(ClientOwnership(
                    reseller_id=user.id, server_id=server.id, inbound_id=_iid,
                    client_email=email, client_uuid=client_uuid,
                    price=(price if _idx == 0 else 0)))
                try:
                    ensure_reseller_allowed_for_assignment(user, server.id, _iid)
                except Exception:
                    pass
            db.session.commit()
            invalidate_ownership_cache()

            # Links from subId (one subscription aggregates all assigned inbounds)
            parsed_host = urlparse(server.host)
            final_port = server.sub_port if server.sub_port else parsed_host.port
            port_str = f":{final_port}" if final_port else ""
            base_sub = f"{parsed_host.scheme}://{parsed_host.hostname}{port_str}"
            final_id = client_sub_id or client_uuid
            sub_url = f"{base_sub}/{(server.sub_path or '').strip('/')}/{final_id}"
            try:
                app_base = request.url_root.rstrip('/')
            except Exception:
                app_base = ''
            dash_sub_url = f"{app_base}/s/{server.id}/{final_id}"

            # Protocol label = distinct protocols across the assigned inbounds
            _protos = []
            for ib in (GLOBAL_SERVER_DATA.get('inbounds') or []):
                try:
                    if int(ib.get('server_id', -1)) == int(server.id) and int(ib.get('id', -1)) in assign_ids:
                        _protos.append(ib.get('protocol') or '')
                except Exception:
                    continue
            proto_label = ', '.join(sorted({p for p in _protos if p})) or 'vless'

            copy_text = ''
            try:
                active_tpl = NotificationTemplate.query.filter_by(type='client_created', is_active=True).first()
                if active_tpl and active_tpl.content:
                    vol_label = '♾️' if volume_gb == 0 else f'{volume_gb} GB'
                    days_label_cc = '♾️' if days == 0 else f'{days}'
                    copy_text = _render_text_template(active_tpl.content, {
                        'service_name': email, 'email': email, 'protocol': proto_label,
                        'volume': vol_label, 'days': days_label_cc, 'sub_link': sub_url,
                        'dashboard_link': dash_sub_url, 'server_name': getattr(server, 'name', '') or '',
                        'comment': data.get('comment', '') or '',
                    })
            except Exception:
                copy_text = ''

            return jsonify({
                "success": True,
                "copy_text": copy_text,
                "client": {
                    "email": email, "comment": data.get('comment', '') or '',
                    "protocol": proto_label, "volume": volume_gb, "days": days,
                    "sub_link": sub_url, "direct_link": None, "dashboard_link": dash_sub_url,
                    "inbound_ids": assign_ids,
                }
            })

        inbound_data = None
        last_fetch_error = None
        last_fetch_url = None

        for tpl in collect_endpoint_templates(server.panel_type, 'inbounds_get', INBOUND_GET_FALLBACKS):
            get_url = build_panel_url(server.host, tpl, {'id': inbound_id})
            if not get_url:
                continue
            last_fetch_url = get_url
            try:
                # Use a short connect timeout and a longer read timeout to reduce false failures on slow panels.
                get_resp = session_obj.get(get_url, verify=False, timeout=(3, 20))
            except requests.exceptions.ConnectTimeout:
                app.logger.warning(f"Panel connect timeout while fetching inbound (server_id={server.id}, host={server.host}, url={get_url})")
                return jsonify({"success": False, "error": f"Connection timeout to panel for server '{server.name}'. Check port/firewall and panel availability."}), 504
            except requests.exceptions.ReadTimeout:
                app.logger.warning(f"Panel read timeout while fetching inbound (server_id={server.id}, host={server.host}, url={get_url})")
                return jsonify({"success": False, "error": f"Panel response timeout for server '{server.name}'. The panel may be slow or overloaded."}), 504
            except requests.exceptions.ConnectionError as exc:
                app.logger.warning(f"Panel connection error while fetching inbound (server_id={server.id}, host={server.host}, url={get_url}): {exc}")
                return jsonify({"success": False, "error": f"Unable to connect to panel for server '{server.name}'. Check host/port and network connectivity."}), 502

            if get_resp.status_code != 200:
                last_fetch_error = f"Unexpected status {get_resp.status_code}"
                continue

            get_json, get_err = _safe_response_json(get_resp)
            if get_err:
                last_fetch_error = get_err
                continue

            if not isinstance(get_json, dict):
                last_fetch_error = "Unexpected response shape"
                continue

            obj = get_json.get('obj')
            if obj is None:
                obj = get_json.get('data')

            if isinstance(obj, dict) and obj:
                inbound_data = obj
                break

            # Some panels wrap as {success:true, data:{...}} or return empty on wrong endpoint.
            last_fetch_error = "Empty inbound data"

        if not inbound_data:
            details = last_fetch_error or 'Failed to fetch inbound data from panel'
            if last_fetch_url:
                details = f"{details} (last url: {last_fetch_url})"
            return jsonify({
                "success": False,
                "error": f"{details}. If this is an Alireza panel, ensure endpoints like /xui/API/... are reachable and server Panel URL/webpath is correct."
            }), 502

        settings = _json_field(inbound_data.get('settings'), {})
        settings.setdefault('clients', [])

        for c in settings['clients']:
            if c['email'] == email: return jsonify({"success": False, "error": f"Email '{email}' already exists on server"})

        # Protocol-specific credentials. VLESS/VMess use `id` (already set); but
        # Shadowsocks needs a per-client method+password and Trojan needs a
        # password — without them x-ui fails: "Shadowsocks password is not specified".
        _proto = (inbound_data.get('protocol') or '').lower()
        if _proto == 'shadowsocks':
            _ss_method = settings.get('method') or 'chacha20-ietf-poly1305'
            new_client['method'] = _ss_method
            new_client['password'] = _ss_password(_ss_method)
        elif _proto == 'trojan':
            new_client['password'] = new_client.get('password') or secrets.token_urlsafe(16)

        settings['clients'].append(new_client)
        
        update_data = inbound_data.copy()
        update_data['settings'] = json.dumps(settings)

        update_ok = False
        update_error = None

        for tpl in collect_endpoint_templates(server.panel_type, 'inbounds_update', INBOUND_UPDATE_FALLBACKS):
            up_url = build_panel_url(server.host, tpl, {'id': inbound_id})
            if not up_url:
                continue
            try:
                up_resp = session_obj.post(up_url, json=update_data, verify=False, timeout=(3, 20))
            except requests.exceptions.ConnectTimeout:
                app.logger.warning(f"Panel connect timeout while updating inbound (server_id={server.id}, host={server.host}, url={up_url})")
                return jsonify({"success": False, "error": f"Connection timeout to panel for server '{server.name}'. Check port/firewall and panel availability."}), 504
            except requests.exceptions.ReadTimeout:
                app.logger.warning(f"Panel read timeout while updating inbound (server_id={server.id}, host={server.host}, url={up_url})")
                return jsonify({"success": False, "error": f"Panel response timeout for server '{server.name}'. The panel may be slow or overloaded."}), 504
            except requests.exceptions.ConnectionError as exc:
                app.logger.warning(f"Panel connection error while updating inbound (server_id={server.id}, host={server.host}, url={up_url}): {exc}")
                return jsonify({"success": False, "error": f"Unable to connect to panel for server '{server.name}'. Check host/port and network connectivity."}), 502

            if up_resp.status_code != 200:
                update_error = f"Unexpected status {up_resp.status_code}"
                continue

            up_json, up_err = _safe_response_json(up_resp)
            if up_err:
                update_error = up_err
                continue
            if isinstance(up_json, dict) and up_json.get('success'):
                update_ok = True
                break

            if isinstance(up_json, dict):
                update_error = up_json.get('msg') or up_json.get('message') or 'Panel update failed'
            else:
                update_error = 'Panel update failed'

        if update_ok:

            sender_card = data.get('sender_card', '') or ''
            card_id = data.get('card_id')
            if is_free:
                if user.role == 'reseller':
                    log_transaction(user.id, 0, 'purchase', f"Add User (Free) - {description}", server_id=server.id, sender_card=sender_card, card_id=card_id, category='usage', client_email=email)
                else:
                    log_transaction(user.id, 0, 'purchase', f"Add User (Free) - {description}", server_id=server.id, sender_card=sender_card, card_id=card_id, category='income', client_email=email)
            elif price > 0:
                if user.role == 'reseller':
                    user.credit -= price
                    log_transaction(user.id, -price, 'purchase', "Add User (Credit Usage)", server_id=server.id, sender_card=sender_card, card_id=card_id, category='usage', client_email=email)
                else:
                    log_transaction(user.id, price, 'purchase', "Add User (Income)", server_id=server.id, sender_card=sender_card, card_id=card_id, category='income', client_email=email)
            
            ownership = ClientOwnership(
                reseller_id=user.id,
                server_id=server.id,
                inbound_id=inbound_id,
                client_email=email,
                client_uuid=client_uuid,
                price=price
            )
            db.session.add(ownership)

            # Keep reseller "Allowed Servers" UI in sync with ownership creation
            try:
                ensure_reseller_allowed_for_assignment(user, server.id, inbound_id)
            except Exception:
                pass

            db.session.commit()
            invalidate_ownership_cache()

            # Generate Links for Response
            parsed_host = urlparse(server.host)
            hostname = parsed_host.hostname
            scheme = parsed_host.scheme
            final_port = server.sub_port if server.sub_port else parsed_host.port
            port_str = f":{final_port}" if final_port else ""
            
            base_sub = f"{scheme}://{hostname}{port_str}"
            s_path = server.sub_path.strip('/')
            final_id = client_sub_id if client_sub_id else client_uuid
            
            sub_url = f"{base_sub}/{s_path}/{final_id}"
            app_base = request.url_root.rstrip('/')
            dash_sub_url = f"{app_base}/s/{server.id}/{final_id}"
            
            # Fetch direct link from upstream subscription instead of generating manually.
            # Short timeout so a slow/overloaded panel doesn't add seconds to every
            # "add client" call — we fall back to local generation immediately.
            direct_link = None
            try:
                sub_resp = requests.get(
                    sub_url,
                    headers={'User-Agent': 'v2rayng'},
                    timeout=(2, 3),
                    verify=False,
                    allow_redirects=False
                )
                if sub_resp.status_code == 200:
                    raw_content = sub_resp.content or b''
                    try:
                        decoded = base64.b64decode(raw_content).decode('utf-8')
                    except Exception:
                        decoded = raw_content.decode('utf-8', errors='ignore')
                    configs = [line.strip() for line in decoded.splitlines() if line.strip()]
                    if configs:
                        direct_link = configs[0]  # First config is usually the main one
            except Exception as e:
                app.logger.debug(f"Failed to fetch direct link from sub: {e}")
            
            # Fallback to manual generation if upstream failed
            if not direct_link:
                direct_link = generate_client_link(new_client, inbound_data, server.host)

            # Render the active Client Created Notification template (if any).
            vol_label = '♾️' if volume_gb == 0 else f'{volume_gb} GB'
            days_label_cc = '♾️' if days == 0 else f'{days}'
            _cc_tpl_vars = {
                'service_name': email,
                'email': email,
                'protocol': inbound_data.get('protocol', 'vless'),
                'volume': vol_label,
                'days': days_label_cc,
                'sub_link': sub_url,
                'dashboard_link': dash_sub_url,
                'server_name': getattr(server, 'name', '') or '',
                'comment': data.get('comment', '') or '',
            }
            copy_text = ''
            try:
                active_tpl = NotificationTemplate.query.filter_by(
                    type='client_created', is_active=True
                ).first()
                if active_tpl and active_tpl.content:
                    copy_text = _render_text_template(active_tpl.content, _cc_tpl_vars)
            except Exception:
                copy_text = ''

            return jsonify({
                "success": True,
                "copy_text": copy_text,
                "tpl_vars": _cc_tpl_vars,
                "client": {
                    "email": email,
                    "comment": data.get('comment', '') or '',
                    "protocol": inbound_data.get('protocol', 'vless'),
                    "volume": volume_gb,
                    "days": days,
                    "sub_link": sub_url,
                    "direct_link": direct_link,
                    "dashboard_link": dash_sub_url
                }
            })
        else:
            return jsonify({"success": False, "error": f"Panel Error: {update_error or 'Panel update failed'}"})

    except Exception as e:
        app.logger.error(f"Add client error (server_id={server_id}, inbound_id={inbound_id}): {e}")
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/packages', methods=['GET'])
@login_required
def get_packages():
    import json as _j
    user = db.session.get(Admin, session['admin_id'])
    packages = Package.query.filter_by(enabled=True).order_by(Package.display_order, Package.id).all()

    # Build creator username lookup
    creator_ids = {p.created_by for p in packages if p.created_by}
    creator_map = {}
    if creator_ids:
        creators = Admin.query.filter(Admin.id.in_(list(creator_ids))).all()
        creator_map = {a.id: a.username for a in creators}

    result = []
    for p in packages:
        scope = p.scope or 'global'
        # Resellers only see global or packages explicitly assigned to them
        if user.role == 'reseller':
            if scope == 'global':
                pass
            elif scope == 'assigned':
                try:
                    ids = _j.loads(p.assigned_reseller_ids or '[]')
                except Exception:
                    ids = []
                if user.id not in ids:
                    continue
            else:  # personal — admin-only
                continue
        # Admins / superadmins see all scopes

        p_dict = p.to_dict()
        p_dict['price'] = calculate_reseller_price(user, package=p)
        p_dict['created_by_username'] = creator_map.get(p.created_by)
        result.append(p_dict)

    resp = make_response(jsonify(result))
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp

@app.route('/admin/packages', methods=['POST'])
@user_management_required
def create_package():
    import json as _j
    data = request.json or {}
    reseller_ids = data.get('reseller_ids', data.get('assigned_reseller_ids', []))
    if not isinstance(reseller_ids, list):
        reseller_ids = []
    package = Package(
        name=data.get('name'),
        days=int(data.get('days', 0)),
        volume=int(data.get('volume', 0)),
        price=int(data.get('price')),
        reseller_price=int(data.get('reseller_price')) if data.get('reseller_price') is not None else None,
        enabled=data.get('enabled', True),
        scope=data.get('scope', 'global'),
        assigned_reseller_ids=_j.dumps([int(r) for r in reseller_ids]),
        created_by=session.get('admin_id'),
        show_on_sub=bool(data.get('show_on_sub', False)),
        created_at=datetime.utcnow(),
    )
    db.session.add(package)
    db.session.commit()
    return jsonify({"success": True, "id": package.id})

@app.route('/admin/packages/<int:package_id>', methods=['PUT'])
@user_management_required
def update_package(package_id):
    package = Package.query.get_or_404(package_id)
    data = request.json or {}
    if 'name' in data:
        package.name = data['name']
    if 'days' in data:
        package.days = int(data['days'])
    if 'volume' in data:
        package.volume = int(data['volume'])
    if 'price' in data:
        package.price = int(data['price'])
    if 'reseller_price' in data:
        package.reseller_price = int(data['reseller_price']) if data['reseller_price'] is not None else None
    if 'enabled' in data:
        package.enabled = bool(data['enabled'])
    if 'scope' in data:
        package.scope = data['scope']
    if 'show_on_sub' in data:
        package.show_on_sub = bool(data['show_on_sub'])
    if 'assigned_reseller_ids' in data or 'reseller_ids' in data:
        import json as _j
        reseller_ids = data.get('assigned_reseller_ids', data.get('reseller_ids', []))
        package.assigned_reseller_ids = _j.dumps([int(r) for r in reseller_ids] if isinstance(reseller_ids, list) else [])
    package.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"success": True})

@app.route('/admin/packages/<int:package_id>', methods=['DELETE'])
@user_management_required
def delete_package(package_id):
    package = Package.query.get_or_404(package_id)
    db.session.delete(package)
    db.session.commit()
    return jsonify({"success": True})


# ── Reseller self-service packages ───────────────────────────────────────────
# Resellers manage their OWN packages and choose which packages (own + assigned
# + global) appear on their customers' subscription pages. Selling price floor
# is the SYSTEM base tariff; the per-use wallet cost stays the reseller's own.

def _reseller_sub_shown_ids(reseller) -> set:
    import json as _j
    try:
        return set(int(x) for x in _j.loads(reseller.sub_shown_package_ids or '[]'))
    except Exception:
        return set()


@app.route('/api/my-packages', methods=['GET'])
@login_required
def reseller_list_packages():
    import json as _j
    user = db.session.get(Admin, session['admin_id'])
    if not user or user.role != 'reseller':
        return jsonify({'success': False, 'error': 'Resellers only'}), 403

    shown = _reseller_sub_shown_ids(user)
    packages = Package.query.filter_by(enabled=True).order_by(Package.display_order, Package.id).all()
    items = []
    for p in packages:
        scope = p.scope or 'global'
        is_own = (p.created_by == user.id)
        if is_own:
            visible = True
        elif scope == 'global':
            visible = True
        elif scope == 'assigned':
            try:
                ids = _j.loads(p.assigned_reseller_ids or '[]')
            except Exception:
                ids = []
            visible = user.id in ids
        else:
            visible = False
        if not visible:
            continue
        items.append({
            'id': p.id,
            'name': p.name,
            'days': int(p.days or 0),
            'volume': int(p.volume or 0),
            'price': int(p.price if is_own else calculate_reseller_price(user, package=p) or 0),
            'is_own': is_own,
            'sub_shown': bool(p.show_on_sub) if is_own else (p.id in shown),
        })
    resp = make_response(jsonify({'success': True, 'items': items}))
    resp.headers['Cache-Control'] = 'no-store'
    return resp


@app.route('/api/my-packages', methods=['POST'])
@login_required
def reseller_create_package():
    user = db.session.get(Admin, session['admin_id'])
    if not user or user.role != 'reseller':
        return jsonify({'success': False, 'error': 'Resellers only'}), 403

    data = request.get_json(force=True) or {}
    name = (data.get('name') or '').strip()
    try:
        days = int(data.get('days') or 0)
        volume = int(data.get('volume') or 0)
        price = int(data.get('price') or 0)
    except Exception:
        return jsonify({'success': False, 'error': 'Invalid numbers'}), 400
    if not name or price <= 0:
        return jsonify({'success': False, 'error': 'Name and price are required'}), 400

    # Selling-price floor = SYSTEM base tariff (no reseller discount applied).
    floor, _cpg, _cpd, _tier = _calculate_minimum_price(volume, days, reseller_id=None, server_id=None, user=None)
    if days > 0 and volume > 0 and floor and price < floor:
        return jsonify({'success': False, 'error': f'Price must be at least {floor:,} (system base tariff).', 'min_price': floor}), 400

    pkg = Package(
        name=name, days=days, volume=volume, price=price,
        enabled=True, scope='personal', assigned_reseller_ids='[]',
        created_by=user.id, show_on_sub=bool(data.get('show_on_sub', False)),
        created_at=datetime.utcnow(),
    )
    db.session.add(pkg)
    db.session.commit()
    return jsonify({'success': True, 'id': pkg.id})


@app.route('/api/my-packages/<int:package_id>', methods=['PUT'])
@login_required
def reseller_update_package(package_id):
    user = db.session.get(Admin, session['admin_id'])
    if not user or user.role != 'reseller':
        return jsonify({'success': False, 'error': 'Resellers only'}), 403

    pkg = db.session.get(Package, package_id)
    if not pkg:
        return jsonify({'success': False, 'error': 'Not found'}), 404
    if pkg.created_by != user.id:
        return jsonify({'success': False, 'error': 'You can only edit your own packages'}), 403

    data = request.get_json(force=True) or {}
    name = (data.get('name') or pkg.name or '').strip()
    try:
        days = int(data.get('days', pkg.days) or 0)
        volume = int(data.get('volume', pkg.volume) or 0)
        price = int(data.get('price', pkg.price) or 0)
    except Exception:
        return jsonify({'success': False, 'error': 'Invalid numbers'}), 400
    if not name or price <= 0:
        return jsonify({'success': False, 'error': 'Name and price are required'}), 400

    floor, _cpg, _cpd, _tier = _calculate_minimum_price(volume, days, reseller_id=None, server_id=None, user=None)
    if days > 0 and volume > 0 and floor and price < floor:
        return jsonify({'success': False, 'error': f'Price must be at least {floor:,} (system base tariff).', 'min_price': floor}), 400

    pkg.name = name
    pkg.days = days
    pkg.volume = volume
    pkg.price = price
    if 'show_on_sub' in data:
        pkg.show_on_sub = bool(data['show_on_sub'])
    pkg.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/my-packages/<int:package_id>', methods=['DELETE'])
@login_required
def reseller_delete_package(package_id):
    user = db.session.get(Admin, session['admin_id'])
    if not user or user.role != 'reseller':
        return jsonify({'success': False, 'error': 'Resellers only'}), 403
    pkg = db.session.get(Package, package_id)
    if not pkg:
        return jsonify({'success': False, 'error': 'Not found'}), 404
    if pkg.created_by != user.id:
        return jsonify({'success': False, 'error': 'You can only delete your own packages'}), 403
    db.session.delete(pkg)
    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/my-packages/<int:package_id>/sub-toggle', methods=['POST'])
@login_required
def reseller_toggle_package_sub(package_id):
    import json as _j
    user = db.session.get(Admin, session['admin_id'])
    if not user or user.role != 'reseller':
        return jsonify({'success': False, 'error': 'Resellers only'}), 403

    pkg = db.session.get(Package, package_id)
    if not pkg or not pkg.enabled:
        return jsonify({'success': False, 'error': 'Not found'}), 404

    data = request.get_json(force=True) or {}
    desired = bool(data.get('show_on_sub'))

    if pkg.created_by == user.id:
        # Own package: flip its own flag.
        pkg.show_on_sub = desired
        db.session.commit()
        return jsonify({'success': True, 'sub_shown': pkg.show_on_sub})

    # Global / assigned package: confirm the reseller may see it, then update the
    # per-reseller shown list.
    scope = pkg.scope or 'global'
    if scope == 'assigned':
        try:
            ids = _j.loads(pkg.assigned_reseller_ids or '[]')
        except Exception:
            ids = []
        if user.id not in ids:
            return jsonify({'success': False, 'error': 'Not allowed'}), 403
    elif scope != 'global':
        return jsonify({'success': False, 'error': 'Not allowed'}), 403

    shown = _reseller_sub_shown_ids(user)
    if desired:
        shown.add(pkg.id)
    else:
        shown.discard(pkg.id)
    user.sub_shown_package_ids = _j.dumps(sorted(shown))
    db.session.commit()
    return jsonify({'success': True, 'sub_shown': desired})


@app.route('/my-packages')
@login_required
def reseller_packages_page():
    user = db.session.get(Admin, session['admin_id'])
    if not user or user.role != 'reseller':
        return redirect(url_for('dashboard'))
    return render_template('reseller_packages.html',
                           admin_username=session.get('admin_username'),
                           is_superadmin=False,
                           role='reseller')

@app.route('/admin/config', methods=['POST'])
@user_management_required
def update_config():
    data = request.json
    for key, value in data.items():
        config = db.session.get(SystemConfig, key)
        if config:
            config.value = str(value)
        else:
            db.session.add(SystemConfig(key=key, value=str(value)))
    db.session.commit()
    return jsonify({'success': True})


# ── Package scope / reseller endpoints ───────────────────────────────────────

@app.route('/admin/packages/<int:package_id>/assign', methods=['POST'])
@user_management_required
def assign_package_to_resellers(package_id):
    """Set which resellers can see this package (scope=assigned)."""
    import json as _j
    package = db.session.get(Package, package_id)
    if not package:
        return jsonify({'success': False, 'error': 'Package not found'}), 404
    data = request.json or {}
    scope = data.get('scope', 'global')
    reseller_ids = data.get('reseller_ids', [])
    package.scope = scope
    package.assigned_reseller_ids = _j.dumps([int(r) for r in reseller_ids])
    db.session.commit()
    return jsonify({'success': True})


# ── PriceTier CRUD ────────────────────────────────────────────────────────────

def _get_applicable_price_tier(volume_gb, days, reseller_id=None, server_id=None):
    """Return the best matching PriceTier or None (falls back to SystemConfig defaults)."""
    volume_gb = float(volume_gb or 0)
    days = int(days or 0)

    # Collect candidates: reseller-specific + global, ordered by priority desc, reseller first
    tiers = (PriceTier.query
             .filter_by(is_active=True)
             .order_by(PriceTier.priority.desc(), PriceTier.reseller_id.desc())
             .all())

    for tier in tiers:
        # Skip if this tier belongs to a different reseller
        if tier.reseller_id is not None and tier.reseller_id != reseller_id:
            continue
        # Skip if reseller context given but tier belongs to no-one AND a reseller-specific one exists
        # (handled naturally by sort order — reseller-specific come first)
        if tier.server_id is not None and tier.server_id != server_id:
            continue
        # Check conditions
        if tier.min_volume_gb is not None and volume_gb < tier.min_volume_gb:
            continue
        if tier.max_volume_gb is not None and volume_gb >= tier.max_volume_gb:
            continue
        if tier.min_days is not None and days < tier.min_days:
            continue
        if tier.max_days is not None and days >= tier.max_days:
            continue
        return tier
    return None


def _calculate_minimum_price(volume_gb, days, reseller_id=None, server_id=None):
    """Returns (min_price, effective_cost_per_gb, effective_cost_per_day)."""
    volume_gb = float(volume_gb or 0)
    days = int(days or 0)

    tier = _get_applicable_price_tier(volume_gb, days, reseller_id=reseller_id, server_id=server_id)

    if tier:
        cpg = tier.cost_per_gb
        cpd = tier.cost_per_day
    else:
        cpg = cpd = None

    if cpg is None:
        try:
            cpg = int((db.session.get(SystemConfig, 'cost_per_gb') or SystemConfig()).value or 0)
        except Exception:
            cpg = 0
    if cpd is None:
        try:
            cpd = int((db.session.get(SystemConfig, 'cost_per_day') or SystemConfig()).value or 0)
        except Exception:
            cpd = 0

    if days == 0:
        try:
            cpd_unlimited = int((db.session.get(SystemConfig, 'cost_per_day_unlimited') or SystemConfig()).value or 0)
        except Exception:
            cpd_unlimited = 0
        min_price = int(volume_gb * cpg + cpd_unlimited)
    else:
        min_price = int(volume_gb * cpg + days * cpd)
    return min_price, cpg, cpd


def _tier_assigned_reseller_ids(tier):
    ids = set()
    if getattr(tier, 'reseller_id', None) is not None:
        try:
            ids.add(int(tier.reseller_id))
        except Exception:
            pass
    try:
        raw_ids = json.loads(tier.assigned_reseller_ids or '[]')
    except Exception:
        raw_ids = []
    for rid in raw_ids if isinstance(raw_ids, list) else []:
        try:
            ids.add(int(rid))
        except Exception:
            continue
    return ids


def _get_applicable_price_tier(volume_gb, days, reseller_id=None, server_id=None):
    """Return the best matching active dynamic pricing tier."""
    volume_gb = float(volume_gb or 0)
    days = int(days or 0)
    try:
        reseller_id = int(reseller_id) if reseller_id not in (None, '', 0, '0') else None
    except Exception:
        reseller_id = None

    tiers = (PriceTier.query
             .filter_by(is_active=True)
             .order_by(PriceTier.priority.desc(), PriceTier.id.desc())
             .all())

    best_global = None
    for tier in tiers:
        assigned_ids = _tier_assigned_reseller_ids(tier)
        if assigned_ids:
            if reseller_id is None or reseller_id not in assigned_ids:
                continue
        elif best_global is not None:
            continue

        if tier.server_id is not None and tier.server_id != server_id:
            continue
        if tier.min_volume_gb is not None and volume_gb < tier.min_volume_gb:
            continue
        if tier.max_volume_gb is not None and volume_gb >= tier.max_volume_gb:
            continue
        if tier.min_days is not None and days < tier.min_days:
            continue
        if tier.max_days is not None and days >= tier.max_days:
            continue
        if assigned_ids:
            return tier
        best_global = tier
    return best_global


def _calculate_minimum_price(volume_gb, days, reseller_id=None, server_id=None, user=None):
    """Returns (price, cost_per_gb, cost_per_day, matched_tier)."""
    volume_gb = float(volume_gb or 0)
    days = int(days or 0)
    tier = _get_applicable_price_tier(volume_gb, days, reseller_id=reseller_id, server_id=server_id)

    if tier:
        cpg = int(tier.cost_per_gb or 0)
        cpd = int(tier.cost_per_day or 0)
    else:
        try:
            cpg = int((db.session.get(SystemConfig, 'cost_per_gb') or SystemConfig()).value or 0)
        except Exception:
            cpg = 0
        try:
            cpd = int((db.session.get(SystemConfig, 'cost_per_day') or SystemConfig()).value or 0)
        except Exception:
            cpd = 0
        if user is not None:
            cpg = calculate_reseller_price(user, base_price=cpg, cost_type='gb')
            cpd = calculate_reseller_price(user, base_price=cpd, cost_type='day')

    if days == 0:
        if tier:
            cpd_unlimited = 0
        else:
            try:
                cpd_unlimited = int((db.session.get(SystemConfig, 'cost_per_day_unlimited') or SystemConfig()).value or 0)
            except Exception:
                cpd_unlimited = 0
            if user is not None:
                cpd_unlimited = calculate_reseller_price(user, base_price=cpd_unlimited, cost_type='day')
        min_price = int(volume_gb * cpg + cpd_unlimited)
    else:
        min_price = int(volume_gb * cpg + days * cpd)
    return min_price, cpg, cpd, tier


@app.route('/api/packages/min-price')
@login_required
def package_min_price():
    """Calculate minimum cost for a given volume+days (for price warning in UI)."""
    user = db.session.get(Admin, session['admin_id'])
    if not user:
        return jsonify({'success': False}), 401

    try:
        volume_gb = float(request.args.get('volume_gb', 0) or 0)
        days = int(request.args.get('days', 0) or 0)
        server_id = request.args.get('server_id')
        server_id = int(server_id) if server_id else None
    except Exception:
        return jsonify({'success': False, 'error': 'Invalid params'}), 400

    # For superadmin, also accept explicit reseller_id; otherwise use caller's ID
    is_super = user.role == 'superadmin' or user.is_superadmin
    if is_super:
        try:
            reseller_id = int(request.args.get('reseller_id', 0) or 0) or None
        except Exception:
            reseller_id = None
    else:
        reseller_id = user.id

    min_price, cpg, cpd, tier = _calculate_minimum_price(
        volume_gb, days, reseller_id=reseller_id, server_id=server_id, user=user
    )
    return jsonify({
        'success': True,
        'min_price': min_price,
        'cost_per_gb': cpg,
        'cost_per_day': cpd,
        'tier_id': tier.id if tier else None,
        'tier_name': tier.name if tier else None,
    })


@app.route('/api/price-tiers', methods=['GET'])
@user_management_required
def list_price_tiers():
    reseller_id = request.args.get('reseller_id')
    q = PriceTier.query
    if reseller_id:
        try:
            rid = int(reseller_id)
            q = q.filter(
                db.or_(
                    PriceTier.reseller_id.is_(None),
                    PriceTier.reseller_id == rid,
                    PriceTier.assigned_reseller_ids.like(f'%{rid}%')
                )
            )
        except Exception:
            pass
    tiers = q.order_by(PriceTier.priority.desc(), PriceTier.id).all()
    return jsonify({'success': True, 'tiers': [t.to_dict() for t in tiers]})


@app.route('/api/price-tiers', methods=['POST'])
@user_management_required
def create_price_tier():
    data = request.json or {}
    admin_id = session.get('admin_id')
    try:
        assigned_ids = data.get('assigned_reseller_ids', data.get('reseller_ids', []))
        if data.get('reseller_id') and not assigned_ids:
            assigned_ids = [data.get('reseller_id')]
        if not isinstance(assigned_ids, list):
            assigned_ids = []
        assigned_ids = [int(r) for r in assigned_ids if str(r or '').strip()]
        tier = PriceTier(
            name=str(data.get('name', '')).strip() or 'Tier',
            min_volume_gb=float(data['min_volume_gb']) if data.get('min_volume_gb') not in (None, '') else None,
            max_volume_gb=float(data['max_volume_gb']) if data.get('max_volume_gb') not in (None, '') else None,
            min_days=int(data['min_days']) if data.get('min_days') not in (None, '') else None,
            max_days=int(data['max_days']) if data.get('max_days') not in (None, '') else None,
            cost_per_gb=int(data['cost_per_gb']) if data.get('cost_per_gb') not in (None, '') else None,
            cost_per_day=int(data['cost_per_day']) if data.get('cost_per_day') not in (None, '') else None,
            reseller_id=assigned_ids[0] if len(assigned_ids) == 1 else None,
            assigned_reseller_ids=json.dumps(assigned_ids),
            server_id=int(data['server_id']) if data.get('server_id') else None,
            priority=int(data.get('priority') or 0),
            is_active=bool(data.get('is_active', True)),
            created_by=admin_id,
        )
        db.session.add(tier)
        db.session.commit()
        return jsonify({'success': True, 'id': tier.id, 'tier': tier.to_dict()})
    except Exception as exc:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(exc)}), 400


@app.route('/api/price-tiers/<int:tier_id>', methods=['PUT'])
@user_management_required
def update_price_tier(tier_id):
    tier = db.session.get(PriceTier, tier_id)
    if not tier:
        return jsonify({'success': False, 'error': 'Not found'}), 404
    data = request.json or {}
    try:
        if 'name' in data:
            tier.name = str(data['name']).strip() or tier.name
        for _field in ('min_volume_gb', 'max_volume_gb'):
            if _field in data:
                setattr(tier, _field, float(data[_field]) if data[_field] not in (None, '') else None)
        for _field in ('min_days', 'max_days', 'cost_per_gb', 'cost_per_day', 'priority'):
            if _field in data:
                setattr(tier, _field, int(data[_field]) if data[_field] not in (None, '') else None)
        if 'reseller_id' in data:
            tier.reseller_id = int(data['reseller_id']) if data['reseller_id'] else None
        if 'assigned_reseller_ids' in data or 'reseller_ids' in data:
            assigned_ids = data.get('assigned_reseller_ids', data.get('reseller_ids', []))
            if not isinstance(assigned_ids, list):
                assigned_ids = []
            assigned_ids = [int(r) for r in assigned_ids if str(r or '').strip()]
            tier.assigned_reseller_ids = json.dumps(assigned_ids)
            tier.reseller_id = assigned_ids[0] if len(assigned_ids) == 1 else None
        if 'server_id' in data:
            tier.server_id = int(data['server_id']) if data['server_id'] else None
        if 'is_active' in data:
            tier.is_active = bool(data['is_active'])
        db.session.commit()
        return jsonify({'success': True, 'tier': tier.to_dict()})
    except Exception as exc:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(exc)}), 400


@app.route('/api/price-tiers/<int:tier_id>', methods=['DELETE'])
@user_management_required
def delete_price_tier(tier_id):
    tier = db.session.get(PriceTier, tier_id)
    if not tier:
        return jsonify({'success': False, 'error': 'Not found'}), 404
    db.session.delete(tier)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/admin/charge', methods=['POST'])
@user_management_required
def charge_admin():
    data = request.json
    admin_id = int(data.get('admin_id'))
    amount = int(data.get('amount'))
    description = data.get('description', 'Manual charge')
    
    admin = Admin.query.get_or_404(admin_id)
    admin.credit += amount
    
    transaction_type = 'deposit' if amount >= 0 else 'manual_debit'
    # Set category to 'income' for deposits (positive) so it counts in stats, 'expense' for debits (negative)
    category = 'income' if amount >= 0 else 'expense'

    transaction = Transaction(
        admin_id=admin_id,
        amount=amount,
        type=transaction_type,
        description=description,
        category=category
    )
    db.session.add(transaction)
    db.session.commit()
    return jsonify({"success": True, "new_credit": admin.credit})

@app.route('/api/transactions', methods=['GET'])
@login_required
def get_transactions():
    try:
        user = db.session.get(Admin, session['admin_id'])
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 401

        query = Transaction.query.join(Admin)

        type_filter = (request.args.get('type') or '').strip()
        direction_filter = (request.args.get('direction') or '').strip()

        if user.role == 'reseller':
            query = query.filter(Transaction.admin_id == user.id)
        else:
            target_user_id = request.args.get('user_id', type=int)
            if target_user_id:
                query = query.filter(Transaction.admin_id == target_user_id)

        # Filter by Server (using new column)
        server_filter = request.args.get('server_id', type=int)
        if server_filter:
            accessible_ids = {s.id for s in get_accessible_servers(user, include_disabled=True)}
            if user.role == 'reseller' and server_filter not in accessible_ids:
                return jsonify({"success": False, "error": "Access denied to requested server"}), 403
            query = query.filter(Transaction.server_id == server_filter)

        search_term = (request.args.get('search') or '').strip()
        if search_term:
            pattern = f"%{search_term}%"
            query = query.filter(or_(
                Transaction.client_email.ilike(pattern),
                Transaction.description.ilike(pattern),
                Transaction.type.ilike(pattern),
                Admin.username.ilike(pattern)
            ))

        if direction_filter == 'income':
            query = query.filter(Transaction.amount > 0)
        elif direction_filter == 'expense':
            query = query.filter(Transaction.amount < 0)

        if type_filter:
            query = query.filter(Transaction.type == type_filter)

        start_dt = parse_jalali_date(request.args.get('start_date'), end_of_day=False)
        if start_dt:
            query = query.filter(Transaction.created_at >= start_dt)

        end_dt = parse_jalali_date(request.args.get('end_date'), end_of_day=True)
        if end_dt:
            query = query.filter(Transaction.created_at <= end_dt)

        # ...existing code...
        # (rest of the function remains unchanged)
        # ...existing code...
    except Exception as ex:
        import traceback
        return jsonify({"success": False, "error": str(ex), "trace": traceback.format_exc()}), 500

    # Pagination
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('limit', 20, type=int)
    per_page = max(1, min(per_page, 100))

    pagination = query.order_by(Transaction.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    transactions = pagination.items

    # Fallback logic for old transactions (missing server_id)
    transaction_emails = {}
    email_pairs = set()
    for tx in transactions:
        if not tx.server_id:
            email = extract_email_from_description(tx.description)
            if email:
                transaction_emails[tx.id] = email
                email_pairs.add((tx.admin_id, email))

    ownership_map = {}
    if email_pairs:
        reseller_ids = {pair[0] for pair in email_pairs}
        email_values = {pair[1] for pair in email_pairs}
        if reseller_ids and email_values:
            ownerships = ClientOwnership.query.filter(
                ClientOwnership.reseller_id.in_(list(reseller_ids)),
                func.lower(ClientOwnership.client_email).in_(list(email_values))
            ).all()
            for ownership in ownerships:
                key = (ownership.reseller_id, (ownership.client_email or '').lower())
                existing = ownership_map.get(key)
                current_created = ownership.created_at or datetime.min
                existing_created = existing.created_at if existing and existing.created_at else datetime.min
                if not existing or current_created >= existing_created:
                    ownership_map[key] = ownership

    payload = []
    for tx in transactions:
        tx_data = tx.to_dict()
        
        # If server_id was missing, try to fill it from ownership map
        if not tx_data.get('server'):
            email = transaction_emails.get(tx.id)
            if email:
                tx_data['client_email'] = email
                ownership = ownership_map.get((tx.admin_id, email))
                if ownership and ownership.server:
                    tx_data['server_id'] = ownership.server.id
                    tx_data['server'] = {
                        'id': ownership.server.id,
                        'name': ownership.server.name
                    }

        payload.append(tx_data)

    return jsonify({
        'transactions': payload,
        'total': pagination.total,
        'pages': pagination.pages,
        'current_page': page,
        'per_page': per_page
    })


def _truncate_text(value: str, max_len: int) -> str:
    if value is None:
        return ''
    s = str(value)
    if len(s) <= max_len:
        return s
    return s[: max(0, max_len - 1)] + '…'


def _build_tx_edit_audit(editor_username: str, at_jalali: str, old_amount: int, old_type: str, old_category: str, old_desc: str, new_amount: int, new_type: str, new_category: str, new_desc: str) -> str:
    # Keep it compact (Transaction.description is VARCHAR(255))
    editor = editor_username or 'unknown'
    when = at_jalali or ''
    base = f"Edited by {editor} at {when}: {old_amount}->{new_amount}, {old_type}->{new_type}, {old_category}->{new_category}. "
    # Allocate remaining space for desc fragments
    remaining = 255 - len(base) - len("Was:  | Now: ")
    if remaining < 0:
        return _truncate_text(base, 255)
    half = max(0, remaining // 2)
    was_part = _truncate_text(old_desc or '', half)
    now_part = _truncate_text(new_desc or '', remaining - len(was_part))
    final = f"{base}Was: {was_part} | Now: {now_part}".strip()
    return _truncate_text(final, 255)


def _build_tx_delete_audit(deleter_username: str, at_jalali: str, deleted_tx_id: int, deleted_admin_username: str, deleted_amount: int, deleted_type: str) -> str:
    deleter = deleter_username or 'unknown'
    when = at_jalali or ''
    admin_u = deleted_admin_username or 'unknown'
    base = f"Deleted by {deleter} at {when}: tx#{deleted_tx_id} ({admin_u}) {deleted_amount} {deleted_type}."
    return _truncate_text(base, 255)


@app.route('/api/transactions/<int:tx_id>', methods=['PUT'])
@user_management_required
def update_transaction(tx_id):
    editor = db.session.get(Admin, session.get('admin_id'))
    tx = Transaction.query.get_or_404(tx_id)

    try:
        data = request.get_json() or {}
    except Exception:
        return jsonify({"success": False, "error": "Invalid JSON"}), 400

    # Snapshot for audit
    old_amount = tx.amount
    old_type = tx.type or ''
    old_category = tx.category or ''
    old_desc = tx.description or ''

    # Determine direction
    is_expense = None
    if 'is_expense' in data:
        is_expense = bool(data.get('is_expense'))

    # Amount (UI sends positive digits; we apply sign based on direction)
    parsed_amount = None
    if 'amount' in data:
        parsed_amount = parse_amount_to_int(data.get('amount'))
        if parsed_amount is None or int(parsed_amount) <= 0:
            return jsonify({"success": False, "error": "Invalid amount"}), 400

    if is_expense is None:
        # infer from existing
        is_expense = (tx.amount or 0) < 0 or (tx.category == 'expense')

    if parsed_amount is not None:
        tx.amount = -abs(int(parsed_amount)) if is_expense else abs(int(parsed_amount))

    # Category
    tx.category = 'expense' if is_expense else 'income'

    # Type
    new_type = (data.get('cost_type') or data.get('type') or tx.type or '').strip() or None
    if new_type is not None:
        tx.type = new_type

    # Common fields
    if 'server_id' in data:
        tx.server_id = data.get('server_id') or None
    if 'card_id' in data:
        tx.card_id = data.get('card_id') or None
    if 'sender_card' in data:
        tx.sender_card = (data.get('sender_card') or '').strip() or None
    if 'sender_name' in data:
        tx.sender_name = (data.get('sender_name') or '').strip() or None
    if 'client_email' in data:
        tx.client_email = (data.get('client_email') or '').strip() or None

    # Date/time (Jalali + Tehran)
    if 'payment_date' in data or 'payment_time' in data:
        date_part = (data.get('payment_date') or '').strip() or None
        time_part = (data.get('payment_time') or '').strip() or None
        combined = None
        if date_part and time_part:
            combined = f"{date_part} {time_part}"
        elif date_part:
            combined = date_part
        if combined:
            dt = parse_jalali_date(combined, end_of_day=False)
            if dt:
                tx.created_at = dt

    # Description update + audit
    new_desc = old_desc
    if 'description' in data:
        new_desc = (data.get('description') or '').strip()

    audit_desc = _build_tx_edit_audit(
        editor.username if editor else 'unknown',
        format_jalali(datetime.utcnow()) or '',
        old_amount,
        old_type,
        old_category,
        old_desc,
        tx.amount,
        (tx.type or ''),
        (tx.category or ''),
        new_desc,
    )
    tx.description = audit_desc

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({"success": False, "error": "Failed to update transaction"}), 500

    return jsonify({"success": True, "transaction": tx.to_dict()})


@app.route('/api/transactions/<int:tx_id>', methods=['DELETE'])
@user_management_required
def delete_transaction(tx_id):
    deleter = db.session.get(Admin, session.get('admin_id'))
    tx = Transaction.query.get_or_404(tx_id)

    # Create an audit log entry that remains visible in /transactions
    try:
        deleted_admin_username = None
        if hasattr(tx, 'admin') and tx.admin:
            deleted_admin_username = tx.admin.username
        else:
            admin_obj = db.session.get(Admin, tx.admin_id)
            deleted_admin_username = admin_obj.username if admin_obj else None

        audit_desc = _build_tx_delete_audit(
            deleter.username if deleter else 'unknown',
            format_jalali(datetime.utcnow()) or '',
            tx.id,
            deleted_admin_username,
            int(tx.amount or 0),
            (tx.type or ''),
        )

        audit_tx = Transaction(
            admin_id=deleter.id if deleter else tx.admin_id,
            amount=0,
            type='audit',
            category='usage',
            description=audit_desc,
            created_at=datetime.utcnow(),
        )
        db.session.add(audit_tx)
    except Exception:
        # If audit creation fails, continue with delete (avoid blocking admin cleanup)
        pass

    db.session.delete(tx)
    db.session.commit()
    return jsonify({"success": True})


# ==================== FINANCE OVERVIEW ====================

@app.route('/finance')
@login_required
def finance_page():
    user = db.session.get(Admin, session['admin_id'])
    cards = BankCard.query.filter_by(is_active=True).all()
    servers = Server.query.order_by(Server.name).all()
    
    # Always show user column, but for reseller only their own username
    admin_options = []
    is_superadmin_view = (user.role == 'superadmin')
    if is_superadmin_view:
        admin_options = Admin.query.order_by(Admin.username).all()
    else:
        admin_options = [user]
    return render_template('finance.html', 
                           cards=cards, 
                           is_superadmin=(user.role == 'superadmin' or user.is_superadmin),
                           admin_username=user.username,
                           role=user.role,
                           wallet_credit=user.credit,
                           admin_options=admin_options,
                           servers=servers)


@app.route('/api/payments', methods=['GET'])
@login_required
def get_payments():
    """Get payment transactions (transactions that have card info)"""
    try:
        user = db.session.get(Admin, session['admin_id'])
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 401
        
        type_filter = (request.args.get('type') or '').strip()
        direction_filter = (request.args.get('direction') or '').strip()

        # Payments
        payment_query = Payment.query
        if user.role == 'reseller':
            payment_query = payment_query.filter(Payment.admin_id == user.id)
        else:
            target_user_id = request.args.get('user_id', type=int)
            if target_user_id:
                payment_query = payment_query.filter(Payment.admin_id == target_user_id)
        card_id = request.args.get('card_id', type=int)
        if card_id:
            payment_query = payment_query.filter(Payment.card_id == card_id)
        search_term = (request.args.get('search') or '').strip()
        if search_term:
            pattern = f"%{search_term}%"
            payment_query = payment_query.filter(or_(
                Payment.description.ilike(pattern),
                Payment.sender_card.ilike(pattern),
                Payment.sender_name.ilike(pattern),
                Payment.client_email.ilike(pattern)
            ))
        start_dt = parse_jalali_date(request.args.get('start_date'), end_of_day=False)
        if start_dt:
            payment_query = payment_query.filter(Payment.payment_date >= start_dt)
        end_dt = parse_jalali_date(request.args.get('end_date'), end_of_day=True)
        if end_dt:
            payment_query = payment_query.filter(Payment.payment_date <= end_dt)
        include_payments = (direction_filter != 'expense' and (not type_filter or type_filter == 'payment'))

        # ...existing code...
        # (rest of the function remains unchanged)
        # ...existing code...
    except Exception as ex:
        import traceback
        return jsonify({"success": False, "error": str(ex), "trace": traceback.format_exc()}), 500
    tx_query = Transaction.query
    if user.role == 'reseller':
        tx_query = tx_query.filter(Transaction.admin_id == user.id)
    else:
        target_user_id = request.args.get('user_id', type=int)
        if target_user_id:
            tx_query = tx_query.filter(Transaction.admin_id == target_user_id)
    if card_id:
        tx_query = tx_query.filter(Transaction.card_id == card_id)
    server_id = request.args.get('server_id', type=int)
    if server_id:
        tx_query = tx_query.filter(Transaction.server_id == server_id)
    if search_term:
        pattern = f"%{search_term}%"
        tx_query = tx_query.filter(or_(
            Transaction.description.ilike(pattern),
            Transaction.sender_card.ilike(pattern),
            Transaction.sender_name.ilike(pattern),
            Transaction.client_email.ilike(pattern),
            Transaction.type.ilike(pattern)
        ))

    # Exclude system/audit rows from Finance overview list
    tx_query = tx_query.filter(Transaction.type != 'audit')

    if direction_filter == 'income':
        tx_query = tx_query.filter(Transaction.amount > 0)
    elif direction_filter == 'expense':
        tx_query = tx_query.filter(Transaction.amount < 0)

    if type_filter and type_filter not in ('payment', 'receipt'):
        tx_query = tx_query.filter(Transaction.type == type_filter)
    elif type_filter in ('payment', 'receipt'):
        tx_query = tx_query.filter(text('1=0'))
    if start_dt:
        tx_query = tx_query.filter(Transaction.created_at >= start_dt)
    if end_dt:
        tx_query = tx_query.filter(Transaction.created_at <= end_dt)
    include_transactions = True

    # ManualReceipts
    receipt_query = ManualReceipt.query
    if user.role == 'reseller':
        receipt_query = receipt_query.filter(ManualReceipt.admin_id == user.id)
    else:
        target_user_id = request.args.get('user_id', type=int)
        if target_user_id:
            receipt_query = receipt_query.filter(ManualReceipt.admin_id == target_user_id)
    if card_id:
        receipt_query = receipt_query.filter(ManualReceipt.card_id == card_id)
    if search_term:
        pattern = f"%{search_term}%"
        receipt_query = receipt_query.filter(or_(
            ManualReceipt.reference_code.ilike(pattern),
            ManualReceipt.notes.ilike(pattern)
        ))
    if start_dt:
        receipt_query = receipt_query.filter(ManualReceipt.deposit_at >= start_dt)
    if end_dt:
        receipt_query = receipt_query.filter(ManualReceipt.deposit_at <= end_dt)
    include_receipts = (direction_filter != 'expense' and (not type_filter or type_filter == 'receipt'))

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('limit', 20, type=int)
    page = max(1, int(page or 1))
    per_page = max(1, min(int(per_page or 20), 100))

    payment_count = payment_query.order_by(None).count() if include_payments else 0
    tx_count = tx_query.order_by(None).count() if include_transactions else 0
    receipt_count = receipt_query.order_by(None).count() if include_receipts else 0

    total = int(payment_count) + int(tx_count) + int(receipt_count)
    pages = (total + per_page - 1) // per_page if total > 0 else 1

    start = (page - 1) * per_page
    end = start + per_page
    fetch_limit = max(end, per_page)

    payments_list = []
    if include_payments and payment_count > 0:
        payments_list = payment_query.options(
            joinedload(Payment.admin),
            joinedload(Payment.card),
        ).order_by(Payment.payment_date.desc()).limit(fetch_limit).all()

    transactions_list = []
    if include_transactions and tx_count > 0:
        transactions_list = tx_query.options(
            joinedload(Transaction.admin),
            joinedload(Transaction.card),
            joinedload(Transaction.server),
        ).order_by(Transaction.created_at.desc()).limit(fetch_limit).all()

    receipts_list = []
    if include_receipts and receipt_count > 0:
        receipts_list = receipt_query.options(
            joinedload(ManualReceipt.admin),
            joinedload(ManualReceipt.card),
        ).order_by(ManualReceipt.deposit_at.desc()).limit(fetch_limit).all()

    # Map payments
    mapped_payments = []
    for p in payments_list:
        d = p.to_dict()
        d['type'] = 'payment'
        mapped_payments.append(d)

    # Map transactions
    mapped_transactions = []
    for t in transactions_list:
        admin = getattr(t, 'admin', None)
        card = getattr(t, 'card', None)
        server = getattr(t, 'server', None)
        jalali_date = format_jalali(t.created_at) or ''
        mapped_transactions.append({
            'id': f"tx-{t.id}",
            'admin_id': t.admin_id,
            'admin': {
                'id': admin.id,
                'username': admin.username,
                'role': admin.role
            } if admin else None,
            'sender_card': t.sender_card or '',
            'sender_name': getattr(t, 'sender_name', None) or None,
            'card_id': t.card_id,
            'card': {
                'id': card.id,
                'label': card.label,
                'bank_name': card.bank_name
            } if card else None,
            'server': {
                'id': server.id,
                'name': server.name
            } if server else None,
            'amount': int(t.amount),
            'type': t.type or 'transaction',
            'description': t.description,
            'client_email': t.client_email or (t.description.split(' - ')[-1] if t.description and ' - ' in t.description else ''),
            'payment_date': t.created_at.isoformat() if t.created_at else None,
            'payment_date_jalali': jalali_date,
            'verified': True,
            'created_at': t.created_at.isoformat() if t.created_at else None,
        })

    # Map receipts
    mapped_receipts = []
    for r in receipts_list:
        d = r.to_dict()
        d['type'] = 'receipt'
        d['payment_date'] = d.get('deposit_at') or d.get('created_at')
        d['payment_date_jalali'] = ''
        if d['payment_date']:
            try:
                dt = datetime.fromisoformat(d['payment_date'])
                d['payment_date_jalali'] = format_jalali(dt)
            except:
                pass
        mapped_receipts.append(d)

    # Combine all
    combined = mapped_payments + mapped_transactions + mapped_receipts
    def get_date(item):
        date_str = item.get('payment_date') or item.get('created_at')
        if not date_str:
            return datetime.min
        try:
            return datetime.fromisoformat(date_str)
        except:
            try:
                return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            except:
                return datetime.min
    combined.sort(key=lambda x: get_date(x), reverse=True)
    page_items = combined[start:end]
    return jsonify({
        'payments': page_items,
        'total': total,
        'pages': pages,
        'current_page': page,
        'per_page': per_page
    })


@app.route('/api/payments', methods=['POST'])
@login_required
def add_payment():
    user = db.session.get(Admin, session['admin_id'])
    if not user:
        return jsonify({"success": False, "error": "User not found"}), 401
    
    try:
        data = request.get_json() or {}
    except Exception as ex:
        logger.exception('Invalid JSON in add_payment')
        return jsonify({"success": False, "error": "Invalid JSON"}), 400

    # Log incoming request for debugging
    try:
        logger.info('add_payment request by user %s: %s', user.id, json.dumps(data, ensure_ascii=False))
    except Exception:
        logger.info('add_payment request: (unserializable data)')
    
    amount_val = parse_amount_to_int(data.get('amount'))
    if not amount_val or int(amount_val) <= 0:
        return jsonify({"success": False, "error": "Amount is required and must be positive"}), 400
    
    payment_date_str = (data.get('payment_date') or '').strip() or None
    payment_time_str = (data.get('payment_time') or '').strip() or None
    combined_dt_str = None
    if payment_date_str and payment_time_str:
        combined_dt_str = f"{payment_date_str} {payment_time_str}"
    elif payment_date_str:
        combined_dt_str = payment_date_str

    # parse_jalali_date converts Tehran -> UTC; ensure we pass date+time together to avoid double shifting
    payment_date = parse_jalali_date(combined_dt_str, end_of_day=False)
    if not payment_date:
        payment_date = datetime.utcnow()
    
    # Expense flow: create a Transaction with category='expense' (amount negative)
    is_expense = bool(data.get('is_expense'))
    if is_expense:
        cost_type = (data.get('cost_type') or 'server_cost').strip()
        server_id = data.get('server_id') or None
        amount_val = -abs(int(amount_val))

        tx = Transaction(
            admin_id=user.id,
            server_id=server_id,
            card_id=data.get('card_id') or None,
            sender_card=(data.get('sender_card') or '').strip() or None,
            sender_name=(data.get('sender_name') or '').strip() or None,
            client_email=(data.get('client_email') or '').strip() or None,
            amount=amount_val,
            type=cost_type,
            description=data.get('description', '').strip() or None,
            category='expense',
            created_at=payment_date
        )
        db.session.add(tx)
        try:
            db.session.commit()
            logger.info('Expense saved as transaction id=%s admin=%s amount=%s server=%s type=%s', tx.id, tx.admin_id, tx.amount, server_id, cost_type)
        except Exception:
            logger.exception('Failed to commit expense transaction')
            db.session.rollback()
            return jsonify({"success": False, "error": "Failed to save expense"}), 500
        return jsonify({"success": True, "id": tx.id, "mode": "expense"})

    # Income (payment) flow
    is_super = (user.role == 'superadmin' or user.is_superadmin)
    payment = Payment(
        admin_id=user.id,
        card_id=data.get('card_id') or None,
        sender_card=data.get('sender_card', '').strip() or None,
        sender_name=data.get('sender_name', '').strip() or None,
        amount=int(amount_val),
        payment_date=payment_date,
        client_email=data.get('client_email', '').strip() or None,
        description=data.get('description', '').strip() or None,
        verified=True if is_super else False
    )
    
    db.session.add(payment)
    try:
        db.session.commit()
        logger.info('Payment saved id=%s admin=%s amount=%s', payment.id, payment.admin_id, payment.amount)
    except Exception as e:
        logger.exception('Failed to commit payment')
        db.session.rollback()
        return jsonify({"success": False, "error": "Failed to save payment"}), 500
    
    return jsonify({"success": True, "payment": payment.to_dict()})


@app.route('/api/payments/<int:payment_id>', methods=['PUT'])
@login_required
def update_payment(payment_id):
    user = db.session.get(Admin, session['admin_id'])
    if not user:
        return jsonify({"success": False, "error": "User not found"}), 401
    
    payment = Payment.query.get_or_404(payment_id)
    
    is_super = (user.role == 'superadmin' or user.is_superadmin)
    # Only owner or superadmin can edit
    if payment.admin_id != user.id and not is_super:
        return jsonify({"success": False, "error": "Access denied"}), 403
    
    try:
        data = request.get_json() or {}
    except:
        return jsonify({"success": False, "error": "Invalid JSON"}), 400

    # Convert payment -> expense transaction (when editing and user switches kind)
    if bool(data.get('is_expense')):
        parsed_amount = parse_amount_to_int(data.get('amount')) if 'amount' in data else payment.amount
        if parsed_amount is None or int(parsed_amount) <= 0:
            return jsonify({"success": False, "error": "Invalid amount"}), 400

        server_id = data.get('server_id') or None
        if not server_id:
            return jsonify({"success": False, "error": "Server is required for expense"}), 400

        # Resolve date/time (Jalali + Tehran)
        resolved_dt = payment.payment_date
        if 'payment_date' in data or 'payment_time' in data:
            date_part = (data.get('payment_date') or '').strip() or None
            time_part = (data.get('payment_time') or '').strip() or None

            if not date_part and time_part and payment.payment_date:
                # derive current Jalali date part from existing UTC datetime
                try:
                    current_tehran = payment.payment_date + timedelta(hours=3, minutes=30)
                    j_current = jdatetime_class.fromgregorian(datetime=current_tehran)
                    date_part = j_current.strftime('%Y/%m/%d')
                except Exception:
                    date_part = None

            combined_dt_str = None
            if date_part and time_part:
                combined_dt_str = f"{date_part} {time_part}"
            elif date_part:
                combined_dt_str = date_part

            new_date = parse_jalali_date(combined_dt_str, end_of_day=False)
            if new_date:
                resolved_dt = new_date

        # Carry forward fields (prefer explicit updates)
        card_id = data.get('card_id') if 'card_id' in data else payment.card_id
        sender_card = (data.get('sender_card') if 'sender_card' in data else payment.sender_card) or None
        sender_name = (data.get('sender_name') if 'sender_name' in data else payment.sender_name) or None
        client_email = (data.get('client_email') if 'client_email' in data else payment.client_email) or None
        base_desc = (data.get('description') if 'description' in data else payment.description) or ''

        sender_card = (sender_card or '').strip() or None
        sender_name = (sender_name or '').strip() or None
        client_email = (client_email or '').strip() or None
        base_desc = (base_desc or '').strip()

        cost_type = (data.get('cost_type') or 'server_cost').strip() or 'server_cost'

        audit_note = _truncate_text(
            f"Converted from payment#{payment.id} by {(user.username if user else 'unknown')} at {format_jalali(datetime.utcnow()) or ''}.",
            255,
        )
        merged_desc = (f"{base_desc} {audit_note}".strip())
        merged_desc = _truncate_text(merged_desc, 255) or None

        tx = Transaction(
            admin_id=payment.admin_id,
            server_id=server_id,
            card_id=card_id or None,
            sender_card=sender_card,
            sender_name=sender_name,
            client_email=client_email,
            amount=-abs(int(parsed_amount)),
            type=cost_type,
            description=merged_desc,
            category='expense',
            created_at=resolved_dt or datetime.utcnow(),
        )

        db.session.add(tx)
        db.session.delete(payment)
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            return jsonify({"success": False, "error": "Failed to convert payment to expense"}), 500

        return jsonify({
            "success": True,
            "converted": True,
            "mode": "expense",
            "transaction_id": tx.id,
            "entry_id": f"tx-{tx.id}",
        })
    
    if 'amount' in data:
        parsed = parse_amount_to_int(data.get('amount'))
        if parsed is None or int(parsed) <= 0:
            return jsonify({"success": False, "error": "Invalid amount"}), 400
        payment.amount = int(parsed)
    if 'card_id' in data:
        payment.card_id = data['card_id'] or None
    if 'sender_card' in data:
        payment.sender_card = data['sender_card'].strip() or None
    if 'sender_name' in data:
        payment.sender_name = data['sender_name'].strip() or None
    if 'client_email' in data:
        payment.client_email = data['client_email'].strip() or None
    if 'description' in data:
        payment.description = data['description'].strip() or None
    if 'verified' in data and is_super:
        payment.verified = bool(data['verified'])
    if 'payment_date' in data or 'payment_time' in data:
        date_part = (data.get('payment_date') or '').strip() or None
        time_part = (data.get('payment_time') or '').strip() or None

        if not date_part and time_part and payment.payment_date:
            # derive current Jalali date part from existing UTC datetime
            try:
                current_tehran = payment.payment_date + timedelta(hours=3, minutes=30)
                j_current = jdatetime_class.fromgregorian(datetime=current_tehran)
                date_part = j_current.strftime('%Y/%m/%d')
            except Exception:
                date_part = None

        combined_dt_str = None
        if date_part and time_part:
            combined_dt_str = f"{date_part} {time_part}"
        elif date_part:
            combined_dt_str = date_part

        new_date = parse_jalali_date(combined_dt_str, end_of_day=False)
        if new_date:
            payment.payment_date = new_date
    
    db.session.commit()
    return jsonify({"success": True, "payment": payment.to_dict()})


@app.route('/api/payments/<int:payment_id>', methods=['DELETE'])
@login_required
def delete_payment(payment_id):
    user = db.session.get(Admin, session['admin_id'])
    if not user:
        return jsonify({"success": False, "error": "User not found"}), 401
    
    payment = Payment.query.get_or_404(payment_id)
    
    is_super = (user.role == 'superadmin' or user.is_superadmin)
    # Only owner or superadmin can delete
    if payment.admin_id != user.id and not is_super:
        return jsonify({"success": False, "error": "Access denied"}), 403
    
    db.session.delete(payment)
    db.session.commit()
    return jsonify({"success": True})


@app.route('/api/finance/stats', methods=['GET'])
@login_required
def get_finance_stats():
    """Get income statistics from transactions: today, this week, this month"""
    user = db.session.get(Admin, session['admin_id'])
    if not user:
        return jsonify({"success": False, "error": "User not found"}), 401
    
    # Calculate dates based on Tehran time and Jalali calendar
    now_utc = datetime.utcnow()
    tehran_offset = timedelta(hours=3, minutes=30)
    now_tehran = now_utc + tehran_offset
    
    j_now = jdatetime_class.fromgregorian(datetime=now_tehran)
    
    # Start of Jalali month
    j_month_start = j_now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    g_month_start_tehran = j_month_start.togregorian()
    month_start = g_month_start_tehran - tehran_offset

    # Start of previous Jalali month
    try:
        prev_year = int(j_month_start.year)
        prev_month = int(j_month_start.month) - 1
        if prev_month <= 0:
            prev_month = 12
            prev_year -= 1
        j_prev_month_start = jdatetime_class(prev_year, prev_month, 1, 0, 0, 0, 0)
        g_prev_month_start_tehran = j_prev_month_start.togregorian()
        prev_month_start = g_prev_month_start_tehran - tehran_offset
        prev_month_end = month_start
    except Exception:
        prev_month_start = None
        prev_month_end = None
    
    # Start of Today (Jalali/Tehran)
    j_today_start = j_now.replace(hour=0, minute=0, second=0, microsecond=0)
    g_today_start_tehran = j_today_start.togregorian()
    today_start = g_today_start_tehran - tehran_offset

    # Period-to-date windows for "compare to same period last month"
    now_period_end = now_utc
    try:
        cur_period_len = now_period_end - month_start
    except Exception:
        cur_period_len = None

    prev_period_end = None
    if prev_month_start and cur_period_len is not None:
        try:
            prev_period_end = prev_month_start + cur_period_len
            if prev_month_end and prev_period_end > prev_month_end:
                prev_period_end = prev_month_end
        except Exception:
            prev_period_end = prev_month_end

    # "Today" comparison: same day-of-month in previous Jalali month, same time-of-day window
    prev_same_day_start = None
    prev_same_day_end = None
    if prev_month_start:
        try:
            day_of_month = int(getattr(j_now, 'day', 0) or 0)
        except Exception:
            day_of_month = 0

        if day_of_month > 0:
            try:
                prev_year = int(j_month_start.year)
                prev_month = int(j_month_start.month) - 1
                if prev_month <= 0:
                    prev_month = 12
                    prev_year -= 1

                # Handle months that don't have this day (e.g., day 31)
                safe_day = day_of_month
                j_prev_same_day = None
                while safe_day >= 1 and j_prev_same_day is None:
                    try:
                        j_prev_same_day = jdatetime_class(prev_year, prev_month, safe_day, 0, 0, 0, 0)
                    except Exception:
                        safe_day -= 1

                if j_prev_same_day is not None:
                    g_prev_same_day_tehran = j_prev_same_day.togregorian()
                    prev_same_day_start = g_prev_same_day_tehran - tehran_offset

                    # Match window length to "today so far" but clamp to that day's end
                    try:
                        today_so_far = now_period_end - today_start
                    except Exception:
                        today_so_far = timedelta(0)
                    day_end = prev_same_day_start + timedelta(days=1)
                    prev_same_day_end = prev_same_day_start + today_so_far
                    if prev_same_day_end > day_end:
                        prev_same_day_end = day_end
            except Exception:
                prev_same_day_start = None
                prev_same_day_end = None

    card_id = request.args.get('card_id', type=int)
    server_id = request.args.get('server_id', type=int)
    target_user_id = request.args.get('user_id', type=int)

    excluded_types_upper = {'SERVER_COST', 'SERVER_RENEWAL', 'SERVER_TRAFFIC'}

    if user.role == 'reseller':
        # Charge: مجموع تراکنش‌های مثبت (واریزها)
        charge_query = Transaction.query.filter(
            Transaction.admin_id == user.id,
            Transaction.amount > 0,
            or_(Transaction.type.is_(None), func.upper(Transaction.type).notin_(excluded_types_upper))
        )
        usage_query = Transaction.query.filter(Transaction.admin_id == user.id, Transaction.amount < 0)
        if card_id:
            charge_query = charge_query.filter(Transaction.card_id == card_id)
            usage_query = usage_query.filter(Transaction.card_id == card_id)
        if server_id:
            charge_query = charge_query.filter(Transaction.server_id == server_id)
            usage_query = usage_query.filter(Transaction.server_id == server_id)

        def sum_amount(q, start_time=None):
            if start_time:
                q = q.filter(Transaction.created_at >= start_time)
            return db.session.query(func.coalesce(func.sum(Transaction.amount), 0)).filter(Transaction.id.in_(q.with_entities(Transaction.id))).scalar() or 0

        today_charge = sum_amount(charge_query, today_start)
        month_charge = sum_amount(charge_query, month_start)
        total_charge = sum_amount(charge_query)

        prev_month_charge = 0
        if prev_month_start and prev_period_end:
            q_prev = charge_query.filter(Transaction.created_at >= prev_month_start, Transaction.created_at < prev_period_end)
            prev_month_charge = db.session.query(func.coalesce(func.sum(Transaction.amount), 0)).filter(Transaction.id.in_(q_prev.with_entities(Transaction.id))).scalar() or 0

        prev_same_day_charge = 0
        if prev_same_day_start and prev_same_day_end:
            q_prev_day = charge_query.filter(Transaction.created_at >= prev_same_day_start, Transaction.created_at < prev_same_day_end)
            prev_same_day_charge = db.session.query(func.coalesce(func.sum(Transaction.amount), 0)).filter(Transaction.id.in_(q_prev_day.with_entities(Transaction.id))).scalar() or 0

        month_usage = abs(sum_amount(usage_query, month_start))
        total_usage = abs(sum_amount(usage_query))

        prev_month_usage = 0
        if prev_month_start and prev_period_end:
            q_prev_u = usage_query.filter(Transaction.created_at >= prev_month_start, Transaction.created_at < prev_period_end)
            prev_month_usage = abs(db.session.query(func.coalesce(func.sum(Transaction.amount), 0)).filter(Transaction.id.in_(q_prev_u.with_entities(Transaction.id))).scalar() or 0)

        month_net = int(month_charge) - int(month_usage)
        prev_month_net = int(prev_month_charge) - int(prev_month_usage)

        def pct_change(cur, prev):
            try:
                cur = float(cur)
                prev = float(prev)
            except Exception:
                return None
            if prev == 0:
                return 0.0 if cur == 0 else None
            return ((cur - prev) / abs(prev)) * 100.0

        month_charge_pct = pct_change(month_charge, prev_month_charge)
        month_usage_pct = pct_change(month_usage, prev_month_usage)
        month_net_pct = pct_change(month_net, prev_month_net)

        today_charge_pct = pct_change(today_charge, prev_same_day_charge)

        month_charge_delta = int(month_charge) - int(prev_month_charge)
        month_usage_delta = int(month_usage) - int(prev_month_usage)
        month_net_delta = int(month_net) - int(prev_month_net)
        today_charge_delta = int(today_charge) - int(prev_same_day_charge)

        remain = total_charge - total_usage

        return jsonify({
            'success': True,
            'stats': {
                'today': today_charge,
                'month': month_charge,
                'month_expense': month_usage,
                'total': remain,
                'prev_month': prev_month_charge,
                'prev_month_expense': prev_month_usage,
                'month_net': month_net,
                'prev_month_net': prev_month_net,
                'month_change_pct': month_charge_pct,
                'month_expense_change_pct': month_usage_pct,
                'month_net_change_pct': month_net_pct,
                'today_prev': prev_same_day_charge,
                'today_change_pct': today_charge_pct,
                'today_change_amount': today_charge_delta,
                'month_change_amount': month_charge_delta,
                'month_expense_change_amount': month_usage_delta,
                'month_net_change_amount': month_net_delta,
                'payment_count': charge_query.count(),
                'total_charge': total_charge,
                'total_usage': total_usage
            }
        })
    else:
        # Month income must include ALL positive entries except server cost/renewal/traffic.
        # Also include manual `Payment` records (these are separate from `Transaction`).
        tx_income_query = Transaction.query.filter(
            Transaction.amount > 0,
            or_(Transaction.type.is_(None), func.upper(Transaction.type).notin_(excluded_types_upper))
        )
        if target_user_id:
            tx_income_query = tx_income_query.filter(Transaction.admin_id == target_user_id)
        if card_id:
            tx_income_query = tx_income_query.filter(Transaction.card_id == card_id)
        if server_id:
            tx_income_query = tx_income_query.filter(Transaction.server_id == server_id)

        pay_income_query = Payment.query.filter(Payment.amount > 0)
        if target_user_id:
            pay_income_query = pay_income_query.filter(Payment.admin_id == target_user_id)
        if card_id:
            pay_income_query = pay_income_query.filter(Payment.card_id == card_id)

        def sum_tx_income(start_time=None, end_time=None):
            q = db.session.query(func.coalesce(func.sum(Transaction.amount), 0)).filter(
                Transaction.id.in_(tx_income_query.with_entities(Transaction.id))
            )
            if start_time:
                q = q.filter(Transaction.created_at >= start_time)
            if end_time:
                q = q.filter(Transaction.created_at < end_time)
            return q.scalar() or 0

        def sum_pay_income(start_time=None, end_time=None):
            q = db.session.query(func.coalesce(func.sum(Payment.amount), 0)).filter(
                Payment.id.in_(pay_income_query.with_entities(Payment.id))
            )
            if start_time:
                q = q.filter(Payment.payment_date >= start_time)
            if end_time:
                q = q.filter(Payment.payment_date < end_time)
            return q.scalar() or 0

        today_income = sum_tx_income(today_start) + sum_pay_income(today_start)
        month_income = sum_tx_income(month_start) + sum_pay_income(month_start)
        total_income = sum_tx_income() + sum_pay_income()

        prev_month_income = 0
        if prev_month_start and prev_period_end:
            prev_month_income = (
                sum_tx_income(prev_month_start, prev_period_end)
                + sum_pay_income(prev_month_start, prev_period_end)
            )

        prev_same_day_income = 0
        if prev_same_day_start and prev_same_day_end:
            prev_same_day_income = (
                sum_tx_income(prev_same_day_start, prev_same_day_end)
                + sum_pay_income(prev_same_day_start, prev_same_day_end)
            )

        # For net profit: get expense transactions separately
        expense_query = Transaction.query.filter(Transaction.category == 'expense')
        if target_user_id:
            expense_query = expense_query.filter(Transaction.admin_id == target_user_id)
        if card_id:
            expense_query = expense_query.filter(Transaction.card_id == card_id)
        if server_id:
            expense_query = expense_query.filter(Transaction.server_id == server_id)

        total_expense = db.session.query(func.coalesce(func.sum(Transaction.amount), 0)).filter(
            Transaction.id.in_(expense_query.with_entities(Transaction.id))
        ).scalar() or 0

        month_expense = db.session.query(func.coalesce(func.sum(Transaction.amount), 0)).filter(
            Transaction.id.in_(expense_query.with_entities(Transaction.id)),
            Transaction.created_at >= month_start
        ).scalar() or 0

        prev_month_expense = 0
        if prev_month_start and prev_period_end:
            prev_month_expense = db.session.query(func.coalesce(func.sum(Transaction.amount), 0)).filter(
                Transaction.id.in_(expense_query.with_entities(Transaction.id)),
                Transaction.created_at >= prev_month_start,
                Transaction.created_at < prev_period_end
            ).scalar() or 0

        month_cost_abs = abs(month_expense)
        prev_month_cost_abs = abs(prev_month_expense)
        month_profit = int(month_income) - int(month_cost_abs)
        prev_month_profit = int(prev_month_income) - int(prev_month_cost_abs)

        def pct_change(cur, prev):
            try:
                cur = float(cur)
                prev = float(prev)
            except Exception:
                return None
            if prev == 0:
                return 0.0 if cur == 0 else None
            return ((cur - prev) / abs(prev)) * 100.0

        month_income_pct = pct_change(month_income, prev_month_income)
        month_cost_pct = pct_change(month_cost_abs, prev_month_cost_abs)
        month_profit_pct = pct_change(month_profit, prev_month_profit)

        today_income_pct = pct_change(today_income, prev_same_day_income)

        month_income_delta = int(month_income) - int(prev_month_income)
        month_cost_delta = int(month_cost_abs) - int(prev_month_cost_abs)
        month_profit_delta = int(month_profit) - int(prev_month_profit)
        today_income_delta = int(today_income) - int(prev_same_day_income)

        payment_count = tx_income_query.count() + pay_income_query.count()

        income_by_card = []
        if user.is_superadmin or user.role == 'reseller':
            card_stats = db.session.query(
                BankCard.id,
                BankCard.label,
                BankCard.bank_name,
                func.sum(Transaction.amount).label('total')
            ).join(Transaction, Transaction.card_id == BankCard.id).filter(
                Transaction.id.in_(tx_income_query.with_entities(Transaction.id)),
                Transaction.category.in_(['income', 'expense'])
            ).group_by(BankCard.id).all()

            for card_id, label, bank_name, total in card_stats:
                income_by_card.append({
                    'card_id': card_id,
                    'label': label,
                    'bank_name': bank_name,
                    'total': total or 0
                })
        return jsonify({
            'success': True,
            'stats': {
                'today': today_income,
                'month': month_income,
                'month_expense': abs(month_expense),
                'total': total_income,
                'prev_month': prev_month_income,
                'prev_month_expense': prev_month_cost_abs,
                'month_net': month_profit,
                'prev_month_net': prev_month_profit,
                'month_change_pct': month_income_pct,
                'month_expense_change_pct': month_cost_pct,
                'month_net_change_pct': month_profit_pct,
                'today_prev': prev_same_day_income,
                'today_change_pct': today_income_pct,
                'today_change_amount': today_income_delta,
                'month_change_amount': month_income_delta,
                'month_expense_change_amount': month_cost_delta,
                'month_net_change_amount': month_profit_delta,
                'payment_count': payment_count,
                'by_card': income_by_card,
                'total_income': total_income,
                'total_expense': total_expense
            }
        })


@app.route('/api/finance/overview', methods=['GET'])
@login_required
def get_finance_overview():
    """Timeseries overview for income/expense/profit."""
    user = db.session.get(Admin, session['admin_id'])
    if not user:
        return jsonify({"success": False, "error": "User not found"}), 401

    requested_range = (request.args.get('range') or '30d').strip().lower()
    if requested_range not in ('12m', '30d', '7d', '24h', 'month'):
        requested_range = '30d'

    # Optional month selection (Jalali)
    selected_month = request.args.get('month', type=int)
    selected_year = request.args.get('year', type=int)
    if selected_month and 1 <= int(selected_month) <= 12:
        requested_range = 'month'

    card_id = request.args.get('card_id', type=int)
    server_id = request.args.get('server_id', type=int)
    target_user_id = request.args.get('user_id', type=int)

    tehran_offset = timedelta(hours=3, minutes=30)
    now_utc = datetime.utcnow()
    now_tehran = now_utc + tehran_offset

    def as_tehran(dt_utc):
        return (dt_utc + tehran_offset) if dt_utc else None

    labels = []
    keys = []
    start_utc = None
    end_utc = None

    excluded_types_upper = {'SERVER_COST', 'SERVER_RENEWAL', 'SERVER_TRAFFIC'}

    # Build bucket keys (chronological)
    if requested_range == '12m':
        j_now = jdatetime_class.fromgregorian(datetime=now_tehran)
        j_year = int(j_now.year)
        j_month = int(j_now.month)

        def shift_month(year, month, delta):
            total = (year * 12 + (month - 1)) + delta
            new_year = total // 12
            new_month = (total % 12) + 1
            return new_year, new_month

        month_starts_tehran = []
        for i in range(11, -1, -1):
            y, m = shift_month(j_year, j_month, -i)
            j_start = jdatetime_class(y, m, 1, 0, 0, 0, 0)
            g_start_tehran = j_start.togregorian()
            month_starts_tehran.append(g_start_tehran)
            labels.append(f"{y:04d}/{m:02d}")
            keys.append((y, m))

        # end is start of next month
        next_y, next_m = shift_month(j_year, j_month, 1)
        j_end = jdatetime_class(next_y, next_m, 1, 0, 0, 0, 0)
        g_end_tehran = j_end.togregorian()
        start_utc = month_starts_tehran[0] - tehran_offset
        end_utc = g_end_tehran - tehran_offset
    elif requested_range in ('30d', '7d'):
        days = 30 if requested_range == '30d' else 7
        end_tehran = now_tehran
        end_tehran_floor = end_tehran.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
        start_tehran = end_tehran_floor - timedelta(days=days)
        start_utc = start_tehran - tehran_offset
        end_utc = end_tehran_floor - tehran_offset

        for i in range(days, 0, -1):
            day_start_tehran = end_tehran_floor - timedelta(days=i)
            # label as Jalali date
            j_label = (format_jalali(day_start_tehran) or '').strip()
            if ' ' in j_label:
                j_label = j_label.split(' ')[0]
            labels.append(j_label)
            keys.append(day_start_tehran.date())
    elif requested_range == 'month':
        # Daily buckets for a selected Jalali month (defaults to current Jalali year)
        j_now = jdatetime_class.fromgregorian(datetime=now_tehran)
        j_year = int(selected_year or j_now.year)
        j_month = int(selected_month or j_now.month)

        # Start of selected month
        j_start = jdatetime_class(j_year, j_month, 1, 0, 0, 0, 0)
        g_start_tehran = j_start.togregorian()
        start_utc = g_start_tehran - tehran_offset

        # Start of next month
        if j_month == 12:
            j_end = jdatetime_class(j_year + 1, 1, 1, 0, 0, 0, 0)
        else:
            j_end = jdatetime_class(j_year, j_month + 1, 1, 0, 0, 0, 0)
        g_end_tehran = j_end.togregorian()
        end_utc = g_end_tehran - tehran_offset

        # Number of days in this Jalali month
        try:
            days_in_month = int(j_end.togregorian().date() - j_start.togregorian().date()).days
        except Exception:
            days_in_month = 31
            if j_month > 6:
                days_in_month = 30
            if j_month == 12:
                days_in_month = 29

        for day in range(1, days_in_month + 1):
            # Use day number as label (cleaner for bar chart)
            labels.append(str(day))
            # Keys are Gregorian dates in Tehran (date-only)
            g_day_tehran = (jdatetime_class(j_year, j_month, day, 0, 0, 0, 0)).togregorian()
            keys.append(g_day_tehran.date())
    else:  # 24h
        end_tehran = now_tehran.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
        start_tehran = end_tehran - timedelta(hours=24)
        start_utc = start_tehran - tehran_offset
        end_utc = end_tehran - tehran_offset

        for i in range(24, 0, -1):
            hour_start_tehran = end_tehran - timedelta(hours=i)
            labels.append(hour_start_tehran.strftime('%H:00'))
            keys.append(hour_start_tehran)

    # Query ledger rows in a single window then bin in Python.
    # - Income: any positive amount EXCEPT server-cost/renewal/traffic.
    # - Expense: any negative amount (absolute).
    # Also include manual `Payment` rows as income.
    tx_query = Transaction.query
    if user.role == 'reseller':
        tx_query = tx_query.filter(Transaction.admin_id == user.id)
    else:
        if target_user_id:
            tx_query = tx_query.filter(Transaction.admin_id == target_user_id)

    if card_id:
        tx_query = tx_query.filter(Transaction.card_id == card_id)
    if server_id:
        tx_query = tx_query.filter(Transaction.server_id == server_id)

    tx_query = tx_query.filter(Transaction.created_at >= start_utc, Transaction.created_at < end_utc)
    tx_query = tx_query.filter(Transaction.type != 'audit')

    tx_rows = tx_query.all()

    pay_query = Payment.query.filter(Payment.payment_date >= start_utc, Payment.payment_date < end_utc)
    if user.role == 'reseller':
        pay_query = pay_query.filter(Payment.admin_id == user.id)
    else:
        if target_user_id:
            pay_query = pay_query.filter(Payment.admin_id == target_user_id)
    if card_id:
        pay_query = pay_query.filter(Payment.card_id == card_id)
    pay_rows = pay_query.all()

    income_map = {k: 0 for k in keys}
    expense_map = {k: 0 for k in keys}

    def bucket_for_tehran_dt(tehran_dt):
        if requested_range == '12m':
            j_dt = jdatetime_class.fromgregorian(datetime=tehran_dt)
            return (int(j_dt.year), int(j_dt.month))
        if requested_range in ('30d', '7d', 'month'):
            return tehran_dt.date()
        return tehran_dt.replace(minute=0, second=0, microsecond=0)

    for tx in tx_rows:
        if not tx.created_at:
            continue
        tehran_dt = as_tehran(tx.created_at)
        if not tehran_dt:
            continue

        bucket_key = bucket_for_tehran_dt(tehran_dt)
        if bucket_key not in income_map:
            continue

        amount = int(tx.amount or 0)
        if amount > 0:
            tx_type = (tx.type or '')
            if tx_type and str(tx_type).upper() in excluded_types_upper:
                continue
            income_map[bucket_key] += amount
        elif amount < 0:
            expense_map[bucket_key] += abs(amount)

    for pay in pay_rows:
        if not pay.payment_date:
            continue
        tehran_dt = as_tehran(pay.payment_date)
        if not tehran_dt:
            continue

        bucket_key = bucket_for_tehran_dt(tehran_dt)
        if bucket_key not in income_map:
            continue

        amount = int(pay.amount or 0)
        if amount > 0:
            income_map[bucket_key] += amount

    income_series = [int(income_map[k] or 0) for k in keys]
    expense_series = [int(expense_map[k] or 0) for k in keys]
    profit_series = [int(i - e) for i, e in zip(income_series, expense_series)]

    return jsonify({
        'success': True,
        'range': requested_range,
        'month': int(selected_month) if selected_month else None,
        'year': int(selected_year) if selected_year else None,
        'labels': labels,
        'series': {
            'income': income_series,
            'expense': expense_series,
            'profit': profit_series
        }
    })


@app.route('/sub/history/<int:server_id>/<sub_id>')
def sub_usage_history(server_id, sub_id):
    """Return usage snapshots + renewal events for a subscription.

    Query params:
      period: hour (last 24h raw) | day (last 30d, by day) | month (last 12m, by month)
    """
    normalized_sub_id = str(sub_id or '').strip()
    if not normalized_sub_id or any(c in normalized_sub_id for c in ('/', '\\', '?', '#', '@', ':')):
        return jsonify({'success': False, 'error': 'Invalid subscription ID'}), 400

    server = db.session.get(Server, server_id)
    if not server:
        return jsonify({'success': False, 'error': 'Server not found'}), 404

    period = (request.args.get('period') or 'day').strip().lower()
    if period not in ('5min', 'hour', 'day', 'month'):
        period = 'day'

    now_utc = datetime.utcnow()
    if period == '5min':
        since = now_utc - timedelta(hours=3)    # last 3h at 5-min granularity
    elif period == 'hour':
        since = now_utc - timedelta(hours=48)   # 48h window so daily boundary is visible
    elif period == 'month':
        since = now_utc - timedelta(days=366)
    else:
        since = now_utc - timedelta(days=30)

    snapshots = (UsageSnapshot.query
                 .filter_by(server_id=server_id, sub_id=normalized_sub_id)
                 .filter(UsageSnapshot.recorded_at >= since)
                 .order_by(UsageSnapshot.recorded_at.asc())
                 .all())

    # Prepend the last snapshot before the window as a baseline for delta computation
    if snapshots:
        baseline = (UsageSnapshot.query
                    .filter_by(server_id=server_id, sub_id=normalized_sub_id)
                    .filter(UsageSnapshot.recorded_at < since)
                    .order_by(UsageSnapshot.recorded_at.desc())
                    .first())
        if baseline:
            snapshots = [baseline] + list(snapshots)

    # Compute per-snapshot deltas.
    # has_baseline = True when snapshots[0] was prepended from before the window.
    has_baseline = len(snapshots) > 1 and snapshots[0].recorded_at < since
    delta_rows = []

    if not snapshots:
        pass
    elif len(snapshots) == 1:
        # Single snapshot, no baseline — expose its cumulative totals directly.
        snap = snapshots[0]
        delta_rows.append({
            'ts': snap.recorded_at,
            'delta_upload': snap.upload_bytes,
            'delta_download': snap.download_bytes,
            'delta_total': snap.total_bytes,
            'remaining': snap.remaining_bytes,
            'volume_limit': snap.volume_limit_bytes,
            'cumulative': snap.total_bytes,
            'is_cumulative': True,
        })
    else:
        # When there is no baseline before the window, snap[0]'s absolute values
        # would otherwise be invisible (only used as the prev of the first delta).
        # Expose them as a dedicated cumulative row so historical context is never lost.
        if not has_baseline:
            snap0 = snapshots[0]
            delta_rows.append({
                'ts': snap0.recorded_at,
                'delta_upload': snap0.upload_bytes,
                'delta_download': snap0.download_bytes,
                'delta_total': snap0.total_bytes,
                'remaining': snap0.remaining_bytes,
                'volume_limit': snap0.volume_limit_bytes,
                'cumulative': snap0.total_bytes,
                'is_cumulative': True,
            })

        for i in range(1, len(snapshots)):
            prev = snapshots[i - 1]
            curr = snapshots[i]
            delta_up   = max(curr.upload_bytes   - prev.upload_bytes,   0)
            delta_down = max(curr.download_bytes - prev.download_bytes, 0)
            # Use latest non-null remaining; fall back to prev if curr has none
            remaining = curr.remaining_bytes
            if remaining is None:
                remaining = prev.remaining_bytes
            delta_rows.append({
                'ts': curr.recorded_at,
                'delta_upload': delta_up,
                'delta_download': delta_down,
                'delta_total': delta_up + delta_down,
                'remaining': remaining,
                'volume_limit': curr.volume_limit_bytes or prev.volume_limit_bytes,
                'cumulative': curr.total_bytes,
                'is_cumulative': False,
            })

    # Aggregate by period using Tehran timezone label (UTC+3:30)
    _TEHRAN_OFFSET = timedelta(hours=3, minutes=30)

    def _tehran_date(ts):
        local = ts + _TEHRAN_OFFSET
        return local.strftime('%Y-%m-%d')

    def _tehran_hour_key(ts):
        local = ts + _TEHRAN_OFFSET
        return local.strftime('%Y-%m-%dT%H')

    def _tehran_5min_key(ts):
        local = ts + _TEHRAN_OFFSET
        bucket_min = (local.minute // 5) * 5
        return local.strftime('%Y-%m-%dT%H:') + str(bucket_min).zfill(2)

    def _tehran_month_key(ts):
        local = ts + _TEHRAN_OFFSET
        return local.strftime('%Y-%m')

    from collections import defaultdict, OrderedDict

    def _aggregate(key_fn):
        bucket = OrderedDict()
        for r in delta_rows:
            k = key_fn(r['ts'])
            if k not in bucket:
                bucket[k] = {'delta_upload': 0, 'delta_download': 0, 'delta_total': 0,
                              'remaining': None, 'volume_limit': None, 'ts_example': r['ts'],
                              'is_cumulative': False}
            bucket[k]['delta_upload'] += r['delta_upload']
            bucket[k]['delta_download'] += r['delta_download']
            bucket[k]['delta_total'] += r['delta_total']
            bucket[k]['remaining'] = r['remaining']
            bucket[k]['volume_limit'] = r['volume_limit']
            if r.get('is_cumulative'):
                bucket[k]['is_cumulative'] = True
        return bucket

    if period == '5min':
        bucket = _aggregate(_tehran_5min_key)
    elif period == 'hour':
        bucket = _aggregate(_tehran_hour_key)
    elif period == 'month':
        bucket = _aggregate(_tehran_month_key)
    else:  # day
        bucket = _aggregate(_tehran_date)

    history_rows = []
    for k, v in bucket.items():
        history_rows.append({
            'period_key': k,
            'recorded_at': v['ts_example'].isoformat() + 'Z',
            'delta_upload': v['delta_upload'],
            'delta_download': v['delta_download'],
            'delta_total': v['delta_total'],
            'remaining': v['remaining'],
            'volume_limit': v['volume_limit'],
            'is_cumulative': v.get('is_cumulative', False),
        })
    # Most recent first
    history_rows.reverse()

    renewals = (RenewalEvent.query
                .filter_by(server_id=server_id, sub_id=normalized_sub_id)
                .order_by(RenewalEvent.renewed_at.desc())
                .limit(30)
                .all())

    renewal_rows = [{
        'renewed_at': r.renewed_at.isoformat() + 'Z',
        'volume_bytes': r.volume_bytes,
        'days': r.days,
        'is_unlimited_volume': r.is_unlimited_volume,
        'is_unlimited_time': r.is_unlimited_time,
    } for r in renewals]

    # Latest snapshot for current state
    latest = (UsageSnapshot.query
              .filter_by(server_id=server_id, sub_id=normalized_sub_id)
              .order_by(UsageSnapshot.recorded_at.desc())
              .first())

    return jsonify({
        'success': True,
        'period': period,
        'history': history_rows,
        'renewals': renewal_rows,
        'snapshot_count': len(snapshots),
        'latest_remaining': latest.remaining_bytes if latest else None,
        'latest_volume_limit': latest.volume_limit_bytes if latest else None,
        'latest_recorded_at': (latest.recorded_at.isoformat() + 'Z') if latest else None,
    })


def _fa_digits(value) -> str:
    """Convert ASCII digits in `value` to Persian digits."""
    return str(value).translate(str.maketrans('0123456789', '۰۱۲۳۴۵۶۷۸۹'))


def _build_status_config_line(state: dict, expiry_info: dict, remaining_bytes, total_limit: int, lang: str = 'fa') -> str | None:
    """Return a single non-routable vmess:// 'status' config.

    Its display name (the vmess `ps` field) summarizes the customer's service
    state, remaining days and remaining volume. It is appended as the LAST entry
    of a subscription so customers can read their status from inside their VPN
    app (each config shows by name in the server list) without ever opening the
    subscription page. It points at 127.0.0.1:1 and never carries traffic.
    Recomputed on every request, so it always reflects the latest status.
    """
    try:
        fa = _normalize_ui_lang(lang, default='en') == 'fa'
        key = (state or {}).get('key') or 'active'
        emoji = (state or {}).get('emoji') or ''
        label = (state or {}).get('label') or ('فعال' if fa else 'Active')

        parts = [f"{emoji} {label}".strip()]

        if key in ('expired', 'volume_ended', 'inactive'):
            # Terminal states: the label already says it; add a renew nudge.
            parts.append('لطفا تمدید کنید' if fa else 'Please renew')
        else:
            etype = str((expiry_info or {}).get('type') or '').lower()
            days = (expiry_info or {}).get('days')
            if etype in ('unlimited', 'start_after_use'):
                parts.append('زمان نامحدود' if fa else 'Unlimited time')
            elif isinstance(days, (int, float)) and days > 0:
                d = int(days)
                parts.append(f"{_fa_digits(d)} روز مانده" if fa else f"{d} days left")

            if total_limit and total_limit > 0:
                gb = max(int(remaining_bytes or 0), 0) / (1024 ** 3)
                gb_str = f"{gb:.1f}".rstrip('0').rstrip('.')
                parts.append(f"{_fa_digits(gb_str)} گیگ مانده" if fa else f"{gb_str} GB left")
            else:
                parts.append('حجم نامحدود' if fa else 'Unlimited data')

        # Make clear this entry is informational only — it must not be connected to.
        parts.append('🚫 انتخاب نکنید' if fa else '🚫 Do not select')

        name = ' | '.join(p for p in parts if p)
        vmess_obj = {
            "v": "2", "ps": name, "add": "127.0.0.1", "port": "1",
            "id": "00000000-0000-0000-0000-000000000000", "aid": "0",
            "scy": "auto", "net": "tcp", "type": "none",
            "host": "", "path": "", "tls": "",
        }
        payload = base64.b64encode(json.dumps(vmess_obj, ensure_ascii=False).encode()).decode()
        return f"vmess://{payload}"
    except Exception:
        app.logger.exception("status config build failed")
        return None


@app.route('/s/<int:server_id>/<sub_id>')
def client_subscription(server_id, sub_id):
    server = db.session.get(Server, server_id)
    if not server:
        return "Subscription not found", 404

    wants_html_view = str(request.args.get('view', '')).strip().lower() in ('1', 'true', 'yes')

    # Normalize subscription identifier early
    normalized_sub_id = str(sub_id).strip()
    
    # SSRF/Path Traversal Protection: Ensure sub_id doesn't contain characters that could manipulate the URL
    if any(c in normalized_sub_id for c in ('/', '\\', '?', '#', '@', ':', '..')):
        app.logger.warning(f"Potential SSRF/Traversal attempt with sub_id: {normalized_sub_id}")
        return "Invalid subscription ID", 400

    target_client = None
    target_inbound = None
    found_in_cache = False

    # === Cache-first path: try to find client in in-memory GLOBAL_SERVER_DATA ===
    try:
        cached_inbounds = GLOBAL_SERVER_DATA.get('inbounds', []) or []
        # Filter inbounds for this server
        server_inbounds = [i for i in cached_inbounds if int(i.get('server_id', -1)) == int(server_id)]
        for inbound in server_inbounds:
            for client in inbound.get('clients', []):
                c_sub_id = str(client.get('subId') or '').strip()
                c_uuid = str(client.get('id') or '').strip()
                if normalized_sub_id and (normalized_sub_id == c_sub_id or (not c_sub_id and normalized_sub_id == c_uuid)):
                    target_client = client
                    target_inbound = inbound
                    found_in_cache = True
                    break
            if target_client:
                break
    except Exception:
        found_in_cache = False

    # === Stale-cache recovery: if client was found in cache but server is marked unreachable,
    #     try a live fetch so quota/limit changes made in x-ui are reflected immediately ===
    if found_in_cache and wants_html_view:
        try:
            _srv_statuses = GLOBAL_SERVER_DATA.get('servers_status') or []
            _srv_status = next(
                (s for s in _srv_statuses if int(s.get('server_id', -1)) == int(server_id)),
                None
            )
            _server_unreachable = _srv_status is not None and not _srv_status.get('reachable', True)
            if _server_unreachable:
                _s_obj, _s_err = get_xui_session(server)
                if not _s_err and _s_obj:
                    _live_inbounds, _live_err, _live_type = fetch_inbounds(_s_obj, server.host, server.panel_type)
                    if not _live_err and _live_inbounds:
                        persist_detected_panel_type(server, _live_type)
                        for _inb in _live_inbounds:
                            _settings = _json_field(_inb.get('settings'), {})
                            for _cli in _settings.get('clients', []):
                                _c_sub = str(_cli.get('subId') or '').strip()
                                _c_uuid = str(_cli.get('id') or '').strip()
                                if normalized_sub_id and (normalized_sub_id == _c_sub or (not _c_sub and normalized_sub_id == _c_uuid)):
                                    target_client = _cli
                                    target_inbound = _inb
                                    found_in_cache = False
                                    break
                            if not found_in_cache:
                                break
        except Exception:
            pass  # keep cached data on any error

    # === Fallback: if not found in cache, perform live fetch (legacy behavior) ===
    if not target_client:
        session_obj, login_error = get_xui_session(server)
        if login_error or not session_obj:
            app.logger.warning(f"Dash sub auth failed for server {server_id}: {login_error}")
            return "Unable to load subscription", 502

        inbounds, fetch_error, detected_type = fetch_inbounds(session_obj, server.host, server.panel_type)
        if fetch_error or not inbounds:
            app.logger.warning(f"Dash sub fetch failed for server {server_id}: {fetch_error}")
            return "Unable to load subscription", 502

        persist_detected_panel_type(server, detected_type)

        # Search in raw fetched inbounds (original logic)
        for inbound in inbounds:
            settings = _json_field(inbound.get('settings'), {})
            for client in settings.get('clients', []):
                client_sub_id = str(client.get('subId') or '').strip()
                client_uuid = str(client.get('id') or '').strip()
                if normalized_sub_id and (normalized_sub_id == client_sub_id or (not client_sub_id and normalized_sub_id == client_uuid)):
                    target_client = client
                    target_inbound = inbound
                    break
            if target_client:
                break

    # (client search completed either from cache or from fetched inbounds)

    if not target_client or not target_inbound:
        return "Subscription not found", 404

    client_email = target_client.get('email') or f"user-{normalized_sub_id}"

    def _to_int_or_none(value):
        if value is None:
            return None
        if isinstance(value, bool):
            return int(value)
        try:
            return int(value)
        except Exception:
            try:
                return int(float(str(value).strip()))
            except Exception:
                return None

    # Cache path typically stores traffic directly on the client object,
    # while live-fetch path exposes traffic via inbound.clientStats.
    up = _to_int_or_none(target_client.get('up'))
    down = _to_int_or_none(target_client.get('down'))

    if up is None or down is None:
        client_stats = target_inbound.get('clientStats') or []
        for stat in client_stats:
            if stat.get('email') == target_client.get('email'):
                up = _to_int_or_none(stat.get('up'))
                down = _to_int_or_none(stat.get('down'))
                break

    up = up or 0
    down = down or 0

    total_used = (up or 0) + (down or 0)
    try:
        total_limit = int(target_client.get('totalGB') or 0)
    except (TypeError, ValueError):
        total_limit = 0
    remaining = max(total_limit - total_used, 0) if total_limit > 0 else None
    percentage_used = round((total_used / total_limit) * 100, 2) if total_limit else 0

    page_lang = (_get_or_create_system_setting('subscription_page_lang', 'en') or 'en').strip().lower()
    if page_lang not in ('fa', 'en'):
        page_lang = 'en'

    # When serving from cache, `expiryTime` is already formatted text.
    expiry_raw_ms = target_client.get('expiryTimestamp', None) if found_in_cache else target_client.get('expiryTime', None)
    if expiry_raw_ms is None:
        expiry_raw_ms = target_client.get('expiryTime', 0)
    expiry_info = format_remaining_days(expiry_raw_ms, lang=page_lang)

    try:
        expiry_ts_norm = int(expiry_raw_ms or 0)
    except Exception:
        expiry_ts_norm = 0

    subscription_state = _compute_client_service_state(
        enabled=bool(target_client.get('enable', True)),
        total_bytes=int(total_limit or 0),
        remaining_bytes=(None if remaining is None else int(remaining)),
        expiry_ts=expiry_ts_norm,
        expiry_info=expiry_info,
        thresholds=_get_dashboard_status_thresholds(),
        lang=page_lang,
    )

    # Prepare fallback headers for client apps (used for both upstream-proxy and manual generation)
    expiry_time_ms = expiry_raw_ms or 0
    expiry_time_sec = int(expiry_time_ms / 1000) if expiry_time_ms and expiry_time_ms > 0 else 0
    
    # Fix: If expire is 0 (unlimited), set to far future to prevent v2rayNG from hanging/looping
    # v2rayNG interprets expire=0 incorrectly, causing subscription loading issues
    if expiry_time_sec == 0:
        import time as _time
        expiry_time_sec = int(_time.time()) + 315360000  # 10 years in the future
    
    user_info_header = f"upload={up}; download={down}; total={total_limit}; expire={expiry_time_sec}"
    _profile_title_raw = f"{server.name} - {client_email}"
    _profile_title_b64 = base64.b64encode(_profile_title_raw.encode('utf-8')).decode('utf-8')
    fallback_headers = {
        'Subscription-Userinfo': user_info_header,
        'Profile-Update-Interval': '24',
        'Content-Type': 'text/plain; charset=utf-8',
        'Profile-Title': f"base64:{_profile_title_b64}"
    }

    host_value = server.host
    if host_value and not host_value.startswith(('http://', 'https://')):
        host_value = f"http://{host_value}"
    parsed_host = urlparse(host_value or '')
    hostname = parsed_host.hostname or parsed_host.path or ''
    scheme = parsed_host.scheme or 'http'
    final_port = server.sub_port if server.sub_port else parsed_host.port
    port_str = f":{final_port}" if final_port else ''
    sub_path = (server.sub_path or '/sub/').strip('/')
    base_sub = f"{scheme}://{hostname}{port_str}"
    
    # SSRF Protection: Quote the sub_id to ensure it stays in the path component
    safe_sub_id = quote(normalized_sub_id)
    sub_url = f"{base_sub}/{sub_path}/{safe_sub_id}" if sub_path else f"{base_sub}/{safe_sub_id}"

    # Forward query params (except local-only ones) to upstream
    forward_params = dict(request.args)
    forward_params.pop('view', None)
    forward_params.pop('format', None)
    upstream_sub_url = f"{sub_url}?{urlencode(forward_params)}" if forward_params else sub_url

    # Prepare User-Agent check
    user_agent = (request.headers.get('User-Agent') or '').lower()
    # Comprehensive list of V2Ray/Xray client user-agents
    agent_tokens = [
        # --- Universal / Cross Platform ---
        'v2ray', 'xray', 'shadowsocks', 'clash', 'sing-box', 'tuic', 'hysteria',
        'hiddify', 'happ', 'karing',

        # --- iOS Clients ---
        'shadowrocket', 'streisand', 'v2box', 'kitsunebi', 'quantumult',
        'surge', 'loon', 'stash', 'fair', 'pepi', 'i2ray', 'foxray', 'potatso',
        'oneclick', 'v2rayu', 'spectre', 'shadowlink',

        # --- Android Clients ---
        'v2rayng', 'sagernet', 'nekobox', 'matsuri', 'bifrostv',
        'igniter', 'anxray', 'surfboard', 'v2raytun', 'mahsa', 'napsternetv', 'npv',
        'invizible', 'karimg',

        # --- Desktop (Windows, Mac, Linux) ---
        'nekoray', 'v2rayn', 'v2raya', 'qv2ray', 'mellow', 'flclash', 'furious',
        'clash-verge', 'clashverge', 'v2rayx', 'musedaq',
    ]
    wants_b64 = request.args.get('format', '').lower() == 'b64'
    accept = (request.headers.get('Accept') or '').lower()
    accept_prefers_html = ('text/html' in accept) or ('application/xhtml+xml' in accept)
    # A request is browser-like only if it BOTH sends text/html in Accept AND has a browser UA.
    # Everything else (unknown UA, no Accept, Accept:*/*, known V2Ray UA) is treated as a client app.
    is_browser_like = accept_prefers_html and ('mozilla' in user_agent)
    is_client_app = (
        wants_b64 or
        any(token in user_agent for token in agent_tokens) or
        (accept and not accept_prefers_html) or
        not is_browser_like
    )

    # v2rayNG is more reliable when the subscription response is base64.
    # Some versions can appear to hang/spin when the server returns plain text.
    if 'v2rayng' in user_agent:
        wants_b64 = True

    def _looks_like_config_payload(text: str) -> bool:
        t = (text or '').lstrip()
        if not t:
            return False
        schemes = (
            'vmess://', 'vless://', 'trojan://', 'ss://', 'ssr://',
            'hysteria://', 'hysteria2://', 'tuic://', 'warp://'
        )
        return t.startswith(schemes)

    def _normalize_subscription_bytes(raw: bytes) -> bytes:
        """Return plain-text subscription bytes.

        Upstream panels sometimes return base64; this normalizes to plain text
        (one config per line) so we can reliably re-encode for clients.
        """
        raw = raw or b''
        try:
            raw_text = raw.decode('utf-8', errors='ignore')
        except Exception:
            raw_text = ''

        if _looks_like_config_payload(raw_text) or ('\n' in raw_text and '://' in raw_text):
            return raw

        # Try strict base64 decode. If it yields config-like text, use it.
        try:
            decoded = base64.b64decode(raw, validate=True)
            decoded_text = decoded.decode('utf-8', errors='ignore')
            if _looks_like_config_payload(decoded_text) or ('\n' in decoded_text and '://' in decoded_text):
                return decoded
        except Exception:
            pass

        return raw

    # Always try to fetch configs from upstream subscription first
    upstream_configs = []
    try:
        # SSRF Protection: Validate the final URL before requesting
        parsed_upstream = urlparse(upstream_sub_url)
        if parsed_upstream.scheme in ('http', 'https') and parsed_upstream.hostname == hostname:
            resp = requests.get(
                upstream_sub_url,
                headers={'User-Agent': 'v2rayng'},
                timeout=15,
                verify=False,
                allow_redirects=True,
            )
            # SSRF: reject if redirect led outside the server host
            _final_host = urlparse(resp.url).hostname or ''
            if _final_host and _final_host != hostname:
                raise ValueError(f"SSRF: redirect to unexpected host {_final_host}")
            if resp.status_code == 200:
                raw_content = resp.content or b''
                try:
                    decoded = base64.b64decode(raw_content).decode('utf-8')
                except Exception:
                    decoded = raw_content.decode('utf-8', errors='ignore')
                # Only accept lines that look like actual proxy configs, not HTML
                upstream_configs = [
                    line.strip() for line in decoded.splitlines()
                    if line.strip() and '://' in line and not line.strip().startswith('<')
                ]
    except Exception as e:
        app.logger.debug(f"Upstream sub fetch for HTML page: {e}")

    # If it's a client app, try to proxy the subscription from the upstream X-UI panel
    if is_client_app and not wants_html_view:
        try:
            # SSRF Protection: Validate the final URL before requesting
            parsed_upstream = urlparse(upstream_sub_url)
            if parsed_upstream.scheme not in ('http', 'https'):
                app.logger.error(f"SSRF blocked: invalid protocol {parsed_upstream.scheme}")
                return "Invalid upstream protocol", 400
            if parsed_upstream.hostname != hostname:
                app.logger.error(f"SSRF blocked: hostname {parsed_upstream.hostname} does not match server {hostname}")
                return "Invalid upstream host", 400

            resp = requests.get(
                upstream_sub_url,
                headers={'User-Agent': request.headers.get('User-Agent')},
                timeout=15,
                verify=False,
                allow_redirects=True,
            )
            # SSRF: reject if redirect led outside the server host
            _final_host = urlparse(resp.url).hostname or ''
            if _final_host and _final_host != hostname:
                app.logger.error(f"SSRF blocked: redirect led to {_final_host}")
                raise ValueError(f"SSRF: redirect to unexpected host {_final_host}")
            if resp.status_code == 200:
                # Prefer upstream headers (especially Subscription-Userinfo) so client apps show the same usage/expiry.
                upstream_headers = {}

                def pick_header(name: str):
                    return resp.headers.get(name) or resp.headers.get(name.lower())

                for k in ('Subscription-Userinfo', 'Profile-Title', 'Profile-Update-Interval', 'Content-Type', 'Content-Disposition'):
                    v = pick_header(k)
                    if v:
                        upstream_headers[k] = v

                # Fix problematic Subscription-Userinfo values that cause v2rayNG to hang/loop
                # When expire=0 or total=0, some clients interpret this incorrectly
                if 'Subscription-Userinfo' in upstream_headers:
                    sub_info = upstream_headers['Subscription-Userinfo']
                    # Parse the header to check for problematic values
                    info_parts = {}
                    for part in sub_info.split(';'):
                        part = part.strip()
                        if '=' in part:
                            k_part, v_part = part.split('=', 1)
                            info_parts[k_part.strip()] = v_part.strip()
                    
                    # If expire=0, set to far future (10 years) to indicate "unlimited"
                    # This prevents v2rayNG from thinking the subscription is expired
                    if info_parts.get('expire', '0') == '0':
                        import time as _time
                        info_parts['expire'] = str(int(_time.time()) + 315360000)  # 10 years
                    
                    # Rebuild the header
                    upstream_headers['Subscription-Userinfo'] = '; '.join(
                        f"{k}={v}" for k, v in info_parts.items()
                    )

                if 'Subscription-Userinfo' not in upstream_headers:
                    upstream_headers['Subscription-Userinfo'] = fallback_headers['Subscription-Userinfo']
                if 'Profile-Title' not in upstream_headers:
                    upstream_headers['Profile-Title'] = fallback_headers['Profile-Title']
                if 'Profile-Update-Interval' not in upstream_headers:
                    upstream_headers['Profile-Update-Interval'] = fallback_headers['Profile-Update-Interval']
                if 'Content-Type' not in upstream_headers:
                    upstream_headers['Content-Type'] = fallback_headers['Content-Type']

                normalized_payload = _normalize_subscription_bytes(resp.content or b'')
                # Reject HTML/login-page responses — they're not valid subscription data
                _preview = normalized_payload[:300].decode('utf-8', errors='ignore').lower().lstrip()
                if _preview.startswith('<') or 'doctype html' in _preview or '<html' in _preview:
                    raise ValueError("Upstream returned HTML instead of subscription data")
                if not normalized_payload.strip():
                    raise ValueError("Upstream returned empty subscription content")

                # Append the live status config as the last entry (plain-text payloads only).
                _status_line = _build_status_config_line(subscription_state, expiry_info, remaining, total_limit, page_lang)
                if _status_line:
                    try:
                        _payload_text = normalized_payload.decode('utf-8', errors='ignore')
                        if '://' in _payload_text:
                            normalized_payload = (_payload_text.rstrip('\n') + '\n' + _status_line).encode('utf-8')
                    except Exception:
                        pass

                if wants_b64:
                    encoded = base64.b64encode(normalized_payload).decode('utf-8')
                    upstream_headers['Content-Type'] = 'text/plain; charset=utf-8'
                    return encoded, 200, upstream_headers

                return normalized_payload, 200, upstream_headers
            else:
                app.logger.warning(f"Upstream sub fetch failed: {resp.status_code} for {upstream_sub_url}")
        except Exception as e:
            app.logger.error(f"Upstream sub fetch error: {e}")

    # Use upstream configs if available, otherwise fallback to manual generation
    if upstream_configs:
        configs = upstream_configs
    else:
        configs = []
        direct_link = generate_client_link(target_client, target_inbound, server.host)
        if direct_link:
            configs.append(direct_link)

    subscription_entries = [entry for entry in configs if entry]
    # Append the live status config as the last entry (client-app payload only;
    # the HTML view uses `configs`, which we keep clean).
    _status_line = _build_status_config_line(subscription_state, expiry_info, remaining, total_limit, page_lang)
    if _status_line:
        subscription_entries.append(_status_line)
    # Do NOT fall back to sub_url — returning a URL as a "config" causes
    # "Subscription does not contain valid configurations" in every V2Ray client.
    subscription_blob = '\n'.join(subscription_entries)
    encoded_blob = base64.b64encode(subscription_blob.encode('utf-8')).decode('utf-8')

    if is_client_app and not wants_html_view:
        headers = dict(fallback_headers)
        headers['Content-Type'] = 'text/plain; charset=utf-8'
        return encoded_blob, 200, headers

    client_payload = {
        "email": client_email,
        "is_active": target_client.get('enable', True),
        "service_state": subscription_state.get('key', 'active'),
        "service_state_label": subscription_state.get('label', ('فعاله' if page_lang == 'fa' else 'Active')),
        "service_state_emoji": subscription_state.get('emoji', '✅'),
        "service_state_tag": subscription_state.get('tag', 'ok'),
        "total_used": format_bytes(total_used),
        "total_limit": format_bytes(total_limit) if total_limit > 0 else "Unlimited",
        "percentage_used": percentage_used,
        "expiry": expiry_info['text'],
        "expiry_days": expiry_info.get('days', 0),
        "expiry_type": expiry_info.get('type', 'normal'),
        "remaining": format_bytes(remaining) if remaining is not None else None,
        "subscription_url": f"{request.base_url}",
        "configs": configs,
        "server_name": server.name
    }

    apps = SubAppConfig.query.filter_by(is_enabled=True).all()
    apps_payload = [app.to_dict() for app in apps]

    # Get FAQs
    faqs = FAQ.query.filter_by(is_enabled=True).all()
    faqs_payload = [faq.to_dict() for faq in faqs]
    
    # Get support info
    support_telegram = db.session.get(SystemConfig, 'support_telegram')
    support_whatsapp = db.session.get(SystemConfig, 'support_whatsapp')
    support_sms_cfg = db.session.get(SystemConfig, 'support_sms')

    # Get channel links
    channel_telegram = db.session.get(SystemConfig, 'channel_telegram')
    channel_whatsapp = db.session.get(SystemConfig, 'channel_whatsapp')

    def _normalize_url(raw: str, *, default_prefix: str | None = None) -> str:
        val = (raw or '').strip()
        if not val:
            return ''
        if val.startswith('@'):
            val = val[1:].strip()
        if val.startswith('http://') or val.startswith('https://'):
            return val
        if val.startswith('t.me/') or val.startswith('telegram.me/'):
            return f"https://{val}"
        if default_prefix:
            return f"{default_prefix}{val}"
        return f"https://{val}"
    
    support_info = {
        'telegram': support_telegram.value if support_telegram else '',
        'whatsapp': support_whatsapp.value if support_whatsapp else '',
        'sms': (support_sms_cfg.value if support_sms_cfg else '').strip() or '',
    }

    channels_info = {
        'telegram': _normalize_url(channel_telegram.value if channel_telegram else '', default_prefix='https://t.me/'),
        'whatsapp': _normalize_url(channel_whatsapp.value if channel_whatsapp else '')
    }

    # If this client is assigned to a reseller, use reseller-defined support/channels instead of global SystemConfig.
    sub_owner_reseller = None  # the account's reseller owner (if any), used for sub-page packages
    try:
        cu = (target_client.get('id') or '').strip() if isinstance(target_client, dict) else ''
        email_l = (client_email or '').strip().lower()
        ownership = ClientOwnership.query.filter(
            ClientOwnership.server_id == int(server.id),
            or_(
                ClientOwnership.client_uuid == cu,
                func.lower(ClientOwnership.client_email) == email_l,
            )
        ).first()
        reseller = ownership.reseller if ownership else None
        if reseller and getattr(reseller, 'role', None) == 'reseller':
            sub_owner_reseller = reseller
            def _clean_telegram_username(v: str | None) -> str:
                val = (v or '').strip()
                if not val:
                    return ''
                if val.startswith('@'):
                    val = val[1:].strip()
                val = re.sub(r'^(https?://)?(t\.me/|telegram\.me/)', '', val, flags=re.IGNORECASE)
                val = val.strip('/').strip()
                val = re.sub(r'[^0-9a-zA-Z_]', '', val)
                return (val or '')[:100]

            def _clean_whatsapp_number(v: str | None) -> str:
                val = (v or '').strip()
                if not val:
                    return ''
                val = re.sub(r'^(https?://)?wa\.me/', '', val, flags=re.IGNORECASE)
                val = val.strip('/').strip()
                val = re.sub(r'[^0-9+]', '', val)
                return (val or '')[:64]

            support_info = {
                'telegram': _clean_telegram_username(getattr(reseller, 'support_telegram', None)),
                'whatsapp': _clean_whatsapp_number(getattr(reseller, 'support_whatsapp', None)),
                'sms': _clean_whatsapp_number(getattr(reseller, 'support_sms', None)),
            }

            channels_info = {
                'telegram': _normalize_url(getattr(reseller, 'channel_telegram', '') or '', default_prefix='https://t.me/'),
                'whatsapp': _normalize_url(getattr(reseller, 'channel_whatsapp', '') or ''),
            }
    except Exception:
        pass

    # Announcements (server+inbound scoped) for subscription page
    announcements_payload = []
    try:
        def _parse_int_or_none(val):
            if val is None:
                return None
            try:
                return int(val)
            except Exception:
                try:
                    return int(float(str(val).strip()))
                except Exception:
                    return None

        inbound_id = None
        try:
            inbound_id = _parse_int_or_none((target_inbound or {}).get('id'))
            if inbound_id is None:
                inbound_id = _parse_int_or_none((target_inbound or {}).get('inbound_id'))
        except Exception:
            inbound_id = None

        def _normalize_targets(raw_targets, *, fallback_all_servers: bool, fallback_server_ids: list[int]):
            if raw_targets is None:
                if fallback_all_servers:
                    return '*'
                return [{'server_id': int(sid), 'inbounds': '*'} for sid in (fallback_server_ids or [])]

            if raw_targets == '*':
                return '*'

            if isinstance(raw_targets, str):
                trimmed = raw_targets.strip()
                if not trimmed:
                    if fallback_all_servers:
                        return '*'
                    return [{'server_id': int(sid), 'inbounds': '*'} for sid in (fallback_server_ids or [])]
                if trimmed == '*':
                    return '*'
                try:
                    parsed = json.loads(trimmed)
                    return _normalize_targets(parsed, fallback_all_servers=fallback_all_servers, fallback_server_ids=fallback_server_ids)
                except Exception:
                    # Back-compat: comma-separated server ids
                    ids = []
                    for part in trimmed.split(','):
                        try:
                            ids.append(int(part.strip()))
                        except Exception:
                            continue
                    return [{'server_id': int(sid), 'inbounds': '*'} for sid in ids]

            entries = raw_targets if isinstance(raw_targets, list) else [raw_targets]
            merged: dict[int, str | set[int]] = {}
            for item in entries:
                server_id = None
                inbounds: str | list[int] = '*'

                if isinstance(item, (int, float)):
                    server_id = _parse_int_or_none(item)
                    inbounds = '*'
                elif isinstance(item, str):
                    if item.strip() == '*':
                        return '*'
                    server_id = _parse_int_or_none(item)
                    inbounds = '*'
                elif isinstance(item, dict):
                    server_id = _parse_int_or_none(item.get('server_id') or item.get('server') or item.get('id'))
                    raw_inb = item.get('inbounds')
                    if raw_inb == '*' or (isinstance(raw_inb, str) and raw_inb.strip() == '*') or raw_inb is None:
                        inbounds = '*'
                    elif isinstance(raw_inb, list):
                        inbounds = [v for v in (_parse_int_or_none(x) for x in raw_inb) if v is not None]
                    else:
                        one = _parse_int_or_none(raw_inb)
                        inbounds = [] if one is None else [one]

                if not server_id:
                    continue

                if server_id not in merged:
                    merged[server_id] = '*' if inbounds == '*' else set(inbounds)
                else:
                    if merged[server_id] == '*' or inbounds == '*':
                        merged[server_id] = '*'
                    else:
                        for v in inbounds:
                            merged[server_id].add(int(v))

            return [
                {
                    'server_id': sid,
                    'inbounds': '*' if inb == '*' else sorted(list(inb)),
                }
                for sid, inb in merged.items()
            ]

        def _announcement_allows(ann: Announcement, *, server_id: int, inbound_id: int | None) -> bool:
            try:
                rules = _normalize_targets(
                    ann.targets,
                    fallback_all_servers=bool(ann.all_servers),
                    fallback_server_ids=[s.id for s in (ann.servers or [])],
                )
                if rules == '*':
                    return True
                for rule in rules:
                    try:
                        if int(rule.get('server_id')) != int(server_id):
                            continue
                    except Exception:
                        continue

                    inb = rule.get('inbounds')
                    if inb == '*':
                        return True
                    if inbound_id is None:
                        return True
                    if isinstance(inb, list) and any(int(x) == int(inbound_id) for x in inb if x is not None):
                        return True
                return False
            except Exception:
                # Fail closed (do not show announcement) on malformed targeting
                return False

        now_utc = datetime.utcnow()
        q = Announcement.query.filter(Announcement.start_at <= now_utc, Announcement.end_at >= now_utc)
        q = q.order_by(Announcement.created_at.desc())
        active = q.all()
        announcements_payload = [
            a.to_dict() for a in active
            if _announcement_allows(a, server_id=server.id, inbound_id=inbound_id)
            and not (getattr(a, 'hide_from_resellers', False) and sub_owner_reseller is not None)
        ]
    except Exception:
        announcements_payload = []

    # Active Online Chat snippet for subscription page
    active_online_chat_script = ''
    try:
        active_chat = OnlineChatScript.query.filter_by(is_active=True).order_by(OnlineChatScript.id.desc()).first()
        if active_chat and active_chat.script_code:
            nonce = getattr(g, 'csp_nonce', '') or ''
            snippet = (active_chat.script_code or '').strip()
            if nonce and snippet:
                snippet = re.sub(r'<script(?![^>]*\bnonce=)', f'<script nonce="{nonce}"', snippet, flags=re.IGNORECASE)
            active_online_chat_script = snippet
            if active_online_chat_script:
                g.allow_external_chat_widget = True
    except Exception:
        active_online_chat_script = ''

    backup_configs_payload = []
    try:
        from sqlalchemy import or_ as _or
        _bcs = BackupConfig.query.filter(
            BackupConfig.is_enabled == True,
            _or(BackupConfig.server_id == server.id, BackupConfig.server_id == None)
        ).order_by(BackupConfig.sort_order, BackupConfig.id).all()
        backup_configs_payload = [bc.to_dict() for bc in _bcs]
    except Exception:
        backup_configs_payload = []

    # Renewal packages to show on the sub page, based on the account owner.
    sub_packages_payload = _build_sub_page_packages(sub_owner_reseller)

    return render_template(
        'subscription.html',
        client=client_payload,
        apps=apps_payload,
        faqs=faqs_payload,
        support=support_info,
        channels=channels_info,
        announcements=announcements_payload,
        active_online_chat_script=active_online_chat_script,
        backup_configs=backup_configs_payload,
        sub_packages=sub_packages_payload,
        page_lang=page_lang,
        server_id=server_id,
        sub_id=normalized_sub_id,
    )

@app.route('/sub-manager')
@user_management_required
def sub_manager_page():
    user = db.session.get(Admin, session['admin_id'])
    
    _support_cfg = _get_system_configs_batch(['support_telegram', 'support_whatsapp', 'support_sms', 'channel_telegram', 'channel_whatsapp'])
    whatsapp_cfg = _get_whatsapp_runtime_settings()
    
    return render_template('sub_manager.html',
                         admin_username=session.get('admin_username'),
                         is_superadmin=session.get('is_superadmin', False),
                         role=session.get('role', 'admin'),
                         support_telegram=_support_cfg.get('support_telegram') or '',
                         support_whatsapp=_support_cfg.get('support_whatsapp') or '',
                         support_sms=_support_cfg.get('support_sms') or '',
                         channel_telegram=_support_cfg.get('channel_telegram') or '',
                         channel_whatsapp=_support_cfg.get('channel_whatsapp') or '',
                         whatsapp_deployment_region=whatsapp_cfg.get('deployment_region', 'outside'),
                         whatsapp_enabled=whatsapp_cfg.get('enabled_requested', False),
                         whatsapp_provider=whatsapp_cfg.get('provider', 'baileys'),
                         whatsapp_trigger_renew_success=whatsapp_cfg.get('trigger_renew_success', True),
                         whatsapp_trigger_welcome=whatsapp_cfg.get('trigger_welcome', False),
                         whatsapp_trigger_pre_expiry=whatsapp_cfg.get('trigger_pre_expiry', False),
                         whatsapp_min_interval_seconds=whatsapp_cfg.get('min_interval_seconds', 45),
                         whatsapp_daily_limit=whatsapp_cfg.get('daily_limit', 100),
                         whatsapp_pre_expiry_hours=whatsapp_cfg.get('pre_expiry_hours', 24),
                         whatsapp_retry_count=whatsapp_cfg.get('retry_count', 3),
                         whatsapp_backoff_seconds=whatsapp_cfg.get('backoff_seconds', 30),
                         whatsapp_circuit_breaker=whatsapp_cfg.get('circuit_breaker', True),
                         whatsapp_gateway_url=whatsapp_cfg.get('gateway_url', ''),
                         whatsapp_gateway_api_key=whatsapp_cfg.get('gateway_api_key', ''),
                         whatsapp_gateway_timeout_seconds=whatsapp_cfg.get('gateway_timeout_seconds', 10),
                         whatsapp_template_renew=whatsapp_cfg.get('template_renew', DEFAULT_WHATSAPP_TEMPLATE_RENEW),
                         whatsapp_template_welcome=whatsapp_cfg.get('template_welcome', DEFAULT_WHATSAPP_TEMPLATE_WELCOME),
                         whatsapp_template_pre_expiry=whatsapp_cfg.get('template_pre_expiry', DEFAULT_WHATSAPP_TEMPLATE_PRE_EXPIRY))

@app.route('/api/sub-apps', methods=['GET'])
def get_sub_apps():
    apps = SubAppConfig.query.order_by(SubAppConfig.display_order, SubAppConfig.id).all()
    return jsonify([a.to_dict() for a in apps])

@app.route('/api/sub-apps', methods=['POST'])
@user_management_required
def create_sub_app():
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'No data provided'}), 400
    
    # Auto-generate app_code if not provided
    app_code = data.get('app_code')
    if not app_code:
        app_code = str(uuid.uuid4())[:8]
        
    if SubAppConfig.query.filter_by(app_code=app_code).first():
        return jsonify({'success': False, 'error': 'App code already exists'}), 400
        
    # Sanitize descriptions to prevent XSS
    desc_fa = sanitize_html(data.get('description_fa', ''))
    desc_en = sanitize_html(data.get('description_en', ''))

    new_app = SubAppConfig(
        app_code=app_code,
        name=sanitize_html(data.get('name')),
        os_type=data.get('os_type', 'android'),
        is_enabled=data.get('is_enabled', True),
        title_fa=sanitize_html(data.get('title_fa')),
        description_fa=desc_fa,
        title_en=sanitize_html(data.get('title_en')),
        description_en=desc_en,
        download_link=data.get('download_link'),
        store_link=data.get('store_link'),
        tutorial_link=data.get('tutorial_link'),
        icon_url=data.get('icon_url'),
        is_recommended=data.get('is_recommended', False)
    )
    
    try:
        db.session.add(new_app)
        db.session.commit()
        return jsonify({'success': True, 'app': new_app.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sub-apps/<int:app_id>', methods=['PUT'])
@user_management_required
def update_sub_app(app_id):
    app_config = db.session.get(SubAppConfig, app_id)
    if not app_config:
        return jsonify({'success': False, 'error': 'App not found'}), 404
        
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'No data provided'}), 400
        
    # Check if app_code is being changed and if it conflicts
    new_app_code = data.get('app_code')
    if new_app_code and new_app_code != app_config.app_code:
        if SubAppConfig.query.filter_by(app_code=new_app_code).first():
            return jsonify({'success': False, 'error': 'App code already exists'}), 400
        app_config.app_code = new_app_code
        
    if 'name' in data: app_config.name = sanitize_html(data['name'])
    if 'os_type' in data: app_config.os_type = data['os_type']
    if 'is_enabled' in data: app_config.is_enabled = data['is_enabled']
    if 'title_fa' in data: app_config.title_fa = sanitize_html(data['title_fa'])
    if 'description_fa' in data:
        app_config.description_fa = sanitize_html(data['description_fa'])
    if 'title_en' in data: app_config.title_en = sanitize_html(data['title_en'])
    if 'description_en' in data:
        app_config.description_en = sanitize_html(data['description_en'])
    if 'download_link' in data: app_config.download_link = data['download_link']
    if 'store_link' in data: app_config.store_link = data['store_link']
    if 'tutorial_link' in data: app_config.tutorial_link = data['tutorial_link']
    if 'icon_url' in data: app_config.icon_url = data['icon_url']
    if 'is_recommended' in data: app_config.is_recommended = data['is_recommended']
    if 'display_order' in data:
        try:
            app_config.display_order = int(data['display_order'])
        except (TypeError, ValueError):
            pass

    try:
        db.session.commit()
        return jsonify({'success': True, 'app': app_config.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/sub-apps/reorder', methods=['POST'])
@user_management_required
def reorder_sub_apps():
    """Accept [{id, display_order}, ...] and bulk-update ordering."""
    items = request.get_json() or []
    if not isinstance(items, list):
        return jsonify({'success': False, 'error': 'Expected a list'}), 400
    try:
        for item in items:
            app_id = int(item.get('id') or 0)
            order = int(item.get('display_order') or 0)
            if app_id:
                SubAppConfig.query.filter_by(id=app_id).update({'display_order': order})
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/sub-apps/<int:app_id>', methods=['DELETE'])
@user_management_required
def delete_sub_app(app_id):
    app_config = db.session.get(SubAppConfig, app_id)
    if not app_config:
        return jsonify({'success': False, 'error': 'App not found'}), 404
        
    try:
        db.session.delete(app_config)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

# FAQ APIs
@app.route('/api/faqs', methods=['GET'])
@user_management_required
def get_faqs():
    faqs = FAQ.query.order_by(FAQ.created_at.desc()).all()
    resp = jsonify([f.to_dict() for f in faqs])
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return resp

@app.route('/api/faqs', methods=['POST'])
@user_management_required
def create_faq():
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'No data provided'}), 400
    
    if not data.get('title'):
        return jsonify({'success': False, 'error': 'Title is required'}), 400
        
    # Sanitize HTML content to prevent XSS
    content = sanitize_html(
        data.get('content', ''),
        tags=ALLOWED_FAQ_TAGS,
        attributes=ALLOWED_FAQ_ATTRIBUTES,
        styles=ALLOWED_FAQ_STYLES
    )

    new_faq = FAQ(
        title=sanitize_html(data.get('title')),
        content=content,
        image_url=data.get('image_url'),
        video_url=data.get('video_url'),
        platform=data.get('platform', 'android'),
        is_enabled=data.get('is_enabled', True)
    )
    
    try:
        db.session.add(new_faq)
        db.session.commit()
        return jsonify({'success': True, 'faq': new_faq.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/faqs/<int:faq_id>', methods=['PUT'])
@user_management_required
def update_faq(faq_id):
    faq = db.session.get(FAQ, faq_id)
    if not faq:
        return jsonify({'success': False, 'error': 'FAQ not found'}), 404
        
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'No data provided'}), 400
        
    if 'title' in data: faq.title = sanitize_html(data['title'])
    if 'content' in data:
        # Sanitize HTML content to prevent XSS
        faq.content = sanitize_html(
            data['content'],
            tags=ALLOWED_FAQ_TAGS,
            attributes=ALLOWED_FAQ_ATTRIBUTES,
            styles=ALLOWED_FAQ_STYLES
        )
    if 'image_url' in data: faq.image_url = data['image_url']
    if 'video_url' in data: faq.video_url = data['video_url']
    if 'platform' in data: faq.platform = data['platform']
    if 'is_enabled' in data: faq.is_enabled = data['is_enabled']
    
    try:
        db.session.commit()
        return jsonify({'success': True, 'faq': faq.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/faqs/<int:faq_id>', methods=['DELETE'])
@user_management_required
def delete_faq(faq_id):
    faq = db.session.get(FAQ, faq_id)
    if not faq:
        return jsonify({'success': False, 'error': 'FAQ not found'}), 404
        
    try:
        db.session.delete(faq)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


# Announcement APIs (Sub Manager)
@app.route('/api/announcements', methods=['GET'])
@user_management_required
def get_announcements():
    items = Announcement.query.order_by(Announcement.created_at.desc()).all()
    resp = jsonify([a.to_dict() for a in items])
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return resp


def _parse_announcement_payload(data: dict) -> tuple[dict | None, str | None]:
    if not data:
        return None, 'No data provided'

    message = (data.get('message') or '').strip()
    if not message:
        return None, 'Message is required'

    start_at_iso_raw = (data.get('start_at') or '').strip()
    end_at_iso_raw = (data.get('end_at') or '').strip()
    start_at_jalali_raw = (data.get('start_at_jalali') or '').strip()
    end_at_jalali_raw = (data.get('end_at_jalali') or '').strip()

    start_at = parse_iso_datetime(start_at_iso_raw) if start_at_iso_raw else None
    end_at = parse_iso_datetime(end_at_iso_raw) if end_at_iso_raw else None
    if not start_at and start_at_jalali_raw:
        start_at = parse_jalali_date(start_at_jalali_raw)
    if not end_at and end_at_jalali_raw:
        end_at = parse_jalali_date(end_at_jalali_raw)

    if not start_at or not end_at:
        return None, 'Start and End datetime are required'
    if start_at > end_at:
        return None, 'Start datetime must be before End datetime'

    def _parse_int_or_none(val):
        if val is None:
            return None
        try:
            return int(val)
        except Exception:
            try:
                return int(float(str(val).strip()))
            except Exception:
                return None

    raw_targets = data.get('targets')
    all_servers_raw = data.get('all_servers', None)
    server_ids_raw = data.get('server_ids') or []
    if not isinstance(server_ids_raw, list):
        server_ids_raw = []

    normalized_server_ids: list[int] = []
    for sid in server_ids_raw:
        parsed = _parse_int_or_none(sid)
        if parsed is not None:
            normalized_server_ids.append(parsed)
    normalized_server_ids = list(dict.fromkeys(normalized_server_ids))

    def _normalize_targets(raw):
        if raw is None:
            return None
        if raw == '*':
            return '*'
        if isinstance(raw, str):
            trimmed = raw.strip()
            if trimmed == '*':
                return '*'
            if not trimmed:
                return []
            try:
                parsed = json.loads(trimmed)
                return _normalize_targets(parsed)
            except Exception:
                # Back-compat: comma-separated server ids
                ids = []
                for part in trimmed.split(','):
                    parsed_id = _parse_int_or_none(part)
                    if parsed_id is not None:
                        ids.append(parsed_id)
                return [{'server_id': sid, 'inbounds': '*'} for sid in ids]

        entries = raw if isinstance(raw, list) else [raw]
        merged: dict[int, str | set[int]] = {}
        for item in entries:
            server_id = None
            inbounds: str | list[int] = '*'
            if isinstance(item, (int, float, str)):
                server_id = _parse_int_or_none(item)
                inbounds = '*'
            elif isinstance(item, dict):
                server_id = _parse_int_or_none(item.get('server_id') or item.get('server') or item.get('id'))
                raw_inb = item.get('inbounds')
                if raw_inb == '*' or (isinstance(raw_inb, str) and raw_inb.strip() == '*') or raw_inb is None:
                    inbounds = '*'
                elif isinstance(raw_inb, list):
                    inbounds = [v for v in (_parse_int_or_none(x) for x in raw_inb) if v is not None]
                else:
                    one = _parse_int_or_none(raw_inb)
                    inbounds = [] if one is None else [one]

            if not server_id:
                continue

            if server_id not in merged:
                merged[server_id] = '*' if inbounds == '*' else set(inbounds)
            else:
                if merged[server_id] == '*' or inbounds == '*':
                    merged[server_id] = '*'
                else:
                    for v in inbounds:
                        merged[server_id].add(int(v))

        return [
            {'server_id': sid, 'inbounds': '*' if inb == '*' else sorted(list(inb))}
            for sid, inb in merged.items()
        ]

    normalized_targets = _normalize_targets(raw_targets)

    # Back-compat: if targets not provided, derive from all_servers/server_ids
    if normalized_targets is None:
        all_servers = bool(all_servers_raw) if all_servers_raw is not None else True
        if all_servers:
            normalized_targets = '*'
        else:
            normalized_targets = [{'server_id': sid, 'inbounds': '*'} for sid in normalized_server_ids]

    if normalized_targets == '*':
        targets_str = '*'
        all_servers = True
        derived_server_ids: list[int] = []
    else:
        try:
            targets_str = json.dumps(normalized_targets, ensure_ascii=False)
        except Exception:
            targets_str = '[]'
        all_servers = False
        derived_server_ids = []
        for rule in (normalized_targets or []):
            sid = _parse_int_or_none((rule or {}).get('server_id'))
            if sid is not None:
                derived_server_ids.append(sid)
        derived_server_ids = list(dict.fromkeys(derived_server_ids))

    if not all_servers and not derived_server_ids:
        return None, 'Select at least one server (or choose all)'

    payload = {
        'message': message,
        'targets': targets_str,
        'all_servers': all_servers,
        'start_at': start_at,
        'end_at': end_at,
        'server_ids': derived_server_ids,
    }
    return payload, None


@app.route('/api/announcements', methods=['POST'])
@user_management_required
def create_announcement():
    data = request.get_json() or {}
    payload, err = _parse_announcement_payload(data)
    if err:
        return jsonify({'success': False, 'error': err}), 400

    user = db.session.get(Admin, session.get('admin_id')) if session.get('admin_id') else None
    created_by = (getattr(user, 'username', None) or session.get('admin_username') or '').strip() or None

    _ANN_TAGS = ['b','strong','i','em','u','br','p','div','span','ul','ol','li',
                 'a','img','video','source']
    _ANN_ATTRS = {'a': ['href','class','target'], 'span': ['style'], 'div': ['style','class'],
                  'img': ['src','alt','style','width','height'],
                  'video': ['src','controls','style','width','height','preload'],
                  'source': ['src','type'], '*': []}
    _ANN_STYLES = ['color','background-color','font-size','text-align','direction',
                   'max-width','width','height','border-radius','padding','margin',
                   'display','text-decoration','font-weight']
    ann = Announcement(
        message=sanitize_html(payload['message'], tags=_ANN_TAGS, attributes=_ANN_ATTRS, styles=_ANN_STYLES),
        all_servers=payload['all_servers'],
        targets=payload['targets'],
        start_at=payload['start_at'],
        end_at=payload['end_at'],
        created_by=created_by,
        hide_from_resellers=bool(data.get('hide_from_resellers', False)),
        is_popup=bool(data.get('is_popup', False)),
        button_text=(str(data.get('button_text') or '').strip()[:120] or None),
    )

    if not payload['all_servers']:
        servers = Server.query.filter(Server.id.in_(payload['server_ids'])).all() if payload['server_ids'] else []
        ann.servers = servers

    try:
        db.session.add(ann)
        db.session.commit()
        return jsonify({'success': True, 'announcement': ann.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/announcements/<int:announcement_id>', methods=['PUT'])
@user_management_required
def update_announcement(announcement_id):
    ann = db.session.get(Announcement, announcement_id)
    if not ann:
        return jsonify({'success': False, 'error': 'Announcement not found'}), 404

    data = request.get_json() or {}
    payload, err = _parse_announcement_payload(data)
    if err:
        return jsonify({'success': False, 'error': err}), 400

    _ANN_TAGS = ['b','strong','i','em','u','br','p','div','span','ul','ol','li',
                 'a','img','video','source']
    _ANN_ATTRS = {'a': ['href','class','target'], 'span': ['style'], 'div': ['style','class'],
                  'img': ['src','alt','style','width','height'],
                  'video': ['src','controls','style','width','height','preload'],
                  'source': ['src','type'], '*': []}
    _ANN_STYLES = ['color','background-color','font-size','text-align','direction',
                   'max-width','width','height','border-radius','padding','margin',
                   'display','text-decoration','font-weight']
    ann.message = sanitize_html(payload['message'], tags=_ANN_TAGS, attributes=_ANN_ATTRS, styles=_ANN_STYLES)
    ann.all_servers = payload['all_servers']
    ann.targets = payload['targets']
    ann.start_at = payload['start_at']
    ann.end_at = payload['end_at']
    if 'hide_from_resellers' in data:
        ann.hide_from_resellers = bool(data['hide_from_resellers'])
    if 'is_popup' in data:
        ann.is_popup = bool(data['is_popup'])
    if 'button_text' in data:
        ann.button_text = (str(data.get('button_text') or '').strip()[:120] or None)

    if ann.all_servers:
        ann.servers = []
    else:
        servers = Server.query.filter(Server.id.in_(payload['server_ids'])).all() if payload['server_ids'] else []
        ann.servers = servers

    try:
        db.session.commit()
        return jsonify({'success': True, 'announcement': ann.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/announcements/<int:announcement_id>', methods=['DELETE'])
@user_management_required
def delete_announcement(announcement_id):
    ann = db.session.get(Announcement, announcement_id)
    if not ann:
        return jsonify({'success': False, 'error': 'Announcement not found'}), 404

    try:
        db.session.delete(ann)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


# Online Chat Scripts APIs (Sub Manager)
def _parse_online_chat_payload(data: dict) -> tuple[dict | None, str | None]:
    if not data:
        return None, 'No data provided'

    name = (data.get('name') or '').strip()
    script_code = (data.get('script_code') or '').strip()

    if not name:
        return None, 'Name is required'
    if not script_code:
        return None, 'Script code is required'
    if len(name) > 120:
        return None, 'Name is too long'
    if len(script_code) > 50000:
        return None, 'Script code is too long'

    return {
        'name': name,
        'script_code': script_code,
    }, None


@app.route('/api/online-chat-scripts', methods=['GET'])
@user_management_required
def get_online_chat_scripts():
    items = OnlineChatScript.query.order_by(OnlineChatScript.created_at.desc()).all()
    return jsonify([item.to_dict() for item in items])


@app.route('/api/online-chat-scripts', methods=['POST'])
@user_management_required
def create_online_chat_script():
    data = request.get_json() or {}
    payload, err = _parse_online_chat_payload(data)
    if err:
        return jsonify({'success': False, 'error': err}), 400

    user = db.session.get(Admin, session.get('admin_id')) if session.get('admin_id') else None
    created_by = (getattr(user, 'username', None) or session.get('admin_username') or '').strip() or None

    item = OnlineChatScript(
        name=sanitize_html(payload['name']),
        script_code=payload['script_code'],
        is_active=False,
        created_by=created_by,
    )

    try:
        db.session.add(item)
        db.session.commit()
        return jsonify({'success': True, 'item': item.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/online-chat-scripts/<int:item_id>', methods=['PUT'])
@user_management_required
def update_online_chat_script(item_id):
    item = db.session.get(OnlineChatScript, item_id)
    if not item:
        return jsonify({'success': False, 'error': 'Script not found'}), 404

    data = request.get_json() or {}
    payload, err = _parse_online_chat_payload(data)
    if err:
        return jsonify({'success': False, 'error': err}), 400

    item.name = sanitize_html(payload['name'])
    item.script_code = payload['script_code']

    try:
        db.session.commit()
        return jsonify({'success': True, 'item': item.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/online-chat-scripts/<int:item_id>', methods=['DELETE'])
@user_management_required
def delete_online_chat_script(item_id):
    item = db.session.get(OnlineChatScript, item_id)
    if not item:
        return jsonify({'success': False, 'error': 'Script not found'}), 404

    try:
        db.session.delete(item)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/online-chat-scripts/<int:item_id>/activate', methods=['POST'])
@user_management_required
def activate_online_chat_script(item_id):
    item = db.session.get(OnlineChatScript, item_id)
    if not item:
        return jsonify({'success': False, 'error': 'Script not found'}), 404

    try:
        OnlineChatScript.query.update({OnlineChatScript.is_active: False})
        item.is_active = True
        db.session.commit()
        return jsonify({'success': True, 'item': item.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/backup-configs', methods=['GET'])
@user_management_required
def get_backup_configs():
    items = BackupConfig.query.order_by(BackupConfig.sort_order, BackupConfig.id).all()
    servers = Server.query.order_by(Server.name).all()
    return jsonify({
        'success': True,
        'items': [i.to_dict() for i in items],
        'servers': [{'id': s.id, 'name': s.name} for s in servers],
        'default_description': BackupConfig.DEFAULT_DESCRIPTION,
    })


@app.route('/api/backup-configs', methods=['POST'])
@user_management_required
def create_backup_config():
    data = request.get_json(force=True) or {}
    title = (data.get('title') or '').strip()
    config_url = (data.get('config_url') or '').strip()
    if not title or not config_url:
        return jsonify({'success': False, 'error': 'Title and config URL are required'}), 400
    item = BackupConfig(
        server_id=data.get('server_id') or None,
        title=title,
        config_url=config_url,
        description=(data.get('description') or '').strip(),
        is_enabled=bool(data.get('is_enabled', True)),
        sort_order=int(data.get('sort_order') or 0),
    )
    try:
        db.session.add(item)
        db.session.commit()
        return jsonify({'success': True, 'item': item.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/backup-configs/<int:item_id>', methods=['PUT'])
@user_management_required
def update_backup_config(item_id):
    item = db.session.get(BackupConfig, item_id)
    if not item:
        return jsonify({'success': False, 'error': 'Not found'}), 404
    data = request.get_json(force=True) or {}
    if 'title' in data:
        item.title = (data['title'] or '').strip()
    if 'config_url' in data:
        item.config_url = (data['config_url'] or '').strip()
    if 'description' in data:
        item.description = (data['description'] or '').strip()
    if 'is_enabled' in data:
        item.is_enabled = bool(data['is_enabled'])
    if 'server_id' in data:
        item.server_id = data['server_id'] or None
    if 'sort_order' in data:
        item.sort_order = int(data.get('sort_order') or 0)
    item.updated_at = datetime.utcnow()
    try:
        db.session.commit()
        return jsonify({'success': True, 'item': item.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/backup-configs/<int:item_id>', methods=['DELETE'])
@user_management_required
def delete_backup_config(item_id):
    item = db.session.get(BackupConfig, item_id)
    if not item:
        return jsonify({'success': False, 'error': 'Not found'}), 404
    try:
        db.session.delete(item)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/upload', methods=['POST'])
@user_management_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No selected file'}), 400

    if file:
        file.seek(0, os.SEEK_END)
        file_length = file.tell()
        file.seek(0)
        if file_length > MAX_FILE_SIZE:
            return jsonify({'success': False, 'error': 'File too large'}), 413

        filename = secure_filename(f"{uuid.uuid4().hex[:8]}_{file.filename}")
        upload_folder = os.path.join(app.static_folder, 'uploads')
        os.makedirs(upload_folder, exist_ok=True)
        file.save(os.path.join(upload_folder, filename))
        return jsonify({'success': True, 'url': f'/static/uploads/{filename}'})


# ── App File Manager ──────────────────────────────────────────────────────────
# Separate from the general /api/upload — restricted to superadmin,
# larger size limits, strict whitelist, stored in static/app-files/.

_APP_FILE_MAX_BYTES  = 500 * 1024 * 1024   # 500 MB (covers large installers + videos)
_APP_FILES_DIR_NAME  = 'app-files'

# Extension → category mapping (whitelist)
_ALLOWED_APP_EXTS = {
    # Installers
    '.apk':  'android', '.aab':  'android',
    '.exe':  'windows', '.msi':  'windows',
    '.dmg':  'macos',   '.pkg':  'macos',
    '.deb':  'linux',   '.rpm':  'linux',   '.appimage': 'linux',
    # Archives / cross-platform
    '.zip':  'archive', '.tar':  'archive', '.gz': 'archive',
    # Videos
    '.mp4':  'video',   '.webm': 'video',   '.mkv': 'video', '.mov': 'video',
    # Images (icons / screenshots)
    '.png':  'image',   '.jpg':  'image',   '.jpeg': 'image', '.webp': 'image',
    '.svg':  'image',
}


def _app_files_dir() -> str:
    """Return (and create if needed) the app-files storage directory.
    Raises RuntimeError with a descriptive message on permission failure.
    """
    d = os.path.join(app.static_folder, _APP_FILES_DIR_NAME)
    try:
        os.makedirs(d, exist_ok=True)
    except OSError as e:
        raise RuntimeError(
            f"Cannot create upload directory '{d}': {e}. "
            "Run: mkdir -p {d} && chown <user> {d} && chmod 755 {d}"
        ) from e
    if not os.access(d, os.W_OK):
        raise RuntimeError(
            f"Upload directory '{d}' exists but is not writable. "
            f"Run: chown $(whoami) '{d}' && chmod 755 '{d}'"
        )
    return d


def _safe_app_file_path(filename: str) -> str | None:
    """Return absolute path if filename stays inside app-files dir, else None."""
    base = os.path.realpath(_app_files_dir())
    target = os.path.realpath(os.path.join(base, filename))
    return target if target.startswith(base + os.sep) else None


@app.route('/api/app-files/health', methods=['GET'])
@superadmin_required
def app_files_health():
    """Diagnostic endpoint — returns directory status and write-test result."""
    static_folder = app.static_folder or '(not set)'
    d = os.path.join(static_folder, _APP_FILES_DIR_NAME)
    info = {
        'static_folder': static_folder,
        'target_dir': d,
        'exists': os.path.isdir(d),
        'writable': os.access(d, os.W_OK) if os.path.isdir(d) else False,
        'file_count': 0,
        'write_test': None,
        'error': None,
    }
    try:
        real_d = _app_files_dir()
        info['target_dir'] = real_d
        info['exists'] = True
        info['writable'] = True
        info['file_count'] = sum(1 for f in os.listdir(real_d) if os.path.isfile(os.path.join(real_d, f)))
        # Write test
        test_path = os.path.join(real_d, f'.write_test_{uuid.uuid4().hex[:6]}')
        with open(test_path, 'w') as t:
            t.write('ok')
        os.remove(test_path)
        info['write_test'] = 'passed'
        info['success'] = True
    except Exception as e:
        info['error'] = str(e)
        info['success'] = False
        app.logger.error(f'app_files_health error: {e}')
    return jsonify(info)


@app.route('/api/app-files/setup', methods=['POST'])
@superadmin_required
def app_files_setup():
    """Auto-create upload directory, fix permissions, run write test. Returns step-by-step diagnostics."""
    static_folder = app.static_folder or ''
    d = os.path.join(static_folder, _APP_FILES_DIR_NAME)
    steps = []

    def _step(name, ok, detail='', fix=''):
        steps.append({'name': name, 'ok': ok, 'detail': detail, 'fix': fix})

    if not os.path.isdir(static_folder):
        _step('Static folder exists', False,
              f"'{static_folder}' does not exist",
              f"mkdir -p '{static_folder}'")
        return jsonify({'success': False, 'steps': steps, 'error': 'Static folder missing'})
    _step('Static folder exists', True, static_folder)

    try:
        os.makedirs(d, exist_ok=True)
        _step('Create upload directory', True, d)
    except OSError as e:
        fix = f"mkdir -p '{d}' && chown $(whoami) '{d}' && chmod 755 '{d}'"
        _step('Create upload directory', False, str(e), fix)
        return jsonify({'success': False, 'steps': steps, 'error': str(e)})

    if not os.access(d, os.W_OK):
        try:
            os.chmod(d, 0o755)
        except OSError:
            pass
        if os.access(d, os.W_OK):
            _step('Set permissions (755)', True, 'Applied successfully')
        else:
            fix = f"sudo chown $(whoami) '{d}' && sudo chmod 755 '{d}'"
            _step('Set permissions (755)', False, 'Directory still not writable — manual fix required', fix)
            return jsonify({'success': False, 'steps': steps, 'error': fix})
    else:
        _step('Directory writable', True)

    test_path = os.path.join(d, f'.write_test_{uuid.uuid4().hex[:6]}')
    try:
        with open(test_path, 'w') as _t:
            _t.write('ok')
        os.remove(test_path)
        _step('Write test', True, 'Temporary file written and removed')
    except Exception as e:
        fix = f"sudo chown -R $(whoami) '{d}'"
        _step('Write test', False, str(e), fix)
        return jsonify({'success': False, 'steps': steps, 'error': str(e)})

    app.logger.info(f"app_files_setup by {session.get('admin_username', '?')}: {d}")
    return jsonify({'success': True, 'steps': steps, 'directory': d})


@app.route('/api/app-files', methods=['GET'])
@superadmin_required
def list_app_files():
    try:
        base = _app_files_dir()
    except RuntimeError as e:
        app.logger.error(f'list_app_files dir error: {e}')
        return jsonify({'success': False, 'error': str(e)}), 500
    files = []
    try:
        for fname in sorted(os.listdir(base)):
            fpath = os.path.join(base, fname)
            if not os.path.isfile(fpath):
                continue
            ext = os.path.splitext(fname)[1].lower()
            stat = os.stat(fpath)
            files.append({
                'name': fname,
                'size': stat.st_size,
                'modified': int(stat.st_mtime),
                'url': f'/static/{_APP_FILES_DIR_NAME}/{fname}',
                'category': _ALLOWED_APP_EXTS.get(ext, 'other'),
                'ext': ext.lstrip('.'),
            })
    except Exception as e:
        app.logger.error(f'list_app_files error: {e}')
        return jsonify({'success': False, 'error': str(e)}), 500
    return jsonify({'success': True, 'files': files})


@app.route('/api/app-files/upload', methods=['POST'])
@app.route('/api/app-files/save', methods=['POST'])
@superadmin_required
def upload_app_file():
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'}), 400

    f = request.files['file']
    if not f or f.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'}), 400

    original = secure_filename(f.filename)
    if not original:
        return jsonify({'success': False, 'error': 'Invalid filename'}), 400

    ext = os.path.splitext(original)[1].lower()
    if ext not in _ALLOWED_APP_EXTS:
        return jsonify({'success': False, 'error': f'File type not allowed: {ext or "(none)"}'}), 415

    # Use Content-Length header first (fast, no extra read); fall back to seek/tell
    size = request.content_length or 0
    if size == 0:
        try:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(0)
        except Exception:
            size = 0

    if size > _APP_FILE_MAX_BYTES:
        return jsonify({'success': False, 'error': f'File too large ({size // (1024*1024)} MB). Max 500 MB.'}), 413

    # Verify upload directory is accessible — return a clear 500 (not a mystery error)
    try:
        base_dir = _app_files_dir()
    except RuntimeError as e:
        app.logger.error(f'upload_app_file dir error: {e}')
        return jsonify({'success': False, 'error': str(e)}), 500

    uid = uuid.uuid4().hex[:10]
    safe_name = f"{uid}_{original}"
    dest = os.path.join(base_dir, safe_name)

    try:
        f.save(dest)
    except Exception as e:
        app.logger.error(f'upload_app_file save error ({dest}): {e}')
        return jsonify({'success': False, 'error': f'Save failed: {e}'}), 500

    try:
        saved_size = os.stat(dest).st_size
        modified   = int(os.stat(dest).st_mtime)
    except OSError:
        saved_size, modified = size, int(__import__('time').time())

    category = _ALLOWED_APP_EXTS.get(ext, 'other')
    app.logger.info(
        f"App file uploaded by {session.get('admin_username','?')}: "
        f"{safe_name} ({saved_size} bytes, category={category})"
    )
    return jsonify({
        'success': True,
        'file': {
            'name': safe_name,
            'size': saved_size,
            'modified': modified,
            'url': f'/static/{_APP_FILES_DIR_NAME}/{safe_name}',
            'category': category,
            'ext': ext.lstrip('.'),
        }
    })


@app.route('/api/app-files/<path:filename>', methods=['DELETE'])
@superadmin_required
def delete_app_file(filename):
    # Prevent path traversal
    safe_name = secure_filename(filename)
    fpath = _safe_app_file_path(safe_name)
    if not fpath or not os.path.isfile(fpath):
        return jsonify({'success': False, 'error': 'File not found'}), 404
    try:
        os.remove(fpath)
        app.logger.info(f"App file deleted by {session.get('admin_username')}: {safe_name}")
        return jsonify({'success': True})
    except Exception as e:
        app.logger.error(f'delete_app_file error: {e}')
        return jsonify({'success': False, 'error': 'Delete failed'}), 500


# Startup: ensure app-files directory exists and is writable
with app.app_context():
    try:
        _app_files_dir()
        print("[startup] app-files upload directory is ready")
    except RuntimeError as _appfiles_err:
        print(f"[startup] WARNING: app-files directory not ready: {_appfiles_err}")
        print("[startup] File uploads will fail. Use the 'Fix Setup' button in File Manager, or run:")
        print(f"[startup]   mkdir -p '{os.path.join(app.static_folder or '', _APP_FILES_DIR_NAME)}' && chmod 755 <dir>")


# ── SSL startup migration ─────────────────────────────────────────────────────
# When upgrading from a version that didn't copy certs to /etc/ssl/eve-manager/,
# we try to do the copy automatically so the export feature works immediately.
# This is silent — failure never blocks startup.
with app.app_context():
    try:
        _ssl_dest_cert = '/etc/ssl/eve-manager/fullchain.pem'
        _ssl_dest_key  = '/etc/ssl/eve-manager/privkey.pem'
        _need_copy = not (os.path.isfile(_ssl_dest_cert) and os.access(_ssl_dest_cert, os.R_OK)
                         and os.path.isfile(_ssl_dest_key) and os.access(_ssl_dest_key, os.R_OK))

        if _need_copy:
            # Try to find source paths (nginx config → letsencrypt glob)
            import re as _re, glob as _gl
            _src_cert = _src_key = ''

            # 1. Read nginx config
            for _nc in ['/etc/nginx/sites-available/eve-manager',
                        '/etc/nginx/sites-enabled/eve-manager',
                        '/etc/nginx/sites-available/eve-xui-manager']:
                if not os.path.isfile(_nc):
                    continue
                try:
                    with open(_nc, 'r', errors='ignore') as _nf:
                        _conf = _nf.read()
                    _cm = _re.search(r'ssl_certificate\s+([^;]+);', _conf)
                    _km = _re.search(r'ssl_certificate_key\s+([^;]+);', _conf)
                    if _cm and _km:
                        _src_cert = _cm.group(1).strip()
                        _src_key  = _km.group(1).strip()
                        break
                except Exception:
                    pass

            # 2. Fallback: letsencrypt glob
            if not _src_cert:
                for _lc in sorted(_gl.glob('/etc/letsencrypt/live/*/fullchain.pem')):
                    _src_cert = _lc
                    _src_key  = os.path.join(os.path.dirname(_lc), 'privkey.pem')
                    break

            if _src_cert and _src_key and os.path.isfile(_src_cert) and os.path.isfile(_src_key):
                _app_user = os.environ.get('APP_USER', 'evemgr')
                _copy_cmds = [
                    ['sudo', 'mkdir', '-p', '/etc/ssl/eve-manager'],
                    ['sudo', 'cp', '-f', _src_cert, _ssl_dest_cert],
                    ['sudo', 'cp', '-f', _src_key,  _ssl_dest_key],
                    ['sudo', 'chown', f'{_app_user}:{_app_user}', _ssl_dest_cert, _ssl_dest_key],
                    ['sudo', 'chmod', '644', _ssl_dest_cert],
                    ['sudo', 'chmod', '600', _ssl_dest_key],
                ]
                _copy_ok = True
                for _cmd in _copy_cmds:
                    _r = subprocess.run(_cmd, capture_output=True, timeout=10)
                    if _r.returncode != 0:
                        _copy_ok = False
                        break

                if _copy_ok:
                    # Update DB paths to the new readable location
                    for _k, _v in [('ssl_cert_path', _ssl_dest_cert), ('ssl_key_path', _ssl_dest_key)]:
                        _row = db.session.get(SystemSetting, _k) or SystemSetting(key=_k, value=_v)
                        _row.value = _v
                        db.session.merge(_row)
                    db.session.commit()
                    print(f"[startup] SSL certs migrated → {'/etc/ssl/eve-manager/'}")
                else:
                    print("[startup] SSL cert migration failed (sudo not configured yet — use Settings → SSL → Sync)")
            else:
                print("[startup] SSL not detected or not yet configured — skipping cert migration")
    except Exception as _ssl_migrate_err:
        print(f"[startup] SSL migration skipped: {_ssl_migrate_err}")


@app.route('/api/system-config', methods=['POST'])
@superadmin_required
def update_system_config():
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'No data provided'}), 400
        
    try:
        normalized_region = None
        if WHATSAPP_DEPLOYMENT_REGION_KEY in data:
            normalized_region = _normalize_whatsapp_region(data.get(WHATSAPP_DEPLOYMENT_REGION_KEY))

        for key, value in data.items():
            config = db.session.get(SystemConfig, key)

            if key == WHATSAPP_DEPLOYMENT_REGION_KEY:
                sanitized_value = _normalize_whatsapp_region(value)
            elif key == WHATSAPP_PROVIDER_KEY:
                sanitized_value = _normalize_whatsapp_provider(value)
            elif key in {
                WHATSAPP_ENABLED_KEY,
                WHATSAPP_TRIGGER_RENEW_KEY,
                WHATSAPP_TRIGGER_WELCOME_KEY,
                WHATSAPP_TRIGGER_PRE_EXPIRY_KEY,
                WHATSAPP_CIRCUIT_BREAKER_KEY,
            }:
                sanitized_value = 'true' if _parse_bool(value) else 'false'
            elif key == WHATSAPP_MIN_INTERVAL_SECONDS_KEY:
                sanitized_value = str(_parse_int(value, 45, min_value=45, max_value=3600))
            elif key == WHATSAPP_DAILY_LIMIT_KEY:
                sanitized_value = str(_parse_int(value, 100, min_value=1, max_value=50000))
            elif key == WHATSAPP_PRE_EXPIRY_HOURS_KEY:
                sanitized_value = str(_parse_int(value, 24, min_value=1, max_value=720))
            elif key == WHATSAPP_RETRY_COUNT_KEY:
                sanitized_value = str(_parse_int(value, 3, min_value=0, max_value=10))
            elif key == WHATSAPP_BACKOFF_SECONDS_KEY:
                sanitized_value = str(_parse_int(value, 30, min_value=5, max_value=3600))
            elif key == WHATSAPP_GATEWAY_URL_KEY:
                sanitized_value = _normalize_whatsapp_gateway_url(value)
            elif key == WHATSAPP_GATEWAY_API_KEY:
                sanitized_value = sanitize_html(str(value))[:512]
            elif key == WHATSAPP_GATEWAY_TIMEOUT_KEY:
                sanitized_value = str(_parse_int(value, 10, min_value=3, max_value=60))
            elif key in {WHATSAPP_TEMPLATE_RENEW_KEY, WHATSAPP_TEMPLATE_WELCOME_KEY, WHATSAPP_TEMPLATE_PRE_EXPIRY_KEY}:
                sanitized_value = sanitize_html(str(value))[:2000]
            else:
                sanitized_value = sanitize_html(str(value))

            if config:
                config.value = sanitized_value
            else:
                config = SystemConfig(key=key, value=sanitized_value)
                db.session.add(config)

        effective_region = normalized_region
        if effective_region is None:
            effective_region = _normalize_whatsapp_region(_get_system_config_text(WHATSAPP_DEPLOYMENT_REGION_KEY, 'outside'))

        warning = None
        if effective_region == 'iran':
            enabled_conf = db.session.get(SystemConfig, WHATSAPP_ENABLED_KEY)
            if enabled_conf:
                enabled_conf.value = 'false'
            else:
                db.session.add(SystemConfig(key=WHATSAPP_ENABLED_KEY, value='false'))
            warning = 'WhatsApp automation is not available when the panel is deployed in Iran.'
        
        db.session.commit()
        return jsonify({'success': True, 'warning': warning})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/whatsapp/test-connection', methods=['POST'])
@superadmin_required
def test_whatsapp_connection():
    runtime_cfg = _get_whatsapp_runtime_settings()
    if runtime_cfg.get('deployment_region') == 'iran':
        return jsonify({
            'success': False,
            'error': 'WhatsApp automation is not available when the panel is deployed in Iran.',
            'blocked_reason': 'deployment_in_iran'
        }), 400

    gateway_url = (runtime_cfg.get('gateway_url') or '').strip()
    if not gateway_url:
        return jsonify({'success': False, 'error': 'WhatsApp gateway URL is not configured.'}), 400

    ok, status_code, error_reason = _probe_whatsapp_gateway(
        gateway_url,
        timeout_seconds=int(runtime_cfg.get('gateway_timeout_seconds') or 10),
        api_key=(runtime_cfg.get('gateway_api_key') or '').strip(),
    )

    if ok:
        return jsonify({
            'success': True,
            'status_code': status_code,
            'message': 'Gateway reachable'
        })

    if status_code is not None:
        return jsonify({
            'success': False,
            'status_code': status_code,
            'message': 'Gateway returned non-success status'
        }), 400

    return jsonify({'success': False, 'error': f'Gateway connection failed: {error_reason}'}), 400


@app.route('/api/whatsapp/auto-configure', methods=['POST'])
@superadmin_required
def auto_configure_whatsapp_gateway():
    runtime_cfg = _get_whatsapp_runtime_settings()
    if runtime_cfg.get('deployment_region') == 'iran':
        return jsonify({
            'success': False,
            'error': 'WhatsApp automation is not available when the panel is deployed in Iran.',
            'blocked_reason': 'deployment_in_iran'
        }), 400

    timeout_seconds = int(runtime_cfg.get('gateway_timeout_seconds') or 10)
    api_key = (runtime_cfg.get('gateway_api_key') or '').strip()
    configured_url = (runtime_cfg.get('gateway_url') or '').strip()
    host_hint = request.host

    candidates = _build_whatsapp_gateway_candidates(host_hint=host_hint, configured_url=configured_url)
    checked = []
    first_error = None

    for candidate in candidates:
        ok, status_code, error_reason = _probe_whatsapp_gateway(candidate, timeout_seconds=timeout_seconds, api_key=api_key)
        checked.append({
            'url': candidate,
            'ok': bool(ok),
            'status_code': int(status_code) if status_code is not None else None,
            'error': None if ok else (error_reason or 'health_check_failed')
        })
        if ok:
            normalized = _normalize_whatsapp_gateway_url(candidate)
            conf = db.session.get(SystemConfig, WHATSAPP_GATEWAY_URL_KEY)
            if conf:
                conf.value = normalized
            else:
                db.session.add(SystemConfig(key=WHATSAPP_GATEWAY_URL_KEY, value=normalized))
            db.session.commit()
            return jsonify({
                'success': True,
                'gateway_url': normalized,
                'auth_url': f"{normalized}/auth",
                'checked': checked,
            })

        if first_error is None and error_reason:
            first_error = str(error_reason)

    debug_enabled = _parse_bool(request.args.get('debug'))
    response_payload = {
        'success': False,
        'error': 'No WhatsApp gateway service is available yet. Auto setup will retry when you open this section again.',
        'checked': checked,
    }
    if debug_enabled and first_error:
        response_payload['details'] = first_error
    return jsonify(response_payload), 400

@app.route('/packages')
@user_management_required
def packages_page():
    cost_gb = db.session.get(SystemConfig, 'cost_per_gb')
    cost_day = db.session.get(SystemConfig, 'cost_per_day')
    cost_day_unlimited = db.session.get(SystemConfig, 'cost_per_day_unlimited')

    return render_template('packages.html',
                         base_cost_gb=int(cost_gb.value) if cost_gb else 0,
                         base_cost_day=int(cost_day.value) if cost_day else 0,
                         base_cost_day_unlimited=int(cost_day_unlimited.value) if cost_day_unlimited else 0,
                         admin_username=session.get('admin_username'),
                         is_superadmin=session.get('is_superadmin', False),
                         role=session.get('role', 'admin'))

@app.route('/bank-cards')
@user_management_required
def bank_cards_page():
    return render_template('bank_cards.html',
                         admin_username=session.get('admin_username'),
                         is_superadmin=session.get('is_superadmin', False),
                         role=session.get('role', 'admin'))

@app.route('/api/bank-cards', methods=['GET'])
@login_required
def list_bank_cards():
    user = db.session.get(Admin, session['admin_id'])
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 401
    include_inactive = request.args.get('include_inactive', '0') in ('1', 'true', 'True')
    query = BankCard.query
    if not (user.role == 'superadmin' or user.is_superadmin):
        query = query.filter_by(is_active=True)
    elif not include_inactive:
        query = query.filter_by(is_active=True)
    cards = query.order_by(BankCard.created_at.desc()).all()
    return jsonify({'success': True, 'cards': [card.to_dict() for card in cards]})

@app.route('/api/bank-cards', methods=['POST'])
@user_management_required
def create_bank_card():
    data = request.get_json() or {}
    label = (data.get('label') or '').strip()
    if not label:
        return jsonify({'success': False, 'error': 'Label is required'}), 400
    
    card = BankCard(
        label=sanitize_html(label),
        bank_name=sanitize_html((data.get('bank_name') or '').strip() or None),
        owner_name=sanitize_html((data.get('owner_name') or '').strip() or None),
        card_number=sanitize_html((data.get('card_number') or '').strip() or None),
        iban=sanitize_html((data.get('iban') or '').strip() or None),
        account_number=sanitize_html((data.get('account_number') or '').strip() or None),
        notes=sanitize_html((data.get('notes') or '').strip() or None),
        is_active=bool(data.get('is_active', True))
    )
    db.session.add(card)
    db.session.commit()
    return jsonify({'success': True, 'card': card.to_dict()})

@app.route('/api/bank-cards/<int:card_id>', methods=['PUT'])
@user_management_required
def update_bank_card(card_id):
    card = db.session.get(BankCard, card_id)
    if not card:
        return jsonify({'success': False, 'error': 'Card not found'}), 404
    data = request.get_json() or {}
    for field in ('label', 'bank_name', 'owner_name', 'card_number', 'iban', 'account_number', 'notes'):
        if field in data:
            value = data.get(field)
            if isinstance(value, str):
                value = sanitize_html(value.strip())
            setattr(card, field, value)
    if 'is_active' in data:
        card.is_active = bool(data.get('is_active'))
    db.session.commit()
    return jsonify({'success': True, 'card': card.to_dict()})

@app.route('/api/bank-cards/<int:card_id>', methods=['DELETE'])
@user_management_required
def delete_bank_card(card_id):
    card = db.session.get(BankCard, card_id)
    if not card:
        return jsonify({'success': False, 'error': 'Card not found'}), 404
    db.session.delete(card)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/transactions')
@login_required
def transactions_page():
    user = db.session.get(Admin, session['admin_id'])
    servers = get_accessible_servers(user, include_disabled=True) if user else []
    admin_options = []
    if user and (user.role == 'superadmin' or user.is_superadmin):
        admin_options = Admin.query.order_by(Admin.username.asc()).all()
    return render_template('transactions.html',
                         admin_username=session.get('admin_username'),
                         is_superadmin=session.get('is_superadmin', False),
                         role=session.get('role', 'admin'),
                         servers=servers,
                         admin_options=admin_options)

@app.route('/receipts')
@login_required
def receipts_page():
    return render_template('receipts.html',
                         admin_username=session.get('admin_username'),
                         is_superadmin=session.get('is_superadmin', False),
                         role=session.get('role', 'admin'),
                         current_admin_id=session.get('admin_id'))

@app.route('/api/receipts', methods=['POST'])
@login_required
def upload_receipt():
    user = db.session.get(Admin, session['admin_id'])
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 401
    trigger_auto_receipt_processing()

    form = request.form
    try:
        amount = int(form.get('amount', 0))
    except (TypeError, ValueError):
        amount = 0
    if amount <= 0:
        return jsonify({'success': False, 'error': 'Amount must be positive'}), 400

    card_id = form.get('card_id')
    card = None
    if card_id:
        try:
            card = db.session.get(BankCard, int(card_id))
        except (TypeError, ValueError):
            card = None
        if not card:
            return jsonify({'success': False, 'error': 'Selected card not found'}), 404
        if not card.is_active and not (user.role == 'superadmin' or user.is_superadmin):
            return jsonify({'success': False, 'error': 'Card is inactive'}), 400

    slip_file = request.files.get('file')
    if not slip_file or not slip_file.filename:
        return jsonify({'success': False, 'error': 'Receipt image is required'}), 400

    slip_file.seek(0, os.SEEK_END)
    file_length = slip_file.tell()
    slip_file.seek(0)
    if file_length > MAX_FILE_SIZE:
        return jsonify({'success': False, 'error': 'File too large'}), 413

    if not allowed_receipt_file(slip_file):
        return jsonify({'success': False, 'error': 'Unsupported file type'}), 400
    stored_path = save_receipt_file(slip_file)
    if not stored_path:
        return jsonify({'success': False, 'error': 'Failed to store file'}), 400

    deposit_at = parse_iso_datetime(form.get('deposit_at'))
    reference_code = (form.get('reference_code') or '').strip() or None
    notes = (form.get('notes') or '').strip() or None
    currency = (form.get('currency') or 'IRT').strip().upper()
    if len(currency) > 10:
        currency = currency[:10]

    auto_window = get_active_auto_window()
    initial_status = RECEIPT_STATUS_PENDING
    auto_deadline = None
    if auto_window and (auto_window.max_amount <= 0 or amount <= auto_window.max_amount):
        initial_status = RECEIPT_STATUS_AUTO_PENDING
        auto_deadline = auto_window.ends_at

    receipt = ManualReceipt(
        admin_id=user.id,
        card_id=card.id if card else None,
        amount=amount,
        currency=currency,
        deposit_at=deposit_at,
        reference_code=reference_code,
        image_path=stored_path,
        status=initial_status,
        auto_deadline=auto_deadline,
        notes=notes
    )
    db.session.add(receipt)
    db.session.commit()

    payload = receipt.to_dict()
    payload['image_url'] = url_for('download_receipt_file', receipt_id=receipt.id)
    return jsonify({'success': True, 'receipt': payload})

@app.route('/api/receipts', methods=['GET'])
@login_required
def list_receipts():
    user = db.session.get(Admin, session['admin_id'])
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 401
    trigger_auto_receipt_processing()
    query = ManualReceipt.query.join(Admin, ManualReceipt.admin_id == Admin.id)
    if not (user.role == 'superadmin' or user.is_superadmin):
        query = query.filter(ManualReceipt.admin_id == user.id)
    else:
        admin_filter = request.args.get('user_id', type=int)
        if admin_filter:
            query = query.filter(ManualReceipt.admin_id == admin_filter)
    status_filter = request.args.get('status')
    if status_filter:
        query = query.filter(ManualReceipt.status == status_filter)
    limit = request.args.get('limit', type=int) or 200
    limit = max(1, min(limit, 1000))
    receipts = query.order_by(ManualReceipt.created_at.desc()).limit(limit).all()
    payload = []
    for receipt in receipts:
        data = receipt.to_dict()
        data['image_url'] = url_for('download_receipt_file', receipt_id=receipt.id)
        payload.append(data)
    return jsonify({'success': True, 'receipts': payload})

@app.route('/receipts/file/<int:receipt_id>')
@login_required
def download_receipt_file(receipt_id):
    user = db.session.get(Admin, session['admin_id'])
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 401
    receipt = db.session.get(ManualReceipt, receipt_id)
    if not receipt:
        return jsonify({'success': False, 'error': 'Receipt not found'}), 404
    if receipt.admin_id != user.id and not (user.role == 'superadmin' or user.is_superadmin):
        return jsonify({'success': False, 'error': 'Forbidden'}), 403
    if not receipt.image_path:
        return jsonify({'success': False, 'error': 'File missing'}), 404
    full_path = os.path.join(app.instance_path, receipt.image_path)
    if not os.path.abspath(full_path).startswith(os.path.abspath(RECEIPTS_DIR)):
        return jsonify({'success': False, 'error': 'Invalid path'}), 403
    if not os.path.isfile(full_path):
        return jsonify({'success': False, 'error': 'File missing'}), 404
    return send_file(full_path, as_attachment=False)

@app.route('/api/receipts/<int:receipt_id>/approve', methods=['POST'])
@user_management_required
def approve_receipt(receipt_id):
    trigger_auto_receipt_processing()
    receipt = db.session.get(ManualReceipt, receipt_id)
    if not receipt:
        return jsonify({'success': False, 'error': 'Receipt not found'}), 404
    reviewer = db.session.get(Admin, session['admin_id'])
    allowed_states = {RECEIPT_STATUS_PENDING, RECEIPT_STATUS_AUTO_PENDING, RECEIPT_STATUS_REJECTED}
    if receipt.status not in allowed_states:
        if receipt.status in (RECEIPT_STATUS_APPROVED, RECEIPT_STATUS_AUTO_APPROVED):
            data = receipt.to_dict()
            data['image_url'] = url_for('download_receipt_file', receipt_id=receipt.id)
            return jsonify({'success': True, 'receipt': data})
        return jsonify({'success': False, 'error': 'Invalid receipt state'}), 400
    success, error = apply_receipt_credit(receipt, reviewer=reviewer, auto=False)
    if not success:
        return jsonify({'success': False, 'error': error}), 400
    db.session.commit()
    data = receipt.to_dict()
    data['image_url'] = url_for('download_receipt_file', receipt_id=receipt.id)
    data['new_balance'] = receipt.admin.credit if receipt.admin else None
    return jsonify({'success': True, 'receipt': data})

@app.route('/api/receipts/<int:receipt_id>/reject', methods=['POST'])
@user_management_required
def reject_receipt(receipt_id):
    trigger_auto_receipt_processing()
    receipt = db.session.get(ManualReceipt, receipt_id)
    if not receipt:
        return jsonify({'success': False, 'error': 'Receipt not found'}), 404
    data = request.get_json() or {}
    reason = (data.get('reason') or '').strip() or 'Rejected'
    reviewer = db.session.get(Admin, session['admin_id'])
    if receipt.status in (RECEIPT_STATUS_APPROVED, RECEIPT_STATUS_AUTO_APPROVED):
        success, error = rollback_receipt_credit(receipt, reviewer=reviewer, reason=reason)
        if not success:
            return jsonify({'success': False, 'error': error}), 400
    receipt.status = RECEIPT_STATUS_REJECTED
    receipt.reviewer_id = reviewer.id if reviewer else None
    receipt.reviewed_at = datetime.utcnow()
    receipt.rejection_reason = reason
    receipt.auto_deadline = None
    db.session.commit()
    data = receipt.to_dict()
    data['image_url'] = url_for('download_receipt_file', receipt_id=receipt.id)
    return jsonify({'success': True, 'receipt': data})

@app.route('/api/receipts/auto-windows', methods=['GET'])
@user_management_required
def list_auto_windows():
    windows = AutoApprovalWindow.query.order_by(AutoApprovalWindow.starts_at.desc()).all()
    return jsonify({'success': True, 'windows': [w.to_dict() for w in windows]})

@app.route('/api/receipts/auto-windows', methods=['POST'])
@user_management_required
def create_auto_window():
    data = request.get_json() or {}
    starts_at = parse_iso_datetime(data.get('starts_at')) or datetime.utcnow()
    ends_at = parse_iso_datetime(data.get('ends_at'))
    if not ends_at or ends_at <= starts_at:
        return jsonify({'success': False, 'error': 'Invalid window timeframe'}), 400
    try:
        max_amount = int(data.get('max_amount', 0) or 0)
    except (TypeError, ValueError):
        max_amount = 0
    window = AutoApprovalWindow(
        starts_at=starts_at,
        ends_at=ends_at,
        max_amount=max_amount,
        status='enabled'
    )
    db.session.add(window)
    db.session.commit()
    return jsonify({'success': True, 'window': window.to_dict()})

@app.route('/api/receipts/auto-windows/<int:window_id>', methods=['DELETE'])
@user_management_required
def disable_auto_window(window_id):
    window = db.session.get(AutoApprovalWindow, window_id)
    if not window:
        return jsonify({'success': False, 'error': 'Window not found'}), 404
    window.status = 'disabled'
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/templates', methods=['GET'])
@user_management_required
def get_templates():
    template_type = (request.args.get('type') or 'client_created').strip().lower()
    query = NotificationTemplate.query
    if template_type != 'all':
        query = query.filter_by(type=template_type)
    templates = query.order_by(NotificationTemplate.created_at.desc()).all()
    return jsonify({'success': True, 'templates': [t.to_dict() for t in templates]})

@app.route('/api/templates', methods=['POST'])
@user_management_required
def create_template():
    data = request.get_json()
    name = data.get('name')
    content = data.get('content')
    template_type = (data.get('type') or 'client_created').strip().lower()
    if not name or not content:
        return jsonify({'success': False, 'error': 'Name and content are required'}), 400

    template = NotificationTemplate(name=name, content=content, type=template_type)
    db.session.add(template)
    db.session.commit()

    type_count = NotificationTemplate.query.filter_by(type=template_type).count()
    if type_count == 1:
        template.is_active = True
        db.session.commit()

    return jsonify({'success': True, 'template': template.to_dict()})

@app.route('/api/templates/<int:template_id>', methods=['PUT'])
@user_management_required
def update_template(template_id):
    template = db.session.get(NotificationTemplate, template_id)
    if not template:
        return jsonify({'success': False, 'error': 'Template not found'}), 404
    
    data = request.get_json()
    template.name = data.get('name', template.name)
    template.content = data.get('content', template.content)
    db.session.commit()
    return jsonify({'success': True, 'template': template.to_dict()})

@app.route('/api/templates/<int:template_id>', methods=['DELETE'])
@user_management_required
def delete_template(template_id):
    template = db.session.get(NotificationTemplate, template_id)
    if not template:
        return jsonify({'success': False, 'error': 'Template not found'}), 404
    if template.is_active:
        return jsonify({'success': False, 'error': 'Cannot delete active template'}), 400
    
    db.session.delete(template)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/templates/<int:template_id>/activate', methods=['POST'])
@user_management_required
def activate_template(template_id):
    template = db.session.get(NotificationTemplate, template_id)
    if not template:
        return jsonify({'success': False, 'error': 'Template not found'}), 404
    
    # Deactivate all others of the same type
    NotificationTemplate.query.filter_by(type=template.type).update({NotificationTemplate.is_active: False})
    template.is_active = True
    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/templates/active', methods=['GET'])
@login_required
def get_active_template():
    template_type = (request.args.get('type') or 'client_created').strip().lower()
    template = NotificationTemplate.query.filter_by(type=template_type, is_active=True).first()
    return jsonify({
        'success': True,
        'template': template.to_dict() if template else None,
        'content': template.content if template else ''
    })

def _account_info_template_vars():
    return [
        '{email}', '{account_name}', '{remaining_time}', '{remaining_volume}',
        '{dashboard_link}', '{sub_link}', '{server_name}',
        '{telegram_channel}', '{whatsapp_channel}',
    ]


def _account_info_channel_links(admin: 'Admin') -> dict:
    """Return telegram_channel / whatsapp_channel for an admin/reseller.

    - superadmin / admin  → uses their own channel fields
    - reseller            → uses the reseller's own channel fields
    - not set             → empty string (template var stays blank, not shown)
    """
    return {
        'telegram_channel': (admin.channel_telegram or '').strip(),
        'whatsapp_channel': (admin.channel_whatsapp or '').strip(),
    }

# channel name → (template type, default content)
_CHANNEL_TEMPLATE_MAP = {
    'whatsapp':                (lambda: ACCOUNT_INFO_WHATSAPP_TEMPLATE_TYPE,   lambda: DEFAULT_ACCOUNT_INFO_WHATSAPP_TEMPLATE),
    'sms':                     (lambda: ACCOUNT_INFO_SMS_TEMPLATE_TYPE,        lambda: DEFAULT_ACCOUNT_INFO_SMS_TEMPLATE),
    'royalty_whatsapp':        (lambda: ROYALTY_INFO_WHATSAPP_TEMPLATE_TYPE,   lambda: DEFAULT_ROYALTY_INFO_WHATSAPP_TEMPLATE),
    'royalty_sms':             (lambda: ROYALTY_INFO_SMS_TEMPLATE_TYPE,        lambda: DEFAULT_ROYALTY_INFO_SMS_TEMPLATE),
    'client_created_whatsapp': (lambda: CLIENT_CREATED_WHATSAPP_TEMPLATE_TYPE, lambda: DEFAULT_CLIENT_CREATED_WHATSAPP_TEMPLATE),
    'client_created_sms':      (lambda: CLIENT_CREATED_SMS_TEMPLATE_TYPE,      lambda: DEFAULT_CLIENT_CREATED_SMS_TEMPLATE),
    'renew_whatsapp':          (lambda: RENEW_WHATSAPP_TEMPLATE_TYPE,          lambda: DEFAULT_RENEW_WHATSAPP_TEMPLATE),
    'renew_sms':               (lambda: RENEW_SMS_TEMPLATE_TYPE,               lambda: DEFAULT_RENEW_SMS_TEMPLATE),
}
_TYPE_TO_CHANNEL = {
    ACCOUNT_INFO_WHATSAPP_TEMPLATE_TYPE: 'whatsapp',
    ACCOUNT_INFO_SMS_TEMPLATE_TYPE: 'sms',
    ROYALTY_INFO_WHATSAPP_TEMPLATE_TYPE: 'royalty_whatsapp',
    ROYALTY_INFO_SMS_TEMPLATE_TYPE: 'royalty_sms',
    CLIENT_CREATED_WHATSAPP_TEMPLATE_TYPE: 'client_created_whatsapp',
    CLIENT_CREATED_SMS_TEMPLATE_TYPE: 'client_created_sms',
    RENEW_WHATSAPP_TEMPLATE_TYPE: 'renew_whatsapp',
    RENEW_SMS_TEMPLATE_TYPE: 'renew_sms',
}

def _account_info_template_type(channel='whatsapp'):
    channel = (channel or 'whatsapp').strip().lower()
    entry = _CHANNEL_TEMPLATE_MAP.get(channel)
    return entry[0]() if entry else ACCOUNT_INFO_WHATSAPP_TEMPLATE_TYPE

def _account_info_default_template(channel='whatsapp'):
    channel = (channel or 'whatsapp').strip().lower()
    entry = _CHANNEL_TEMPLATE_MAP.get(channel)
    return entry[1]() if entry else DEFAULT_ACCOUNT_INFO_WHATSAPP_TEMPLATE

def _account_info_channel_from_type(template_type):
    return _TYPE_TO_CHANNEL.get(template_type, 'whatsapp')

_ALL_ACCOUNT_INFO_TYPES = (
    ACCOUNT_INFO_WHATSAPP_TEMPLATE_TYPE, ACCOUNT_INFO_SMS_TEMPLATE_TYPE,
    ROYALTY_INFO_WHATSAPP_TEMPLATE_TYPE, ROYALTY_INFO_SMS_TEMPLATE_TYPE,
    CLIENT_CREATED_WHATSAPP_TEMPLATE_TYPE, CLIENT_CREATED_SMS_TEMPLATE_TYPE,
    RENEW_WHATSAPP_TEMPLATE_TYPE, RENEW_SMS_TEMPLATE_TYPE,
)

def _ensure_default_account_info_template(channel='whatsapp'):
    template_type = _account_info_template_type(channel)
    # Only ensure a global (owner_id=None) default exists
    existing = NotificationTemplate.query.filter_by(type=template_type, owner_id=None).first()
    if existing:
        return
    name_map = {
        ACCOUNT_INFO_SMS_TEMPLATE_TYPE: 'Default Account Info SMS',
        ROYALTY_INFO_WHATSAPP_TEMPLATE_TYPE: 'Default Royalty Info',
        ROYALTY_INFO_SMS_TEMPLATE_TYPE: 'Default Royalty Info SMS',
        CLIENT_CREATED_WHATSAPP_TEMPLATE_TYPE: 'Default Client Created WhatsApp',
        CLIENT_CREATED_SMS_TEMPLATE_TYPE: 'Default Client Created SMS',
        RENEW_WHATSAPP_TEMPLATE_TYPE: 'Default Renew WhatsApp',
        RENEW_SMS_TEMPLATE_TYPE: 'Default Renew SMS',
    }
    template = NotificationTemplate(
        name=name_map.get(template_type, 'Default Account Info'),
        content=_account_info_default_template(channel),
        type=template_type,
        is_active=True,
        owner_id=None,
    )
    db.session.add(template)
    db.session.commit()


def _resolve_account_info_template(admin: 'Admin', channel: str = 'whatsapp') -> 'NotificationTemplate | None':
    """Return the best-match active template for an admin.

    Priority:
    1. Reseller-specific active template (owner_id = admin.id)
    2. Global active template (owner_id = NULL)
    """
    template_type = _account_info_template_type(channel)
    if admin and admin.role == 'reseller':
        specific = NotificationTemplate.query.filter_by(
            type=template_type, owner_id=admin.id, is_active=True
        ).first()
        if specific:
            return specific
    return NotificationTemplate.query.filter_by(
        type=template_type, owner_id=None, is_active=True
    ).first()

@app.route('/api/account-message-templates', methods=['GET'])
@user_management_required
def get_account_message_templates():
    for _ch in ('whatsapp', 'sms', 'royalty_whatsapp', 'royalty_sms',
                'client_created_whatsapp', 'client_created_sms',
                'renew_whatsapp', 'renew_sms'):
        _ensure_default_account_info_template(_ch)

    current_admin = db.session.get(Admin, session.get('admin_id'))

    # Resellers only see their own specific templates + global ones
    # Admins/superadmins see everything
    q = NotificationTemplate.query.filter(
        NotificationTemplate.type.in_(_ALL_ACCOUNT_INFO_TYPES)
    )
    if current_admin and current_admin.role == 'reseller':
        q = q.filter(
            (NotificationTemplate.owner_id == current_admin.id) |
            (NotificationTemplate.owner_id == None)  # noqa: E711
        )
    templates = q.order_by(NotificationTemplate.owner_id.desc().nullslast(),
                           NotificationTemplate.created_at.desc()).all()

    template_dicts = []
    for template in templates:
        data = template.to_dict()
        data['channel'] = _account_info_channel_from_type(template.type)
        template_dicts.append(data)

    # Build reseller list for admin UI (assign template to reseller)
    resellers = []
    if current_admin and current_admin.role in ('admin', 'superadmin'):
        resellers = [
            {'id': r.id, 'username': r.username}
            for r in Admin.query.filter_by(role='reseller').order_by(Admin.username).all()
        ]

    return jsonify({
        'success': True,
        'templates': template_dicts,
        'available_vars': _account_info_template_vars(),
        'default_content': DEFAULT_ACCOUNT_INFO_WHATSAPP_TEMPLATE,
        'default_sms_content': DEFAULT_ACCOUNT_INFO_SMS_TEMPLATE,
        'default_royalty_whatsapp_content': DEFAULT_ROYALTY_INFO_WHATSAPP_TEMPLATE,
        'default_royalty_sms_content': DEFAULT_ROYALTY_INFO_SMS_TEMPLATE,
        'default_client_created_whatsapp_content': DEFAULT_CLIENT_CREATED_WHATSAPP_TEMPLATE,
        'default_client_created_sms_content': DEFAULT_CLIENT_CREATED_SMS_TEMPLATE,
        'default_renew_whatsapp_content': DEFAULT_RENEW_WHATSAPP_TEMPLATE,
        'default_renew_sms_content': DEFAULT_RENEW_SMS_TEMPLATE,
        'resellers': resellers,
    })

@app.route('/api/account-message-templates/active', methods=['GET'])
@login_required
def get_active_account_message_template():
    channel = (request.args.get('channel') or 'whatsapp').strip().lower()
    # Normalise: 'royalty' shorthand → 'royalty_whatsapp'
    if channel == 'royalty':
        channel = 'royalty_whatsapp'
    _ensure_default_account_info_template(channel)
    default_content = _account_info_default_template(channel)

    current_admin = db.session.get(Admin, session.get('admin_id'))

    # Priority: reseller-specific → global
    template = _resolve_account_info_template(current_admin, channel)

    template_data = template.to_dict() if template else None
    if template_data:
        template_data['channel'] = _account_info_channel_from_type(template.type)

    channel_links = _account_info_channel_links(current_admin) if current_admin else {
        'telegram_channel': '', 'whatsapp_channel': ''
    }

    return jsonify({
        'success': True,
        'template': template_data,
        'content': template.content if template else default_content,
        'available_vars': _account_info_template_vars(),
        'scope': template_data.get('scope') if template_data else 'global',
        **channel_links,
    })

@app.route('/api/account-message-templates', methods=['POST'])
@user_management_required
def create_account_message_template():
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    content = (data.get('content') or '').strip()
    template_type = _account_info_template_type(data.get('channel') or 'whatsapp')
    if not name or not content:
        return jsonify({'success': False, 'error': 'Name and content are required'}), 400

    # owner_id: None = global, reseller admin.id = reseller-specific
    owner_id = None
    raw_owner = data.get('owner_id')
    if raw_owner:
        try:
            owner_id = int(raw_owner)
            # Validate: must be an existing reseller
            owner = db.session.get(Admin, owner_id)
            if not owner or owner.role != 'reseller':
                return jsonify({'success': False, 'error': 'owner_id must refer to a reseller account'}), 400
        except (ValueError, TypeError):
            return jsonify({'success': False, 'error': 'Invalid owner_id'}), 400

    template = NotificationTemplate(
        name=name,
        content=content,
        type=template_type,
        is_active=False,
        owner_id=owner_id,
    )
    db.session.add(template)
    db.session.commit()

    # Auto-activate if it's the only one of its scope
    scope_count = NotificationTemplate.query.filter_by(type=template_type, owner_id=owner_id).count()
    if scope_count == 1:
        template.is_active = True
        db.session.commit()

    template_data = template.to_dict()
    template_data['channel'] = _account_info_channel_from_type(template.type)
    return jsonify({'success': True, 'template': template_data})

@app.route('/api/account-message-templates/<int:template_id>', methods=['PUT'])
@user_management_required
def update_account_message_template(template_id):
    template = db.session.get(NotificationTemplate, template_id)
    if not template or template.type not in _ALL_ACCOUNT_INFO_TYPES:
        return jsonify({'success': False, 'error': 'Template not found'}), 404
    data = request.get_json() or {}
    if 'name' in data:
        template.name = (data.get('name') or template.name).strip()
    if 'content' in data:
        template.content = (data.get('content') or template.content).strip()
    if not template.is_active and 'channel' in data:
        template.type = _account_info_template_type(data.get('channel') or 'whatsapp')
    if not template.name or not template.content:
        return jsonify({'success': False, 'error': 'Name and content are required'}), 400
    db.session.commit()
    template_data = template.to_dict()
    template_data['channel'] = _account_info_channel_from_type(template.type)
    return jsonify({'success': True, 'template': template_data})

@app.route('/api/account-message-templates/<int:template_id>', methods=['DELETE'])
@user_management_required
def delete_account_message_template(template_id):
    template = db.session.get(NotificationTemplate, template_id)
    if not template or template.type not in _ALL_ACCOUNT_INFO_TYPES:
        return jsonify({'success': False, 'error': 'Template not found'}), 404
    if template.is_active:
        return jsonify({'success': False, 'error': 'Disable this template before deleting it'}), 400
    db.session.delete(template)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/account-message-templates/<int:template_id>/activate', methods=['POST'])
@user_management_required
def activate_account_message_template(template_id):
    template = db.session.get(NotificationTemplate, template_id)
    if not template or template.type not in _ALL_ACCOUNT_INFO_TYPES:
        return jsonify({'success': False, 'error': 'Template not found'}), 404
    # Only deactivate templates in the same scope (same owner_id)
    NotificationTemplate.query.filter_by(
        type=template.type, owner_id=template.owner_id
    ).update({NotificationTemplate.is_active: False})
    template.is_active = True
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/account-message-templates/<int:template_id>/disable', methods=['POST'])
@user_management_required
def disable_account_message_template(template_id):
    template = db.session.get(NotificationTemplate, template_id)
    if not template or template.type not in _ALL_ACCOUNT_INFO_TYPES:
        return jsonify({'success': False, 'error': 'Template not found'}), 404
    template.is_active = False
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/backups', methods=['GET'])
@login_required
def list_backups():
    backups = []
    if os.path.exists(BACKUP_DIR):
        patterns = ('*.db', '*.dump', '*.sql', '*.zip')
        files = []
        for pat in patterns:
            files.extend(glob.glob(os.path.join(BACKUP_DIR, pat)))
        files.sort(key=os.path.getmtime, reverse=True)
        for f in files:
            name = os.path.basename(f)
            ext = os.path.splitext(name)[1].lower()
            size = os.path.getsize(f)
            date = datetime.fromtimestamp(os.path.getmtime(f)).strftime('%Y-%m-%d %H:%M:%S')

            if ext == '.zip':
                restore_supported = True  # full migration bundle (DB + files)
            elif _is_sqlite_db():
                restore_supported = ext == '.db'
            else:
                restore_supported = ext in ('.dump', '.sql')

            if ext == '.zip' or 'migration' in name:
                b_type = 'Migration (DB+files)'
            elif name.startswith('upload_'):
                b_type = 'Uploaded'
            elif name.startswith('auto_'):
                b_type = 'Automatic'
            elif name.startswith('pre_restore_'):
                b_type = 'Safety'
            else:
                b_type = 'System'

            backups.append({
                'name': name, 'size': size, 'date': date,
                'type': b_type, 'restore_supported': restore_supported
            })

    return jsonify({
        'success': True,
        'backups': backups,
        'is_postgres': _is_postgres_db(),
        'restore_supported': True,  # always true; per-file flag controls actual button
    })

@app.route('/api/backups', methods=['POST'])
@login_required
def create_backup():
    try:
        filename = _create_database_backup_file('backup')
        return jsonify({'success': True, 'message': 'Backup created', 'filename': filename})
    except Exception as e:
        app.logger.error(f'create_backup error: {e}')
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/backups/migration', methods=['POST'])
@superadmin_required
def create_migration_backup():
    """Create a COMPLETE migration bundle (DB + all uploaded files) and return its filename.
    Use this to move everything to another server."""
    try:
        filename = _create_full_migration_zip('migration')
        size = os.path.getsize(os.path.join(BACKUP_DIR, filename))
        return jsonify({'success': True, 'filename': filename, 'size': size,
                        'message': 'Full migration bundle created (database + uploaded files)'})
    except Exception as e:
        app.logger.error(f'create_migration_backup error: {e}', exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/backups/diag', methods=['GET'])
@superadmin_required
def backup_diag():
    """Diagnostic: show backup directory path and files on disk."""
    pg_dump_bin = shutil.which('pg_dump')
    files_on_disk = []
    try:
        if os.path.isdir(BACKUP_DIR):
            for f in sorted(os.listdir(BACKUP_DIR)):
                fp = os.path.join(BACKUP_DIR, f)
                if os.path.isfile(fp):
                    files_on_disk.append({'name': f, 'size': os.path.getsize(fp)})
    except Exception as e:
        files_on_disk = [{'error': str(e)}]
    return jsonify({
        'backup_dir': BACKUP_DIR,
        'dir_exists': os.path.isdir(BACKUP_DIR),
        'dir_writable': os.access(BACKUP_DIR, os.W_OK),
        'instance_path': app.instance_path,
        'pg_dump': pg_dump_bin or 'NOT FOUND',
        'db_type': 'postgresql' if _is_postgres_db() else 'sqlite',
        'files_on_disk': files_on_disk,
    })


@app.route('/api/backups/upload', methods=['POST'])
@login_required
def upload_backup():
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file part'})
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No selected file'})
    
    file.seek(0, os.SEEK_END)
    file_length = file.tell()
    file.seek(0)
    if file_length > BACKUP_UPLOAD_MAX_SIZE:
        mb = BACKUP_UPLOAD_MAX_SIZE // (1024 * 1024)
        return jsonify({'success': False, 'error': f'File too large (max {mb} MB)'}), 413

    allowed_exts = {'.db', '.dump', '.sql', '.zip'}  # .zip = full migration bundle
    _, ext = os.path.splitext(file.filename or '')
    ext = (ext or '').lower()

    if file and ext in allowed_exts:
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            safe_name = secure_filename(file.filename)
            filename = f'upload_{timestamp}_{safe_name}'
            file.save(os.path.join(BACKUP_DIR, filename))
            return jsonify({'success': True, 'message': 'Backup uploaded successfully'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})
    return jsonify({'success': False, 'error': 'Invalid file type. Allowed: .db, .dump, .sql, .zip'})

@app.route('/api/settings/backup', methods=['GET'])
@login_required
def get_backup_settings():
    freq = db.session.get(SystemSetting, 'backup_frequency')
    return jsonify({
        'success': True,
        'frequency': freq.value if freq else 'disabled',
        'retention_enabled': _parse_bool(_get_system_setting_value('backup_retention_enabled', 'false')),
        'retention_days': _parse_int(_get_system_setting_value('backup_retention_days', '14'), 14, min_value=1, max_value=3650),
    })

@app.route('/api/settings/backup', methods=['POST'])
@login_required
def save_backup_settings():
    data = request.json
    freq_val = data.get('frequency', 'disabled')

    setting = db.session.get(SystemSetting, 'backup_frequency')
    if not setting:
        setting = SystemSetting(key='backup_frequency', value=freq_val)
        db.session.add(setting)
    else:
        setting.value = freq_val

    if 'retention_enabled' in data:
        _set_system_setting_value('backup_retention_enabled', 'true' if data.get('retention_enabled') else 'false')
    if 'retention_days' in data:
        rdays = _parse_int(data.get('retention_days'), 14, min_value=1, max_value=3650)
        _set_system_setting_value('backup_retention_days', str(rdays))

    db.session.commit()
    return jsonify({'success': True, 'message': 'Settings saved'})


def _cleanup_old_backups(days: int) -> dict:
    """Delete backup files older than `days` from BACKUP_DIR.
    Safety pre_restore_* files are kept. Returns {deleted, freed_bytes}."""
    deleted, freed = 0, 0
    if days < 1 or not os.path.isdir(BACKUP_DIR):
        return {'deleted': 0, 'freed_bytes': 0}
    cutoff = time.time() - days * 86400
    for pat in ('*.db', '*.dump', '*.sql', '*.zip'):
        for f in glob.glob(os.path.join(BACKUP_DIR, pat)):
            name = os.path.basename(f)
            if name.startswith('pre_restore_'):
                continue  # never auto-delete safety backups
            try:
                if os.path.getmtime(f) < cutoff:
                    sz = os.path.getsize(f)
                    os.remove(f)
                    deleted += 1
                    freed += sz
            except Exception:
                pass
    return {'deleted': deleted, 'freed_bytes': freed}


@app.route('/api/backups/cleanup', methods=['POST'])
@login_required
def cleanup_backups_now():
    """Apply the retention rule right now (Clear now button)."""
    data = request.get_json(silent=True) or {}
    # Allow an explicit days override; otherwise use the saved setting
    days = data.get('days')
    if days is None:
        days = _parse_int(_get_system_setting_value('backup_retention_days', '14'), 14, min_value=1, max_value=3650)
    else:
        days = _parse_int(days, 14, min_value=1, max_value=3650)
    result = _cleanup_old_backups(days)
    return jsonify({'success': True, 'days': days, **result})


@app.route('/api/settings/telegram-backup', methods=['GET'])
@user_management_required
def get_telegram_backup_settings():
    settings = _get_telegram_backup_settings()
    return jsonify({'success': True, **settings})


@app.route('/api/settings/telegram-backup', methods=['POST'])
@user_management_required
def save_telegram_backup_settings():
    try:
        data = request.get_json() or {}
    except Exception:
        data = {}

    enabled = bool(data.get('enabled'))
    send_panel_backup = bool(data.get('send_panel_backup'))
    schedule_mode = (data.get('schedule_mode') or 'interval').strip().lower()
    if schedule_mode not in ('interval', 'daily'):
        schedule_mode = 'interval'
    # daily_time: "HH:MM" in Tehran local time
    daily_time = (data.get('daily_time') or '00:00').strip()
    try:
        _h, _m = daily_time.split(':')
        _h = max(0, min(23, int(_h)))
        _m = max(0, min(59, int(_m)))
        daily_time = f"{_h:02d}:{_m:02d}"
    except Exception:
        daily_time = '00:00'
    interval = _parse_int(
        data.get('interval_minutes', TELEGRAM_BACKUP_DEFAULT_INTERVAL_MINUTES),
        TELEGRAM_BACKUP_DEFAULT_INTERVAL_MINUTES,
        min_value=1,
        max_value=TELEGRAM_BACKUP_MAX_INTERVAL_MINUTES
    )
    bot_token = (data.get('bot_token') or '').strip()
    chat_id = (data.get('chat_id') or '').strip()
    use_proxy = bool(data.get('use_proxy'))
    proxy_mode = (data.get('proxy_mode') or 'url').strip().lower()
    if proxy_mode not in ('url', 'hostport'):
        proxy_mode = 'url'
    proxy_url = _normalize_proxy_url(data.get('proxy_url') or '')
    proxy_host = (data.get('proxy_host') or '').strip()
    proxy_port = _parse_int(data.get('proxy_port'), 0, min_value=0, max_value=65535)  # 0 = not set
    proxy_username = (data.get('proxy_username') or '').strip()
    proxy_password = (data.get('proxy_password') or '').strip()

    if use_proxy:
        if proxy_mode == 'hostport' and (not proxy_host or not proxy_port):
            return jsonify({'success': False, 'error': 'Proxy host and port are required'}), 400
        if proxy_mode == 'url' and not proxy_url:
            return jsonify({'success': False, 'error': 'Proxy URL is required'}), 400

    _set_system_setting_value('telegram_backup_enabled', 'true' if enabled else 'false')
    _set_system_setting_value('telegram_backup_send_panel_backup', 'true' if send_panel_backup else 'false')
    _set_system_setting_value('telegram_backup_schedule_mode', schedule_mode)
    _set_system_setting_value('telegram_backup_daily_time', daily_time)
    _set_system_setting_value('telegram_backup_interval_minutes', str(interval))
    _set_system_setting_value('telegram_backup_bot_token', bot_token)
    _set_system_setting_value('telegram_backup_chat_id', chat_id)
    _set_system_setting_value('telegram_backup_use_proxy', 'true' if use_proxy else 'false')
    _set_system_setting_value('telegram_backup_proxy_mode', proxy_mode)
    _set_system_setting_value('telegram_backup_proxy_url', proxy_url)
    _set_system_setting_value('telegram_backup_proxy_host', proxy_host)
    _set_system_setting_value('telegram_backup_proxy_port', str(proxy_port))
    _set_system_setting_value('telegram_backup_proxy_username', proxy_username)
    _set_system_setting_value('telegram_backup_proxy_password', proxy_password)
    db.session.commit()

    return jsonify({'success': True, 'message': 'Telegram backup settings saved'})


@app.route('/api/settings/telegram-backup/test', methods=['POST'])
@user_management_required
def test_telegram_backup_settings():
    settings = _get_telegram_backup_settings()
    data = request.get_json(silent=True) or {}
    token = ((data.get('bot_token') if 'bot_token' in data else settings.get('bot_token')) or '').strip()
    if not token:
        return jsonify({'success': False, 'error': 'Bot token is required'}), 400

    use_proxy = bool(data.get('use_proxy')) if 'use_proxy' in data else bool(settings.get('use_proxy'))
    proxy_mode = ((data.get('proxy_mode') if 'proxy_mode' in data else settings.get('proxy_mode')) or 'url')
    proxy_url = ((data.get('proxy_url') if 'proxy_url' in data else settings.get('proxy_url')) or '')
    proxy_host = ((data.get('proxy_host') if 'proxy_host' in data else settings.get('proxy_host')) or '')
    proxy_port = _parse_int(data.get('proxy_port') if 'proxy_port' in data else settings.get('proxy_port'), 0, min_value=0, max_value=65535)
    proxy_username = ((data.get('proxy_username') if 'proxy_username' in data else settings.get('proxy_username')) or '')
    proxy_password = ((data.get('proxy_password') if 'proxy_password' in data else settings.get('proxy_password')) or '')

    proxies = _build_telegram_proxies(
        use_proxy,
        proxy_mode or 'url',
        proxy_url or '',
        proxy_host or '',
        proxy_port,
        proxy_username or '',
        proxy_password or ''
    )

    try:
        resp = _telegram_get_me(token, proxies=proxies, timeout_sec=10)
    except Exception as exc:
        return jsonify({'success': False, 'error': str(exc)}), 400

    if resp.status_code != 200:
        return jsonify({'success': False, 'error': f"HTTP {resp.status_code}"}), 400

    data, err = _safe_response_json(resp)
    if err:
        return jsonify({'success': False, 'error': err}), 400
    if isinstance(data, dict) and data.get('ok'):
        return jsonify({'success': True, 'message': 'Telegram connection OK'})
    msg = None
    if isinstance(data, dict):
        msg = data.get('description') or data.get('error')
    return jsonify({'success': False, 'error': msg or 'Telegram connection failed'}), 400


@app.route('/api/telegram-backup/now', methods=['POST'])
@user_management_required
def telegram_backup_now():
    # Enqueue as an async job so UI can show stage/progress.
    job_id = secrets.token_hex(8)
    job = {
        'id': job_id,
        'state': 'queued',
        'trigger': 'manual',
        'created_at': _utc_iso_now(),
        'created_at_ts': time.time(),
        'started_at': None,
        'finished_at': None,
        'stage': 'queued',
        'progress': {'total': 0, 'processed': 0},
        'error': None,
        'success_count': 0,
        'total': 0,
        'results': [],
    }
    with TELEGRAM_BACKUP_JOBS_LOCK:
        _load_telegram_backup_jobs_locked()
        TELEGRAM_BACKUP_JOBS[job_id] = job
        _prune_telegram_backup_jobs_locked()
        _save_telegram_backup_jobs_locked()

    t = threading.Thread(target=_run_telegram_backup_job, args=(job_id,), daemon=True)
    t.start()
    return jsonify({'success': True, 'job_id': job_id})


@app.route('/api/telegram-backup/job/<job_id>', methods=['GET'])
@user_management_required
def telegram_backup_job_status(job_id):
    with TELEGRAM_BACKUP_JOBS_LOCK:
        job = _load_telegram_backup_jobs_locked().get(job_id)
        if not job:
            return jsonify({'success': False, 'error': 'Job not found'}), 404
        return jsonify({'success': True, 'job': _summarize_telegram_backup_job(job)})

@app.route('/api/settings/overview', methods=['GET'])
@login_required
def get_settings_overview():
    result = {}

    # Uptime
    result['uptime_seconds'] = int(time.time() - APP_START_TS)

    # Last auto backup
    result['last_backup'] = _get_system_setting_value('last_auto_backup', '') or ''

    # Last Telegram backup
    result['last_telegram_backup'] = _get_system_setting_value('telegram_backup_last_run', '') or ''

    # Database type
    db_url_cfg = app.config.get('SQLALCHEMY_DATABASE_URI', '')
    if db_url_cfg.startswith('postgresql'):
        result['db_type'] = 'PostgreSQL'
        try:
            parsed = urlparse(db_url_cfg)
            result['db_info'] = f"{parsed.hostname}/{(parsed.path or '').lstrip('/')}"
        except Exception:
            result['db_info'] = 'PostgreSQL'
    else:
        result['db_type'] = 'SQLite'
        result['db_info'] = 'Local SQLite'

    # Versions
    result['current_version'] = APP_VERSION
    result['latest_version'] = None
    result['update_available'] = False
    result['is_beta'] = False
    result['release_url'] = ''
    try:
        if UPDATE_CACHE.get('data'):
            result['latest_version'] = UPDATE_CACHE['data'].get('latest_version')
            result['update_available'] = bool(UPDATE_CACHE['data'].get('update_available'))
            result['is_beta'] = bool(UPDATE_CACHE['data'].get('is_beta'))
            result['release_url'] = UPDATE_CACHE['data'].get('release_url', '')
        else:
            resp = requests.get(
                f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest",
                timeout=4
            )
            if resp.status_code == 200:
                gh = resp.json()
                latest_raw = gh.get('tag_name', '').strip().lstrip('vV')
                result['latest_version'] = latest_raw
                result['release_url'] = gh.get('html_url', '')
                try:
                    cur_parts = [int(x) for x in APP_VERSION.split('.')]
                    lat_parts = [int(x) for x in latest_raw.split('.')]
                    while len(cur_parts) < 3: cur_parts.append(0)
                    while len(lat_parts) < 3: lat_parts.append(0)
                    result['update_available'] = lat_parts > cur_parts
                    result['is_beta'] = cur_parts > lat_parts
                except Exception:
                    pass
    except Exception:
        pass

    # SSL info
    cert_path = _get_system_setting_value('ssl_cert_path', '') or ''
    if not cert_path:
        cert_path, _ = _autodetect_ssl_paths()
    ssl_type = 'none'
    ssl_expiry = None
    ssl_issuer = None

    if cert_path and os.path.isfile(cert_path) and os.access(cert_path, os.R_OK):
        # Provisional from path; refined below using the parsed cert.
        if '/etc/letsencrypt/' in cert_path:
            ssl_type = 'letsencrypt'
        elif '/etc/ssl/eve-manager/' in cert_path:
            ssl_type = 'self_signed'
        else:
            ssl_type = 'custom'
        try:
            from cryptography import x509 as _x509
            from cryptography.hazmat.backends import default_backend as _default_backend
            from cryptography.x509.oid import NameOID as _NameOID
            with open(cert_path, 'rb') as f:
                cert = _x509.load_pem_x509_certificate(f.read(), _default_backend())
            # not_valid_after_utc is preferred in newer cryptography; fall back to not_valid_after
            expiry_dt = getattr(cert, 'not_valid_after_utc', None) or cert.not_valid_after
            ssl_expiry = expiry_dt.isoformat()
            try:
                ssl_issuer = cert.issuer.get_attributes_for_oid(_NameOID.COMMON_NAME)[0].value
            except Exception:
                ssl_issuer = None
            # Classify by the cert, not the path (LE certs are copied into the
            # eve-manager dir): self-signed iff issuer DN == subject DN.
            if cert.issuer == cert.subject:
                ssl_type = 'self_signed'
            else:
                _issuer_org = ''
                try:
                    _issuer_org = (cert.issuer.get_attributes_for_oid(_NameOID.ORGANIZATION_NAME)[0].value or '')
                except Exception:
                    _issuer_org = ''
                if '/etc/letsencrypt/' in cert_path or "let's encrypt" in _issuer_org.lower():
                    ssl_type = 'letsencrypt'
                else:
                    ssl_type = 'custom'
        except Exception as exc:
            app.logger.debug(f"SSL cert parse error: {exc}")

    result['ssl_type'] = ssl_type
    result['ssl_expiry'] = ssl_expiry
    result['ssl_issuer'] = ssl_issuer

    # Last usage snapshot
    try:
        last_snap = (UsageSnapshot.query
                     .order_by(UsageSnapshot.recorded_at.desc())
                     .with_entities(UsageSnapshot.recorded_at)
                     .first())
        result['last_snapshot_at'] = (last_snap.recorded_at.isoformat() + 'Z') if last_snap else None
        result['total_snapshots'] = UsageSnapshot.query.count()
    except Exception:
        result['last_snapshot_at'] = None
        result['total_snapshots'] = 0

    return jsonify({'success': True, **result})


def _run_snapshot_with_progress():
    """Background thread: fetch servers one-by-one with progress, then snapshot."""
    global _SNAPSHOT_PROGRESS
    is_fa = False
    try:
        with app.app_context():
            is_fa = _get_panel_ui_lang() == 'fa'
    except Exception:
        pass

    def _msg(en, fa):
        return fa if is_fa else en

    try:
        with app.app_context():
            servers = Server.query.filter_by(enabled=True).all()
            total = len(servers)
            _set_snap_progress({
                'step': 0, 'total': total,
                'message': _msg(f'Fetching {total} server(s)…', f'در حال دریافت {total} سرور…'),
                'message_fa': f'در حال دریافت {total} سرور…',
                'fetched_fresh': False,
            })

            cache_was_empty = not bool(GLOBAL_SERVER_DATA.get('inbounds'))

            admin_user = Admin.query.filter(
                or_(Admin.is_superadmin == True, Admin.role == 'superadmin')
            ).first()
            if not admin_user:
                admin_user = SimpleNamespace(role='superadmin', id=0, is_superadmin=True)

            for i, srv in enumerate(servers, 1):
                _set_snap_progress({
                    'step': i,
                    'current_server': srv.name,
                    'message': _msg(
                        f'Fetching server {i}/{total}: {srv.name}',
                        f'دریافت سرور {i} از {total}: {srv.name}',
                    ),
                })
                try:
                    srv_dict = {
                        'id': srv.id, 'name': srv.name, 'host': srv.host,
                        'username': srv.username, 'password': get_server_password(srv),
                        'api_token': srv.api_token,  # v3 Bearer auth (else cookie login → 403)
                        'panel_type': srv.panel_type, 'sub_port': srv.sub_port,
                        'sub_path': srv.sub_path, 'json_path': srv.json_path,
                    }
                    srv_id, inbounds, online_index, status_payload, status_error, error, detected_type = fetch_worker(srv_dict)
                    if not error:
                        if not isinstance(inbounds, list):
                            inbounds = []
                        processed, stats = process_inbounds(inbounds, srv, admin_user, '*', {}, online_index=online_index)
                        existing = GLOBAL_SERVER_DATA.get('inbounds') or []
                        without = [ib for ib in existing if int(ib.get('server_id', -1)) != int(srv.id)]
                        GLOBAL_SERVER_DATA['inbounds'] = without + list(processed or [])
                        GLOBAL_SERVER_DATA['last_update'] = datetime.utcnow().isoformat()
                except Exception:
                    pass  # keep going for other servers

            inbounds = GLOBAL_SERVER_DATA.get('inbounds') or []
            if not inbounds:
                _set_snap_progress({
                    'status': 'error',
                    'error': _msg(
                        'Fetched all servers but got no inbounds. Check that servers are online and enabled.',
                        'همه سرورها بررسی شدند اما اینباندی یافت نشد. مطمئن شوید سرورها آنلاین و فعال هستند.',
                    ),
                })
                return

            _set_snap_progress({
                'step': total,
                'message': _msg('Taking usage snapshot…', 'در حال ثبت اسنپ‌شات مصرف…'),
            })
            _take_usage_snapshots()

            inbound_count = len(inbounds)
            _set_snap_progress({
                'status': 'done',
                'inbound_count': inbound_count,
                'fetched_fresh': cache_was_empty,
                'message': _msg(
                    f'Done! Snapshot recorded for {inbound_count} inbound(s).{" (cache was empty — fetched fresh data first)" if cache_was_empty else ""}',
                    f'انجام شد! اسنپ‌شات برای {inbound_count} اینباند ثبت شد.{" (کش خالی بود — ابتدا داده‌ها دریافت شدند)" if cache_was_empty else ""}',
                ),
                'error': None,
            })
    except Exception as exc:
        _set_snap_progress({
            'status': 'error',
            'error': str(exc),
        })


@app.route('/api/usage-snapshot/trigger', methods=['POST'])
@user_management_required
def trigger_usage_snapshot():
    """Start a background snapshot task and return immediately."""
    current = _read_snap_progress()
    if current.get('status') == 'running':
        return jsonify({'success': False, 'error': 'A snapshot task is already running.'}), 409
    _set_snap_progress({
        'status': 'running',
        'step': 0, 'total': 0,
        'current_server': '',
        'message': '',
        'inbound_count': 0,
        'fetched_fresh': False,
        'error': None,
    })
    t = threading.Thread(target=_run_snapshot_with_progress, daemon=True)
    t.start()
    return jsonify({'success': True, 'status': 'started'})


@app.route('/api/usage-snapshot/progress', methods=['GET'])
@user_management_required
def snapshot_progress():
    """Return current progress of the running/last snapshot task (cross-worker via shared file)."""
    return jsonify(_read_snap_progress())


@app.route('/traffic-check')
@login_required
def traffic_check_page():
    return render_template('traffic_check.html',
                           admin_username=session.get('admin_username'),
                           is_superadmin=session.get('is_superadmin', False),
                           role=session.get('role', 'admin'))


@app.route('/api/traffic-check', methods=['GET'])
@login_required
def traffic_check():
    """Aggregate snapshot traffic deltas by server → inbound for a given period.
    Optional ?sub_email=x filters to a single client's usage."""
    _TEHRAN_OFFSET = timedelta(hours=3, minutes=30)

    period = (request.args.get('period') or 'today').strip().lower()
    from_ts = request.args.get('from_ts')
    to_ts = request.args.get('to_ts')
    sub_email = (request.args.get('sub_email') or '').strip().lower()

    now_utc = datetime.utcnow()
    now_teh = now_utc + _TEHRAN_OFFSET

    if period == 'custom' and from_ts and to_ts:
        try:
            from_dt = datetime.utcfromtimestamp(int(from_ts) / 1000)
            to_dt = datetime.utcfromtimestamp(int(to_ts) / 1000)
        except Exception:
            return jsonify({'success': False, 'error': 'Invalid timestamps'}), 400
    elif period == 'today':
        teh_midnight = now_teh.replace(hour=0, minute=0, second=0, microsecond=0)
        from_dt = teh_midnight - _TEHRAN_OFFSET
        to_dt = now_utc
    elif period == 'yesterday':
        teh_midnight = now_teh.replace(hour=0, minute=0, second=0, microsecond=0)
        from_dt = (teh_midnight - timedelta(days=1)) - _TEHRAN_OFFSET
        to_dt = teh_midnight - _TEHRAN_OFFSET
    elif period == '7d':
        from_dt = now_utc - timedelta(days=7)
        to_dt = now_utc
    elif period == '30d':
        from_dt = now_utc - timedelta(days=30)
        to_dt = now_utc
    else:
        from_dt = now_teh.replace(hour=0, minute=0, second=0, microsecond=0) - _TEHRAN_OFFSET
        to_dt = now_utc

    try:
        # RBAC: determine what servers/clients this user is allowed to see
        _rbac_role = session.get('role', 'admin')
        _rbac_is_superadmin = session.get('is_superadmin', False)
        _rbac_admin_id = session.get('admin_id')
        _rbac_server_ids = None  # None = no restriction (admin/superadmin)
        _rbac_sub_ids = None     # None = no restriction

        if not _rbac_is_superadmin and _rbac_role == 'reseller':
            _rbac_user = Admin.query.get(_rbac_admin_id)
            if not _rbac_user:
                return jsonify({'success': False, 'error': 'Unauthorized'}), 403
            _allowed_map, _assignments = get_reseller_access_maps(_rbac_user)

            if _allowed_map != '*':
                _rbac_server_ids = set()
                for _sk in list(_allowed_map.keys()) + list(_assignments.keys()):
                    try:
                        _rbac_server_ids.add(int(_sk))
                    except Exception:
                        pass

            _ownerships = ClientOwnership.query.filter_by(reseller_id=_rbac_admin_id).all()
            _owned_emails = {(o.client_email or '').lower() for o in _ownerships if o.client_email}
            _owned_uuids = {(o.client_uuid or '').lower() for o in _ownerships if o.client_uuid}
            _rbac_sub_ids = set()
            for _inb in (GLOBAL_SERVER_DATA.get('inbounds') or []):
                _inb_srv_id = _inb.get('server_id')
                if _rbac_server_ids is not None and _inb_srv_id not in _rbac_server_ids:
                    continue
                _inb_id_val = None
                try:
                    _inb_id_val = int(_inb.get('id'))
                except Exception:
                    pass
                if _allowed_map != '*' and not is_inbound_accessible(_inb_srv_id, _inb_id_val, _allowed_map, _assignments):
                    continue
                for _cli in _inb.get('clients', []):
                    _email = (_cli.get('email') or '').lower()
                    _uuid = (_cli.get('id') or '').lower()
                    if _email in _owned_emails or _uuid in _owned_uuids:
                        _sid = str(_cli.get('subId') or _cli.get('id') or '').strip()
                        if _sid:
                            _rbac_sub_ids.add(_sid)

        servers_map = {s.id: s.name for s in Server.query.all()
                       if _rbac_server_ids is None or s.id in _rbac_server_ids}

        # Build inbound port lookup from live cache
        _inbound_port_map = {}  # {server_id: {remark: {'port': str, 'id': str}}}
        for _inb in (GLOBAL_SERVER_DATA.get('inbounds') or []):
            _srv_id = _inb.get('server_id')
            if _srv_id is None:
                continue
            _remark = (_inb.get('remark') or '').strip()
            _port = str(_inb.get('port') or '')
            _inb_id = str(_inb.get('id') or '')
            _inbound_port_map.setdefault(_srv_id, {})[_remark] = {'port': _port, 'id': _inb_id}

        # Optional: filter by email → find matching sub_ids from cache
        email_sub_ids = None
        email_resolved_name = None
        if sub_email:
            email_sub_ids = set()
            for _inb in (GLOBAL_SERVER_DATA.get('inbounds') or []):
                _inb_srv_id = _inb.get('server_id')
                if _rbac_server_ids is not None and _inb_srv_id not in _rbac_server_ids:
                    continue
                for _cli in _inb.get('clients', []):
                    if (_cli.get('email') or '').strip().lower() == sub_email:
                        _sid = str(_cli.get('subId') or _cli.get('id') or '').strip()
                        if _sid:
                            if _rbac_sub_ids is not None and _sid not in _rbac_sub_ids:
                                continue
                            email_sub_ids.add(_sid)
                            email_resolved_name = (_cli.get('email') or sub_email)
            if not email_sub_ids:
                return jsonify({'success': True, 'servers': [], 'period': period,
                                'from': from_dt.isoformat() + 'Z', 'to': to_dt.isoformat() + 'Z',
                                'message': f'No client found with email: {sub_email}'})

        # All (server_id, inbound_tag, sub_id) combos with data at or before to_dt
        q = (db.session.query(
                UsageSnapshot.server_id,
                UsageSnapshot.inbound_tag,
                UsageSnapshot.sub_id
            )
            .filter(UsageSnapshot.recorded_at <= to_dt)
        )
        if email_sub_ids is not None:
            q = q.filter(UsageSnapshot.sub_id.in_(list(email_sub_ids)))
        elif _rbac_sub_ids is not None:
            q = q.filter(UsageSnapshot.sub_id.in_(list(_rbac_sub_ids)))
        if _rbac_server_ids is not None:
            q = q.filter(UsageSnapshot.server_id.in_(list(_rbac_server_ids)))
        active_subs = q.distinct().all()

        if not active_subs:
            return jsonify({'success': True, 'servers': [], 'period': period,
                            'from': from_dt.isoformat() + 'Z', 'to': to_dt.isoformat() + 'Z',
                            'sub_email': sub_email or None, 'email_resolved_name': email_resolved_name})

        # Deduplicate: same sub_id may appear under NULL tag (old snapshots) AND a real tag.
        # Keep the non-null tag per (server_id, sub_id) to avoid double-counting.
        _dedup: dict = {}
        for _sid, _tag, _sub in active_subs:
            _key = (_sid, _sub)
            if _key not in _dedup or (_dedup[_key] is None and _tag):
                _dedup[_key] = _tag
        active_subs = [(_sid, _tag, _sub) for (_sid, _sub), _tag in _dedup.items()]

        all_sub_ids = list({sub_id for _, _, sub_id in active_subs})

        # ── Build lookups from live cache (memory reads, no SQL) ───────────────
        # sub_id → email for client list display
        sub_id_to_email = {}
        # (server_id, sub_id) → inbound_tag: resolve unknown tags from live data
        sub_id_to_live_tag = {}
        # sub_id → remaining_bytes (None = unlimited)
        sub_id_to_remaining = {}
        # sub_id → 'active' | 'disabled' (absent = deleted — not in live cache)
        sub_id_to_status = {}
        for _inb in (GLOBAL_SERVER_DATA.get('inbounds') or []):
            _srv_id = _inb.get('server_id')
            _remark = (_inb.get('remark') or '').strip()
            for _cli in _inb.get('clients', []):
                _sid = str(_cli.get('subId') or _cli.get('id') or '').strip()
                if not _sid:
                    continue
                _email = (_cli.get('email') or '').strip()
                if _email:
                    sub_id_to_email[_sid] = _email
                if _srv_id is not None and _remark:
                    sub_id_to_live_tag[(_srv_id, _sid)] = _remark
                _rem = _cli.get('remaining_bytes', -1)
                if _rem is not None and _rem >= 0:
                    sub_id_to_remaining[_sid] = int(_rem)
                sub_id_to_status[_sid] = 'disabled' if not _cli.get('enable', True) else 'active'

        # ── BULK QUERY 1: endpoint — latest snapshot per (server_id, sub_id) ≤ to_dt ──
        ep_max_sq = (db.session.query(
                UsageSnapshot.server_id,
                UsageSnapshot.sub_id,
                func.max(UsageSnapshot.recorded_at).label('max_at')
            )
            .filter(UsageSnapshot.sub_id.in_(all_sub_ids))
            .filter(UsageSnapshot.recorded_at <= to_dt)
            .group_by(UsageSnapshot.server_id, UsageSnapshot.sub_id)
            .subquery('ep_max')
        )
        endpoint_map = {
            (s.server_id, s.sub_id): s
            for s in db.session.query(UsageSnapshot).join(ep_max_sq, and_(
                UsageSnapshot.server_id == ep_max_sq.c.server_id,
                UsageSnapshot.sub_id   == ep_max_sq.c.sub_id,
                UsageSnapshot.recorded_at == ep_max_sq.c.max_at
            )).all()
        }

        # ── BULK QUERY 2: baseline — latest snapshot per (server_id, sub_id) ≤ from_dt ──
        bl_max_sq = (db.session.query(
                UsageSnapshot.server_id,
                UsageSnapshot.sub_id,
                func.max(UsageSnapshot.recorded_at).label('max_at')
            )
            .filter(UsageSnapshot.sub_id.in_(all_sub_ids))
            .filter(UsageSnapshot.recorded_at <= from_dt)
            .group_by(UsageSnapshot.server_id, UsageSnapshot.sub_id)
            .subquery('bl_max')
        )
        baseline_map = {
            (s.server_id, s.sub_id): s
            for s in db.session.query(UsageSnapshot).join(bl_max_sq, and_(
                UsageSnapshot.server_id == bl_max_sq.c.server_id,
                UsageSnapshot.sub_id   == bl_max_sq.c.sub_id,
                UsageSnapshot.recorded_at == bl_max_sq.c.max_at
            )).all()
        }

        # ── BULK QUERY 3: first-in-range — for subs with no baseline before from_dt ──
        no_bl_sub_ids = list({sub_id for server_id, _, sub_id in active_subs
                               if (server_id, sub_id) not in baseline_map
                               and (server_id, sub_id) in endpoint_map})
        first_in_range_map = {}
        if no_bl_sub_ids:
            fir_min_sq = (db.session.query(
                    UsageSnapshot.server_id,
                    UsageSnapshot.sub_id,
                    func.min(UsageSnapshot.recorded_at).label('min_at')
                )
                .filter(UsageSnapshot.sub_id.in_(no_bl_sub_ids))
                .filter(UsageSnapshot.recorded_at >= from_dt, UsageSnapshot.recorded_at <= to_dt)
                .group_by(UsageSnapshot.server_id, UsageSnapshot.sub_id)
                .subquery('fir_min')
            )
            first_in_range_map = {
                (s.server_id, s.sub_id): s
                for s in db.session.query(UsageSnapshot).join(fir_min_sq, and_(
                    UsageSnapshot.server_id == fir_min_sq.c.server_id,
                    UsageSnapshot.sub_id   == fir_min_sq.c.sub_id,
                    UsageSnapshot.recorded_at == fir_min_sq.c.min_at
                )).all()
            }

        # ── BULK QUERY 4: first-ever snapshot per server ──────────────────────
        server_first_snap = {
            r[0]: r[1]
            for r in db.session.query(
                UsageSnapshot.server_id,
                func.min(UsageSnapshot.recorded_at)
            ).filter(UsageSnapshot.server_id.in_(list(servers_map.keys())))
             .group_by(UsageSnapshot.server_id).all()
        }

        # ── Aggregation (pure Python, no SQL) ─────────────────────────────────
        result_map = {}
        server_effective_from = {}

        for server_id, inbound_tag, sub_id in active_subs:
            # Resolve tag — fall back to live cache for old NULL tags
            tag = inbound_tag or sub_id_to_live_tag.get((server_id, sub_id)) or '(unknown)'

            endpoint = endpoint_map.get((server_id, sub_id))
            if not endpoint:
                continue

            baseline = baseline_map.get((server_id, sub_id))
            effective_baseline_at = from_dt
            if baseline is None:
                baseline = first_in_range_map.get((server_id, sub_id))
                if baseline:
                    effective_baseline_at = baseline.recorded_at

            base_dl = baseline.download_bytes if baseline else 0
            base_ul = baseline.upload_bytes if baseline else 0
            end_dl = endpoint.download_bytes
            end_ul = endpoint.upload_bytes

            # Handle counter reset (renewal / counter went backwards)
            delta_dl = end_dl - base_dl if end_dl >= base_dl else end_dl
            delta_ul = end_ul - base_ul if end_ul >= base_ul else end_ul
            delta_total = delta_dl + delta_ul

            if delta_total <= 0:
                continue

            cur_eff = server_effective_from.get(server_id)
            if cur_eff is None or effective_baseline_at < cur_eff:
                server_effective_from[server_id] = effective_baseline_at

            if server_id not in result_map:
                result_map[server_id] = {}
            if tag not in result_map[server_id]:
                _port_info = _inbound_port_map.get(server_id, {}).get(inbound_tag or tag, {})
                result_map[server_id][tag] = {
                    'download': 0, 'upload': 0, 'total': 0, 'clients': 0,
                    'remaining_raw': 0,
                    'port': _port_info.get('port', ''),
                    'inbound_id': _port_info.get('id', ''),
                    'client_list': [],
                }

            result_map[server_id][tag]['download'] += delta_dl
            result_map[server_id][tag]['upload'] += delta_ul
            result_map[server_id][tag]['total'] += delta_total
            result_map[server_id][tag]['clients'] += 1
            _client_rem = sub_id_to_remaining.get(sub_id)
            if _client_rem is not None:
                result_map[server_id][tag]['remaining_raw'] += _client_rem

            client_email = sub_id_to_email.get(sub_id, '')
            _live_status = sub_id_to_status.get(sub_id)  # None = not in live cache = deleted
            result_map[server_id][tag]['client_list'].append({
                'email': client_email or (sub_id[:12] + '…') if sub_id else '—',
                'download': delta_dl,
                'upload': delta_ul,
                'total': delta_total,
                'remaining': _client_rem,
                'status': 'deleted' if _live_status is None else ('disabled' if _live_status == 'disabled' else None),
            })

        servers_out = []
        for server_id, inbounds_map in sorted(result_map.items(), key=lambda x: -sum(v['total'] for v in x[1].values())):
            inbounds_out = sorted([
                {
                    'inbound_tag': tag,
                    'port': data['port'],
                    'inbound_id': data['inbound_id'],
                    'download': data['download'],
                    'upload': data['upload'],
                    'total': data['total'],
                    'clients': data['clients'],
                    'remaining_raw': data['remaining_raw'],
                    'remaining': format_bytes(data['remaining_raw']) if data['remaining_raw'] > 0 else None,
                    'client_list': sorted(data['client_list'], key=lambda c: -c['total']),
                }
                for tag, data in inbounds_map.items()
            ], key=lambda x: -x['total'])

            srv_total = sum(i['total'] for i in inbounds_out)
            srv_dl = sum(i['download'] for i in inbounds_out)
            srv_ul = sum(i['upload'] for i in inbounds_out)
            srv_remaining_raw = sum(i['remaining_raw'] for i in inbounds_out)
            first_at = server_first_snap.get(server_id)
            eff_from = server_effective_from.get(server_id)

            servers_out.append({
                'server_id': server_id,
                'server_name': servers_map.get(server_id, f'Server {server_id}'),
                'total': srv_total,
                'download': srv_dl,
                'upload': srv_ul,
                'remaining_raw': srv_remaining_raw,
                'remaining': format_bytes(srv_remaining_raw) if srv_remaining_raw > 0 else None,
                'inbounds': inbounds_out,
                'first_snapshot_at': (first_at.isoformat() + 'Z') if first_at else None,
                'effective_from': (eff_from.isoformat() + 'Z') if eff_from else None,
            })

        return jsonify({
            'success': True,
            'period': period,
            'from': from_dt.isoformat() + 'Z',
            'to': to_dt.isoformat() + 'Z',
            'servers': servers_out,
            'sub_email': sub_email or None,
            'email_resolved_name': email_resolved_name,
        })
    except Exception as e:
        app.logger.exception("traffic_check error")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/settings/ssl/diagnose', methods=['GET'])
@login_required
def diagnose_ssl():
    """Figure out where HTTPS is actually coming from for THIS request.

    Three cases the panel could be in:
      1. own_ssl  — origin server has its own cert (nginx serves HTTPS directly)
      2. cdn_ssl  — a CDN (e.g. Cloudflare) terminates TLS at the edge; the
                    origin may be plain HTTP (browser still shows the padlock)
      3. none     — no SSL anywhere; served over plain HTTP

    We read the headers of the admin's own request (which reflect exactly how
    their browser reached the panel) plus the origin certificate status.
    """
    h = request.headers

    # --- CDN detection (Cloudflare is the common one) ---
    cf_ray = h.get('CF-Ray')
    cf_conn_ip = h.get('CF-Connecting-IP')
    cf_visitor = (h.get('CF-Visitor') or '').lower()
    via = h.get('Via') or ''
    behind_cloudflare = bool(cf_ray or cf_conn_ip)
    # Other CDNs / proxies leave a trail in Via or known headers
    other_cdn = None
    for hdr, name in (('X-Sucuri-ID', 'Sucuri'), ('X-Fastly-Request-ID', 'Fastly'),
                      ('X-Amz-Cf-Id', 'CloudFront'), ('X-Cache', 'Generic CDN')):
        if h.get(hdr):
            other_cdn = name
            break

    # --- Edge scheme: what scheme did the END USER's browser use? ---
    # CF-Visitor carries the real client scheme even when CF→origin is HTTP.
    xfp = (h.get('X-Forwarded-Proto') or '').lower()
    xfp_first = xfp.split(',')[0].strip() if xfp else ''
    edge_https = (
        'https' in cf_visitor
        or xfp_first == 'https'
        or bool(request.is_secure)
    )

    # --- Origin certificate status (reuse autodetect) ---
    cert_path, key_path = _autodetect_ssl_paths()
    # also honor an explicitly saved path
    saved_cert = db.session.get(SystemSetting, 'ssl_cert_path')
    if saved_cert and saved_cert.value:
        cert_path = saved_cert.value
    origin_has_cert = bool(cert_path) and os.path.isfile(cert_path) and os.access(cert_path, os.R_OK)

    # --- Verdict ---
    if behind_cloudflare or other_cdn:
        cdn_name = 'Cloudflare' if behind_cloudflare else other_cdn
        if origin_has_cert:
            mode = 'cdn_plus_origin'
            title = f'HTTPS via {cdn_name} (origin also has a certificate)'
            detail = (f'You are reaching the panel through {cdn_name}, which provides the '
                      f'browser padlock. Your origin server ALSO has its own certificate, '
                      f'so a Full/Strict CDN SSL mode works and direct access stays secure.')
        else:
            mode = 'cdn_only'
            title = f'HTTPS is provided by {cdn_name} — your server has NO certificate'
            detail = (f'The padlock you see comes from {cdn_name} at the edge. Your origin '
                      f'server itself has no SSL certificate. If you turn off the CDN proxy '
                      f'(grey-cloud the DNS record) the panel will fall back to plain HTTP, '
                      f'and any subscription/dash links that depend on HTTPS may break. '
                      f'Consider installing a free Origin/Let\'s Encrypt cert too.')
    elif origin_has_cert and edge_https:
        mode = 'own_ssl'
        title = 'Your server has its own SSL certificate (direct HTTPS)'
        detail = 'No CDN detected. nginx is serving HTTPS directly from a certificate on this server.'
    elif edge_https:
        mode = 'edge_only'
        title = 'HTTPS detected, but no certificate found on this server'
        detail = ('The connection looks secure but no certificate file was found on the origin. '
                  'A reverse proxy or load balancer in front is likely terminating TLS.')
    else:
        mode = 'none'
        title = 'No SSL — the panel is served over plain HTTP'
        detail = ('No CDN and no certificate detected, and this request is not HTTPS. '
                  'Install a certificate (Settings → SSL) or put the domain behind a CDN.')

    return jsonify({
        'success': True,
        'mode': mode,
        'title': title,
        'detail': detail,
        'edge_https': edge_https,
        'behind_cdn': bool(behind_cloudflare or other_cdn),
        'cdn': ('Cloudflare' if behind_cloudflare else other_cdn),
        'origin_has_cert': origin_has_cert,
        'origin_cert_path': cert_path or None,
        'request_scheme': request.scheme,
        'signals': {
            'cf_ray': bool(cf_ray),
            'cf_connecting_ip': bool(cf_conn_ip),
            'cf_visitor': cf_visitor or None,
            'x_forwarded_proto': xfp or None,
            'via': via or None,
            'host': h.get('Host'),
        },
    })


@app.route('/api/settings/ssl', methods=['GET'])
@login_required
def get_ssl_settings():
    cert = db.session.get(SystemSetting, 'ssl_cert_path')
    key = db.session.get(SystemSetting, 'ssl_key_path')
    cert_path = cert.value if cert else ''
    key_path = key.value if key else ''

    auto_detected = False
    if not cert_path and not key_path:
        detected_cert, detected_key = _autodetect_ssl_paths()
        if detected_cert and detected_key:
            cert_path = detected_cert
            key_path = detected_key
            auto_detected = True
            # Persist so the settings page shows the correct state going forward
            try:
                c_row = SystemSetting(key='ssl_cert_path', value=cert_path)
                k_row = SystemSetting(key='ssl_key_path', value=key_path)
                db.session.merge(c_row)
                db.session.merge(k_row)
                db.session.commit()
            except Exception:
                db.session.rollback()

    cert_ok = bool(cert_path) and os.path.isfile(cert_path) and os.access(cert_path, os.R_OK)
    key_ok = bool(key_path) and os.path.isfile(key_path) and os.access(key_path, os.R_OK)

    if cert_path or key_path:
        ssl_status = 'active' if (cert_ok and key_ok) else 'error'
    else:
        ssl_status = 'not_configured'

    # Provisional SSL type from path; refined below once the cert is parsed.
    ssl_type = 'none'
    if cert_path:
        if '/etc/letsencrypt/' in cert_path:
            ssl_type = 'letsencrypt'
        elif '/etc/ssl/eve-manager/' in cert_path:
            ssl_type = 'self_signed'
        elif cert_path:
            ssl_type = 'custom'

    # Parse cert metadata
    cert_expiry = None
    cert_issuer = None
    cert_subject = None
    if cert_ok:
        try:
            from cryptography import x509 as _x509
            from cryptography.hazmat.backends import default_backend as _default_backend
            from cryptography.x509.oid import NameOID as _NameOID
            with open(cert_path, 'rb') as _f:
                _cert = _x509.load_pem_x509_certificate(_f.read(), _default_backend())
            _exp = getattr(_cert, 'not_valid_after_utc', None) or _cert.not_valid_after
            cert_expiry = _exp.isoformat()
            try:
                cert_issuer = _cert.issuer.get_attributes_for_oid(_NameOID.COMMON_NAME)[0].value
            except Exception:
                cert_issuer = None
            try:
                cert_subject = _cert.subject.get_attributes_for_oid(_NameOID.COMMON_NAME)[0].value
            except Exception:
                cert_subject = None
            # Classify by the cert itself, not the file path: a real Let's Encrypt
            # cert is copied into /etc/ssl/eve-manager/ so path-based detection
            # mislabels it "self_signed". Self-signed iff issuer DN == subject DN.
            if _cert.issuer == _cert.subject:
                ssl_type = 'self_signed'
            else:
                _issuer_org = ''
                try:
                    _issuer_org = (_cert.issuer.get_attributes_for_oid(_NameOID.ORGANIZATION_NAME)[0].value or '')
                except Exception:
                    _issuer_org = ''
                if '/etc/letsencrypt/' in cert_path or "let's encrypt" in _issuer_org.lower():
                    ssl_type = 'letsencrypt'
                else:
                    ssl_type = 'custom'
        except Exception:
            pass

    return jsonify({
        'success': True,
        'cert_path': cert_path,
        'key_path': key_path,
        'cert_ok': cert_ok,
        'key_ok': key_ok,
        'ssl_status': ssl_status,
        'ssl_type': ssl_type,
        'cert_expiry': cert_expiry,
        'cert_issuer': cert_issuer,
        'cert_subject': cert_subject,
        'auto_detected': auto_detected
    })

@app.route('/api/settings/ssl', methods=['POST'])
@login_required
def save_ssl_settings():
    data = request.json
    cert_path = data.get('cert_path', '').strip()
    key_path = data.get('key_path', '').strip()

    # Both must be provided together or both empty
    if bool(cert_path) != bool(key_path):
        missing = 'Private key path' if cert_path else 'Certificate path'
        return jsonify({'success': False, 'error': f'{missing} is required'}), 400

    if cert_path:
        if not os.path.isfile(cert_path):
            return jsonify({'success': False, 'error': f'Certificate file not found: {cert_path}'}), 400
        if not os.access(cert_path, os.R_OK):
            return jsonify({'success': False, 'error': f'Certificate file is not readable (check permissions): {cert_path}'}), 400

    if key_path:
        if not os.path.isfile(key_path):
            return jsonify({'success': False, 'error': f'Private key file not found: {key_path}'}), 400
        if not os.access(key_path, os.R_OK):
            return jsonify({'success': False, 'error': f'Private key file is not readable (check permissions): {key_path}'}), 400

    cert_setting = db.session.get(SystemSetting, 'ssl_cert_path')
    if not cert_setting:
        cert_setting = SystemSetting(key='ssl_cert_path', value=cert_path)
        db.session.add(cert_setting)
    else:
        cert_setting.value = cert_path

    key_setting = db.session.get(SystemSetting, 'ssl_key_path')
    if not key_setting:
        key_setting = SystemSetting(key='ssl_key_path', value=key_path)
        db.session.add(key_setting)
    else:
        key_setting.value = key_path

    db.session.commit()

    if cert_path and key_path:
        return jsonify({'success': True, 'message': 'SSL settings saved. Certificate and key files verified.'})
    return jsonify({'success': True, 'message': 'SSL configuration cleared.'})


# ── SSL Sync — copy LetsEncrypt certs to /etc/ssl/eve-manager/ via sudo ──────
@app.route('/api/settings/ssl/sync', methods=['POST'])
@login_required
def ssl_sync():
    """Copy LetsEncrypt cert+key to /etc/ssl/eve-manager/.

    Strategy (no broad sudo needed):
    - /etc/ssl/eve-manager/ must be owned by evemgr (one-time admin setup)
    - Only `sudo cat` is used to read the protected privkey.pem
    - Everything else is done directly as evemgr

    If the destination dir isn't writable, a clear fix command is returned.
    """
    import glob as _glob, re as _re

    FIX_CMD = (
        "sudo bash -c '"
        "mkdir -p /etc/ssl/eve-manager && "
        "chown evemgr:evemgr /etc/ssl/eve-manager && "
        "chmod 700 /etc/ssl/eve-manager && "
        "cat > /etc/sudoers.d/eve-ssl <<EOF\n"
        "evemgr ALL=(root) NOPASSWD: /bin/cat /etc/letsencrypt/live/*/fullchain.pem\n"
        "evemgr ALL=(root) NOPASSWD: /bin/cat /etc/letsencrypt/live/*/privkey.pem\n"
        "evemgr ALL=(root) NOPASSWD: /bin/cat /etc/letsencrypt/archive/*/fullchain*.pem\n"
        "evemgr ALL=(root) NOPASSWD: /bin/cat /etc/letsencrypt/archive/*/privkey*.pem\n"
        "evemgr ALL=(root) NOPASSWD: /bin/systemctl reload nginx\n"
        "evemgr ALL=(root) NOPASSWD: /usr/sbin/nginx -t\n"
        "evemgr ALL=(root) NOPASSWD: /usr/bin/tee /etc/nginx/sites-available/eve-manager\n"
        "EOF\n"
        "chmod 440 /etc/sudoers.d/eve-ssl'"
    )

    dest_dir  = '/etc/ssl/eve-manager'
    cert_dest = os.path.join(dest_dir, 'fullchain.pem')
    key_dest  = os.path.join(dest_dir, 'privkey.pem')

    # Check destination directory is writable (owned by evemgr)
    if not os.path.isdir(dest_dir) or not os.access(dest_dir, os.W_OK):
        return jsonify({
            'success': False,
            'error': (
                f'/etc/ssl/eve-manager/ does not exist or is not writable by the app user.\n'
                f'Run this command on the server once, then try again:\n\n{FIX_CMD}'
            ),
            'fix_command': FIX_CMD,
        }), 500

    # Find source cert paths
    cert_src = key_src = ''
    for _nc in ['/etc/nginx/sites-available/eve-manager',
                '/etc/nginx/sites-enabled/eve-manager',
                '/etc/nginx/sites-available/eve-xui-manager']:
        if not os.path.isfile(_nc):
            continue
        try:
            with open(_nc, 'r', errors='ignore') as _f:
                _conf = _f.read()
            _cm = _re.search(r'ssl_certificate\s+([^;]+);', _conf)
            _km = _re.search(r'ssl_certificate_key\s+([^;]+);', _conf)
            if _cm and _km:
                cert_src = _cm.group(1).strip()
                key_src  = _km.group(1).strip()
                break
        except Exception:
            pass

    if not cert_src:
        for _lc in sorted(_glob.glob('/etc/letsencrypt/live/*/fullchain.pem')):
            cert_src = _lc
            key_src  = os.path.join(os.path.dirname(_lc), 'privkey.pem')
            break

    if not cert_src or not key_src:
        return jsonify({'success': False,
                        'error': 'Cannot find SSL cert paths. Is nginx configured with SSL?'}), 400

    # Read cert — usually world-readable
    try:
        with open(cert_src, 'rb') as _f:
            cert_data = _f.read()
    except PermissionError:
        r = subprocess.run(['sudo', 'cat', cert_src], capture_output=True, timeout=10)
        if r.returncode != 0:
            return jsonify({'success': False,
                            'error': f'Cannot read certificate: {r.stderr.decode().strip()}\n\nRun: {FIX_CMD}',
                            'fix_command': FIX_CMD}), 500
        cert_data = r.stdout

    # Read private key — typically mode 600, needs sudo cat
    try:
        with open(key_src, 'rb') as _f:
            key_data = _f.read()
    except PermissionError:
        r = subprocess.run(['sudo', 'cat', key_src], capture_output=True, timeout=10)
        if r.returncode != 0:
            err = r.stderr.decode().strip()
            if 'password' in err or 'askpass' in err:
                return jsonify({
                    'success': False,
                    'error': f'sudo not configured for this app user.\n\nRun this on the server:\n\n{FIX_CMD}',
                    'fix_command': FIX_CMD,
                }), 500
            return jsonify({'success': False,
                            'error': f'Cannot read private key: {err}'}), 500
        key_data = r.stdout

    # Write directly — evemgr owns the dir, no sudo needed
    with open(cert_dest, 'wb') as _f:
        _f.write(cert_data)
    os.chmod(cert_dest, 0o644)

    with open(key_dest, 'wb') as _f:
        _f.write(key_data)
    os.chmod(key_dest, 0o600)

    # Persist paths in DB
    for k, v in [('ssl_cert_path', cert_dest), ('ssl_key_path', key_dest)]:
        row = db.session.get(SystemSetting, k) or SystemSetting(key=k, value=v)
        row.value = v
        db.session.merge(row)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': f'Synced → {dest_dir}/',
        'cert_path': cert_dest,
        'key_path':  key_dest,
        'source_cert': cert_src,
    })


# ── SSL Export — download cert + key as a zip ───────────────────────────────
@app.route('/api/settings/ssl/export')
@login_required
def ssl_export():
    """Return a zip containing the SSL certificate and private key."""
    import zipfile, io as _io

    cert = db.session.get(SystemSetting, 'ssl_cert_path')
    key  = db.session.get(SystemSetting, 'ssl_key_path')
    cert_path = (cert.value if cert else '').strip()
    key_path  = (key.value  if key  else '').strip()

    # Auto-detect if not saved
    if not cert_path or not key_path:
        cert_path, key_path = _autodetect_ssl_paths()

    # If still not found, try syncing from LetsEncrypt first
    if not cert_path or not key_path:
        return jsonify({
            'success': False,
            'error': 'SSL certificate not configured. Click "Sync from LetsEncrypt" first.'
        }), 400

    # Try to read — if permission denied, suggest sync
    errors = []
    for label, path in [('Certificate', cert_path), ('Private key', key_path)]:
        if not path or not os.path.isfile(path):
            errors.append(f'{label} file not found: {path or "(empty)"}')
        elif not os.access(path, os.R_OK):
            errors.append(f'{label} not readable (permission denied): {path} — click "Sync from LetsEncrypt" to fix')
    if errors:
        return jsonify({'success': False, 'error': ' | '.join(errors)}), 400

    buf = _io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.write(cert_path, 'ssl/fullchain.pem')
        zf.write(key_path,  'ssl/privkey.pem')
    buf.seek(0)

    return send_file(
        buf,
        mimetype='application/zip',
        as_attachment=True,
        download_name='eve-ssl-bundle.zip',
    )


# ── SSL Upload — receive zip, extract cert+key ──────────────────────────────
SSL_DEST_DIR = '/etc/ssl/eve-manager'

@app.route('/api/settings/ssl/upload', methods=['POST'])
@login_required
def ssl_upload():
    """Accept a zip (with fullchain.pem + privkey.pem) or two individual files.

    Strategy:
    1. Write uploaded files to a temp dir that evemgr CAN write to (/tmp)
    2. Use sudo cp/mkdir/chown/chmod to install them under /etc/ssl/eve-manager/
       (sudoers entry created by setup.sh)
    """
    import zipfile, tempfile

    tmp_dir = tempfile.mkdtemp(prefix='eve-ssl-upload-')
    tmp_cert = os.path.join(tmp_dir, 'fullchain.pem')
    tmp_key  = os.path.join(tmp_dir, 'privkey.pem')

    try:
        if 'ssl_zip' in request.files:
            zf_file = request.files['ssl_zip']
            if not zf_file.filename.lower().endswith('.zip'):
                return jsonify({'success': False, 'error': 'Expected a .zip file'}), 400
            raw = zf_file.read()
            try:
                with zipfile.ZipFile(_io_BytesIO(raw)) as zf:
                    names = zf.namelist()
                    cert_member = next(
                        (n for n in names if n.endswith('fullchain.pem')
                         or n.endswith('.crt') or n.endswith('.cer')), None)
                    key_member = next(
                        (n for n in names if n.endswith('privkey.pem')
                         or n.endswith('.key')), None)
                    if not cert_member or not key_member:
                        return jsonify({'success': False,
                                        'error': 'Zip must contain fullchain.pem (or .crt) and privkey.pem (or .key)'}), 400
                    with open(tmp_cert, 'wb') as f:
                        f.write(zf.read(cert_member))
                    with open(tmp_key, 'wb') as f:
                        f.write(zf.read(key_member))
            except zipfile.BadZipFile:
                return jsonify({'success': False, 'error': 'Invalid zip file'}), 400

        elif 'cert_file' in request.files and 'key_file' in request.files:
            request.files['cert_file'].save(tmp_cert)
            request.files['key_file'].save(tmp_key)
        else:
            return jsonify({'success': False, 'error': 'Send ssl_zip OR cert_file+key_file'}), 400

        # Sanity check: must be PEM text
        with open(tmp_cert, 'r', errors='ignore') as _f:
            _head = _f.read(64)
        if '-----BEGIN' not in _head:
            return jsonify({'success': False,
                            'error': 'Certificate does not look like PEM — check the file'}), 400

        cert_dest = f'{SSL_DEST_DIR}/fullchain.pem'
        key_dest  = f'{SSL_DEST_DIR}/privkey.pem'

        FIX_CMD = (
            "sudo bash -c '"
            "mkdir -p /etc/ssl/eve-manager && "
            "chown evemgr:evemgr /etc/ssl/eve-manager && "
            "chmod 700 /etc/ssl/eve-manager && "
            "cat > /etc/sudoers.d/eve-ssl <<EOF\n"
            "evemgr ALL=(root) NOPASSWD: /bin/cat /etc/letsencrypt/live/*/fullchain.pem\n"
            "evemgr ALL=(root) NOPASSWD: /bin/cat /etc/letsencrypt/live/*/privkey.pem\n"
            "evemgr ALL=(root) NOPASSWD: /bin/cat /etc/letsencrypt/archive/*/fullchain*.pem\n"
            "evemgr ALL=(root) NOPASSWD: /bin/cat /etc/letsencrypt/archive/*/privkey*.pem\n"
            "evemgr ALL=(root) NOPASSWD: /bin/systemctl reload nginx\n"
            "evemgr ALL=(root) NOPASSWD: /usr/sbin/nginx -t\n"
            "evemgr ALL=(root) NOPASSWD: /usr/bin/tee /etc/nginx/sites-available/eve-manager\n"
            "EOF\n"
            "chmod 440 /etc/sudoers.d/eve-ssl'"
        )

        # /etc/ssl/eve-manager/ must be owned by evemgr (one-time setup).
        # Then we write directly — no sudo needed at all for upload.
        if not os.path.isdir(SSL_DEST_DIR) or not os.access(SSL_DEST_DIR, os.W_OK):
            return jsonify({
                'success': False,
                'error': (
                    f'{SSL_DEST_DIR}/ does not exist or is not writable.\n'
                    f'Run this on the server once:\n\n{FIX_CMD}'
                ),
                'fix_command': FIX_CMD,
            }), 500

        import shutil as _shutil
        _shutil.copy2(tmp_cert, cert_dest)
        os.chmod(cert_dest, 0o644)
        _shutil.copy2(tmp_key, key_dest)
        os.chmod(key_dest, 0o600)

    finally:
        # Always clean up temp files
        import shutil as _sh
        _sh.rmtree(tmp_dir, ignore_errors=True)

    # Persist paths in DB
    for k, v in [('ssl_cert_path', cert_dest), ('ssl_key_path', key_dest)]:
        row = db.session.get(SystemSetting, k) or SystemSetting(key=k, value=v)
        row.value = v
        db.session.merge(row)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': f'SSL files installed to {SSL_DEST_DIR}/',
        'cert_path': cert_dest,
        'key_path':  key_dest,
    })


def _io_BytesIO(data):
    import io
    return io.BytesIO(data)


# ── SSL Apply — write nginx config + reload ─────────────────────────────────
@app.route('/api/settings/ssl/apply', methods=['POST'])
@login_required
def ssl_apply():
    """Write HTTPS nginx config and reload nginx."""
    import re as _re

    cert = db.session.get(SystemSetting, 'ssl_cert_path')
    key  = db.session.get(SystemSetting, 'ssl_key_path')
    cert_path = (cert.value if cert else '').strip()
    key_path  = (key.value  if key  else '').strip()

    if not cert_path or not key_path:
        return jsonify({'success': False, 'error': 'SSL paths not configured. Upload or enter paths first.'}), 400

    if not os.path.isfile(cert_path):
        return jsonify({'success': False, 'error': f'Certificate not found: {cert_path}'}), 400
    if not os.path.isfile(key_path):
        return jsonify({'success': False, 'error': f'Private key not found: {key_path}'}), 400

    # Detect domain from existing nginx config
    domain = ''
    nginx_conf_path = '/etc/nginx/sites-available/eve-manager'
    try:
        with open(nginx_conf_path, 'r', errors='ignore') as _f:
            _m = _re.search(r'server_name\s+([^;]+);', _f.read())
            if _m:
                domain = _m.group(1).strip().split()[0]
    except Exception:
        pass

    if not domain:
        data = request.get_json(silent=True) or {}
        domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({'success': False, 'error': 'Cannot detect domain. Pass {"domain":"your.domain"} in request body.'}), 400

    app_port = os.environ.get('API_PORT', '5000')

    nginx_config = f"""server {{
    listen 80;
    server_name {domain};
    return 301 https://$host$request_uri;
}}

server {{
    listen 443 ssl;
    server_name {domain};

    ssl_certificate     {cert_path};
    ssl_certificate_key {key_path};
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    client_max_body_size 512m;

    location ~* /stream$ {{
        proxy_pass http://127.0.0.1:{app_port};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_http_version 1.1;
        proxy_set_header Connection '';
    }}

    location / {{
        proxy_pass http://127.0.0.1:{app_port};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 600s;
        proxy_send_timeout 600s;
        proxy_request_buffering off;
    }}
}}
"""

    # Write config via sudo tee (evemgr needs sudo tee permission — added in setup.sh)
    try:
        result = subprocess.run(
            ['sudo', 'tee', nginx_conf_path],
            input=nginx_config, text=True,
            capture_output=True, timeout=10,
        )
        if result.returncode != 0:
            return jsonify({'success': False,
                            'error': f'Could not write nginx config: {result.stderr.strip()}'}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': f'Failed to write nginx config: {e}'}), 500

    # Test nginx config
    test = subprocess.run(['sudo', 'nginx', '-t'], capture_output=True, text=True, timeout=10)
    if test.returncode != 0:
        return jsonify({'success': False,
                        'error': f'nginx config test failed:\n{test.stderr.strip()}'}), 500

    # Reload nginx
    reload_r = subprocess.run(['sudo', 'systemctl', 'reload', 'nginx'],
                              capture_output=True, text=True, timeout=15)
    if reload_r.returncode != 0:
        return jsonify({'success': False,
                        'error': f'nginx reload failed: {reload_r.stderr.strip()}'}), 500

    return jsonify({
        'success': True,
        'message': f'SSL applied — nginx reloaded. Site is now HTTPS on {domain}',
        'domain': domain,
    })


@app.route('/api/settings/session', methods=['GET'])
@login_required
def get_session_settings():
    setting = db.session.get(SystemSetting, 'session_timeout_hours')
    return jsonify({
        'success': True,
        'timeout_hours': int(setting.value) if setting else 168 # Default 7 days = 168 hours
    })

@app.route('/api/settings/session', methods=['POST'])
@login_required
def save_session_settings():
    data = request.json
    try:
        hours = int(data.get('timeout_hours', 168))
        if hours < 1:
            return jsonify({'success': False, 'message': 'Timeout must be at least 1 hour'}), 400
            
        setting = db.session.get(SystemSetting, 'session_timeout_hours')
        if not setting:
            setting = SystemSetting(key='session_timeout_hours', value=str(hours))
            db.session.add(setting)
        else:
            setting.value = str(hours)
            
        db.session.commit()
        
        # Update config immediately
        app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=hours)
        
        return jsonify({'success': True, 'message': 'Session settings saved'})
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid value'}), 400


# ---------------------------------------------------------------------------
# Health Logs API
# ---------------------------------------------------------------------------
@app.route('/api/settings/health-logs', methods=['GET'])
@login_required
def get_health_logs():
    """Paginated health logs for the Settings > System Logs tab."""
    user = db.session.get(Admin, session['admin_id'])
    if not user or not user.is_superadmin:
        return jsonify({'success': False, 'message': 'Forbidden'}), 403

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    level = request.args.get('level', '')
    category = request.args.get('category', '')

    query = HealthLog.query
    if level:
        query = query.filter(HealthLog.level == level)
    if category:
        query = query.filter(HealthLog.category == category)

    pagination = query.order_by(HealthLog.id.desc()).paginate(
        page=page, per_page=min(per_page, 200), error_out=False
    )
    return jsonify({
        'success': True,
        'logs': [l.to_dict() for l in pagination.items],
        'total': pagination.total,
        'page': pagination.page,
        'pages': pagination.pages,
    })


@app.route('/api/settings/health-logs/clear', methods=['POST'])
@login_required
def clear_health_logs():
    """Delete all health logs."""
    user = db.session.get(Admin, session['admin_id'])
    if not user or not user.is_superadmin:
        return jsonify({'success': False, 'message': 'Forbidden'}), 403
    try:
        deleted = HealthLog.query.delete()
        db.session.commit()
        return jsonify({'success': True, 'message': f'Cleared {deleted} log entries'})
    except Exception as exc:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(exc)}), 500


@app.route('/api/settings/health-logs/run-check', methods=['POST'])
@login_required
def run_health_check_now():
    """Trigger a manual health-check cycle and return results."""
    user = db.session.get(Admin, session['admin_id'])
    if not user or not user.is_superadmin:
        return jsonify({'success': False, 'message': 'Forbidden'}), 403
    try:
        results = _run_single_health_cycle()
        summary = {}
        for key, (ok, detail) in results.items():
            summary[key] = {'ok': ok, 'detail': str(detail) if detail else None}
        _add_health_log('info', 'general', 'Manual health check triggered by admin',
                        details=summary, resolved=True)
        return jsonify({'success': True, 'results': summary})
    except Exception as exc:
        return jsonify({'success': False, 'message': str(exc)}), 500


@app.route('/api/renew-templates', methods=['GET'])
@user_management_required
def get_renew_templates():
    templates = RenewTemplate.query.order_by(RenewTemplate.created_at.desc()).all()
    return jsonify({
        'success': True, 
        'templates': [t.to_dict() for t in templates],
        'available_vars': [
            '{email}', '{days}', '{days_label}', '{volume}', '{volume_label}', '{date}', '{server_name}', '{mode}', '{dashboard_link}'
        ]
    })

@app.route('/api/renew-templates', methods=['POST'])
@user_management_required
def create_renew_template():
    data = request.get_json()
    name = data.get('name')
    content = data.get('content')
    if not name or not content:
        return jsonify({'success': False, 'error': 'Name and content are required'}), 400

    template = RenewTemplate(name=name, content=content)
    db.session.add(template)
    db.session.commit()

    if RenewTemplate.query.count() == 1:
        template.is_active = True
        db.session.commit()

    return jsonify({'success': True, 'template': template.to_dict()})

@app.route('/api/renew-templates/<int:template_id>', methods=['PUT'])
@user_management_required
def update_renew_template(template_id):
    template = db.session.get(RenewTemplate, template_id)
    if not template:
        return jsonify({'success': False, 'error': 'Template not found'}), 404
    
    data = request.get_json()
    template.name = data.get('name', template.name)
    template.content = data.get('content', template.content)
    db.session.commit()
    return jsonify({'success': True, 'template': template.to_dict()})

@app.route('/api/renew-templates/<int:template_id>', methods=['DELETE'])
@user_management_required
def delete_renew_template(template_id):
    template = db.session.get(RenewTemplate, template_id)
    if not template:
        return jsonify({'success': False, 'error': 'Template not found'}), 404
    if template.is_active:
        return jsonify({'success': False, 'error': 'Cannot delete active template'}), 400
    
    db.session.delete(template)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/renew-templates/<int:template_id>/activate', methods=['POST'])
@user_management_required
def activate_renew_template(template_id):
    template = db.session.get(RenewTemplate, template_id)
    if not template:
        return jsonify({'success': False, 'error': 'Template not found'}), 404
    
    # Deactivate all others
    RenewTemplate.query.update({RenewTemplate.is_active: False})
    template.is_active = True
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/backups/<filename>/download', methods=['GET'])
@login_required
def download_backup(filename):
    filename = secure_filename(filename)
    path = os.path.join(BACKUP_DIR, filename)
    if not os.path.exists(path):
        return jsonify({'success': False, 'error': 'File not found'}), 404
    file_size = os.path.getsize(path)
    # Files >50 MB: let nginx stream directly via X-Accel-Redirect so the
    # gunicorn worker is freed immediately and never times out mid-download.
    # Requires the /protected-backups/ internal location in nginx.conf.
    # Falls back to send_file when accessed without nginx (dev / direct).
    behind_nginx = bool(request.headers.get('X-Forwarded-For') or
                        request.headers.get('X-Real-IP'))
    if behind_nginx and file_size > 50 * 1024 * 1024:
        resp = make_response()
        resp.headers['X-Accel-Redirect'] = f'/protected-backups/{filename}'
        resp.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        resp.headers['Content-Type'] = 'application/octet-stream'
        resp.headers['Content-Length'] = str(file_size)
        return resp
    return send_file(path, as_attachment=True)

@app.route('/api/backups/<filename>/restore', methods=['POST'])
@login_required
def restore_backup(filename):
    filename = secure_filename(filename)
    backup_path = os.path.join(BACKUP_DIR, filename)
    if not os.path.exists(backup_path):
        return jsonify({'success': False, 'error': 'Backup not found'}), 404

    ext = os.path.splitext(filename)[1].lower()

    try:
        if _is_sqlite_db():
            if ext != '.db':
                return jsonify({'success': False, 'error': 'SQLite databases require a .db backup file'}), 400
            db_path = os.path.join(app.instance_path, 'servers.db')
            # Safety backup before overwrite
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            safety = os.path.join(BACKUP_DIR, f'pre_restore_{timestamp}.db')
            if os.path.exists(db_path):
                shutil.copy2(db_path, safety)
            shutil.copy2(backup_path, db_path)

        elif _is_postgres_db():
            if ext not in ('.dump', '.sql'):
                return jsonify({
                    'success': False,
                    'error': 'PostgreSQL restore requires a .dump or .sql backup file'
                }), 400
            # Safety backup of current DB before restore
            try:
                _create_database_backup_file('pre_restore')
            except Exception as be:
                app.logger.warning(f"Could not create pre-restore safety backup: {be}")
            _pg_restore_backup(backup_path)

        else:
            return jsonify({'success': False, 'error': 'Unsupported database backend'}), 400

        session.clear()
        return jsonify({
            'success': True,
            'message': 'Database restored successfully. Please log in again.',
            'redirect': url_for('login')
        })

    except Exception as e:
        app.logger.error(f"Restore failed for {filename}: {e}")
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/backups/<filename>/restore/stream')
@login_required
def restore_backup_stream(filename):
    """SSE endpoint — streams live restore progress to the browser."""
    import threading
    filename = secure_filename(filename)
    backup_path = os.path.join(BACKUP_DIR, filename)

    def _sse(type_, message, **extra):
        data = {'type': type_, 'message': message, **extra}
        return f"data: {json.dumps(data, ensure_ascii=False)}\n\n"

    def _heartbeat():
        # SSE comment — keeps the connection alive through nginx/proxies
        return ": heartbeat\n\n"

    def generate():
        # ── Pre-flight checks ──────────────────────────────────────────
        yield _sse('log', '🔍 Checking backup file…')

        if not os.path.exists(backup_path):
            yield _sse('error', f'Backup not found: {filename}')
            return

        ext = os.path.splitext(filename)[1].lower()
        size_mb = round(os.path.getsize(backup_path) / 1024 / 1024, 2)
        yield _sse('log', f'File: {filename}  ({size_mb} MB)')

        db_type = 'PostgreSQL' if _is_postgres_db() else ('SQLite' if _is_sqlite_db() else 'Unknown')
        yield _sse('log', f'Database: {db_type}')

        # ── Full migration bundle (.zip): DB + uploaded files ─────────────
        if ext == '.zip':
            try:
                yield _sse('log', '📦 Full migration bundle detected — restoring database AND uploaded files…')
                _msgs = []
                _restore_full_migration_zip(backup_path, log=lambda m: _msgs.append(m))
                for _m in _msgs:
                    yield _sse('log', _m)
                yield _sse('done', '✓ Migration restore complete (DB + files) — logging you out.',
                           redirect=url_for('logout'))
            except Exception as exc:
                app.logger.error(f"migration restore error: {exc}", exc_info=True)
                yield _sse('error', f'Migration restore failed: {exc}')
            return

        try:
            # ── SQLite ────────────────────────────────────────────────────
            if _is_sqlite_db():
                if ext != '.db':
                    yield _sse('error', f'SQLite requires a .db backup; got {ext!r}')
                    return
                db_path = os.path.join(app.instance_path, 'servers.db')
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                safety = os.path.join(BACKUP_DIR, f'pre_restore_{timestamp}.db')
                if os.path.exists(db_path):
                    shutil.copy2(db_path, safety)
                    yield _sse('log', f'✓ Safety backup: {os.path.basename(safety)}')
                yield _sse('log', 'Replacing database file…')
                shutil.copy2(backup_path, db_path)
                yield _sse('done', '✓ Restore complete — logging you out.', redirect=url_for('logout'))

            # ── PostgreSQL ────────────────────────────────────────────────
            elif _is_postgres_db():
                if ext not in ('.dump', '.sql'):
                    yield _sse('error', f'PostgreSQL requires .dump or .sql; got {ext!r}')
                    return

                # Check tools first
                if ext == '.dump':
                    tool_bin = shutil.which('pg_restore')
                    if not tool_bin:
                        yield _sse('error', 'pg_restore not found.\n  Fix: sudo apt install postgresql-client')
                        return
                    if not shutil.which('psql'):
                        yield _sse('error', 'psql not found.\n  Fix: sudo apt install postgresql-client')
                        return
                    jobs = _pg_restore_jobs()
                    tool = 'pg_restore'
                    cmd = [tool_bin, '--no-owner', '--no-acl',
                           f'--jobs={jobs}', '--dbname', _db_uri(), backup_path]
                else:
                    tool_bin = shutil.which('psql')
                    if not tool_bin:
                        yield _sse('error', 'psql not found.\n  Fix: sudo apt install postgresql-client')
                        return
                    tool = 'psql'
                    cmd = [tool_bin, '--dbname', _db_uri(), '--file', backup_path, '--echo-errors']

                yield _sse('log', f'✓ {tool} found at: {tool_bin}')

                # Safety backup
                try:
                    yield _sse('log', 'Creating safety backup before overwriting…')
                    yield _heartbeat()
                    safety_name = _create_database_backup_file('pre_restore')
                    yield _sse('log', f'✓ Safety backup: {os.path.basename(safety_name)}')
                except Exception as be:
                    yield _sse('log', f'⚠ Safety backup failed (continuing): {be}')

                yield _sse('log', f'Running {tool}…')
                yield _heartbeat()

                uri = _db_uri()
                env = _pg_env_from_uri(uri)

                yield _sse('log', 'Resetting PostgreSQL public schema with CASCADEâ€¦')
                yield _heartbeat()
                _pg_reset_public_schema(uri, env)
                yield _sse('log', 'âœ“ PostgreSQL schema reset complete')

                # --jobs=N means pg_restore spawns parallel workers — no stdout
                # lines will flow during restore. We run it in the background and
                # send heartbeats every 2 s so the SSE connection stays alive.
                import threading as _threading
                import time as _time

                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=env,
                )

                # Collect stderr in a background thread so we can show errors
                stderr_lines = []
                def _read_stderr():
                    for _l in proc.stderr:
                        stderr_lines.append(_l.rstrip())
                _t = _threading.Thread(target=_read_stderr, daemon=True)
                _t.start()

                # Stream heartbeats + elapsed time while waiting
                start = _time.monotonic()
                if ext == '.dump':
                    yield _sse('log', f'Running {tool} with --jobs={jobs} (parallel)…')
                else:
                    yield _sse('log', f'Running {tool}…')
                while proc.poll() is None:
                    _time.sleep(2)
                    elapsed = int(_time.monotonic() - start)
                    yield _sse('progress', f'Restoring… {elapsed}s elapsed')
                    yield _heartbeat()

                _t.join(timeout=5)
                proc.wait(timeout=10)

                elapsed = int(_time.monotonic() - start)
                # Show last few stderr lines (errors / warnings)
                visible = [l for l in stderr_lines if l and not l.startswith('pg_restore:')]
                errors  = [l for l in stderr_lines if 'error' in l.lower()]
                for line in (errors or visible)[-10:]:
                    yield _sse('log', line)

                if proc.returncode != 0:
                    yield _sse('error', f'{tool} exited with code {proc.returncode} after {elapsed}s')
                else:
                    suffix = f' (--jobs={jobs})' if ext == '.dump' else ''
                    yield _sse('log', f'✓ {tool} finished in {elapsed}s{suffix}')
                    yield _sse('done', '✓ Restore complete — logging you out.',
                               redirect=url_for('logout'))
            else:
                uri = _db_uri()
                yield _sse('error', f'Unsupported database type (URI: {uri[:30]}…)')

        except Exception as exc:
            app.logger.error(f"restore_backup_stream error: {exc}", exc_info=True)
            yield _sse('error', f'Unexpected error: {exc}')

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'X-Content-Type-Options': 'nosniff',
        },
    )


@app.route('/api/backups/<filename>', methods=['DELETE'])
@login_required
def delete_backup(filename):
    filename = secure_filename(filename)
    path = os.path.join(BACKUP_DIR, filename)
    if not os.path.exists(path):
        return jsonify({'success': False, 'error': 'File not found'}), 404
    try:
        os.remove(path)
        return jsonify({'success': True, 'message': 'Backup deleted'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/me', methods=['GET'])
@login_required
def get_current_user_info():
    user = db.session.get(Admin, session['admin_id'])
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 401
    return jsonify({
        'success': True,
        'user': user.to_dict()
    })

@app.context_processor
def inject_version():
    return dict(app_version=APP_VERSION)

@app.route('/api/check-update', methods=['GET'])
@login_required
def check_update():
    def _normalize_version_str(v: str) -> str:
        if not v:
            return ''
        v = str(v).strip()
        # GitHub tags are often like "v1.7.0"
        if v[:1] in ('v', 'V'):
            v = v[1:]
        return v.strip()

    def _parse_semver(v: str):
        """Best-effort semver parsing.

        Returns (major, minor, patch, is_prerelease) or None.
        Accepts: 1, 1.7, 1.7.0, 1.7.0-rc1, 1.7.0+meta
        """
        v = _normalize_version_str(v)
        if not v:
            return None
        # Split build metadata
        core = v.split('+', 1)[0]
        # Split prerelease
        core_part, prerelease_part = (core.split('-', 1) + [''])[:2]
        is_prerelease = bool(prerelease_part)
        parts = core_part.split('.')
        try:
            major = int(parts[0]) if len(parts) >= 1 and parts[0] != '' else 0
            minor = int(parts[1]) if len(parts) >= 2 and parts[1] != '' else 0
            patch = int(parts[2]) if len(parts) >= 3 and parts[2] != '' else 0
        except Exception:
            return None
        return (major, minor, patch, is_prerelease)

    def _is_update_available(current: str, latest: str) -> bool:
        cur_norm = _normalize_version_str(current)
        lat_norm = _normalize_version_str(latest)
        if not cur_norm or not lat_norm:
            return False
        cur = _parse_semver(cur_norm)
        lat = _parse_semver(lat_norm)
        if cur and lat:
            cur_key = (cur[0], cur[1], cur[2])
            lat_key = (lat[0], lat[1], lat[2])
            if lat_key != cur_key:
                return lat_key > cur_key
            # Same base version: stable beats prerelease.
            # (So 1.7.0 should NOT report update vs 1.7.0-rc1)
            return (cur[3] is True) and (lat[3] is False)
        # Fallback: normalized string compare
        return lat_norm != cur_norm

    # Check cache first (but don't reuse cache across app version changes)
    current_time = time.time()
    if UPDATE_CACHE['data'] and (current_time - UPDATE_CACHE['last_check'] < UPDATE_CACHE['ttl']):
        try:
            if str(UPDATE_CACHE['data'].get('current_version')) == str(APP_VERSION):
                return jsonify(UPDATE_CACHE['data'])
        except Exception:
            pass

    try:
        resp = requests.get(f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest", timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            latest_version_raw = data.get('tag_name', '')
            latest_version = _normalize_version_str(latest_version_raw)
            
            result = {
                'success': True,
                'current_version': APP_VERSION,
                'latest_version': latest_version,
                'update_available': _is_update_available(APP_VERSION, latest_version),
                'release_url': data.get('html_url', '')
            }
            
            # Update cache
            UPDATE_CACHE['last_check'] = current_time
            UPDATE_CACHE['data'] = result
            
            return jsonify(result)
        return jsonify({'success': False, 'error': 'GitHub API error'})
    except Exception as e:
        # If request fails (timeout/network), return cached data if available (even if expired) to avoid error
        if UPDATE_CACHE['data']:
            return jsonify(UPDATE_CACHE['data'])
        return jsonify({'success': False, 'error': str(e)})

def background_data_fetcher():
    """
    این تابع در پس‌زمینه اجرا می‌شود و هر ۳۰ ثانیه اطلاعات را در RAM بروز می‌کند.
    Fetches from panels, processes, and (if Redis is on) publishes the snapshot.
    """
    ensure_background_threads_started()
    while True:
        with app.app_context():
            # Avoid overlapping with a manual refresh job.
            if GLOBAL_REFRESH_LOCK.acquire(blocking=False):
                try:
                    fetch_and_update_global_data(force=False)
                finally:
                    try:
                        GLOBAL_REFRESH_LOCK.release()
                    except Exception:
                        pass
        time.sleep(30)


def snapshot_reader_worker():
    """Runs in workers that DON'T fetch (Redis mode). Pulls the shared snapshot
    from Redis into local memory so requests are served fast & in-process.
    Only decompresses when the snapshot version actually changed."""
    # Prime immediately so the worker has data without waiting a full interval.
    try:
        load_snapshot_from_redis(force=True)
    except Exception:
        pass
    while True:
        try:
            load_snapshot_from_redis()
        except Exception:
            pass
        time.sleep(10)


def fetch_and_update_global_data(force: bool = False, server_ids=None):
    """یک بار داده‌ها را از سرورها واکشی و در RAM به‌روزرسانی می‌کند."""
    try:
        GLOBAL_SERVER_DATA['is_updating'] = True

        servers_q = Server.query.filter_by(enabled=True).filter(
            (Server.hidden == False) | (Server.hidden == None))
        if server_ids:
            try:
                ids = [int(x) for x in (server_ids or [])]
                servers_q = servers_q.filter(Server.id.in_(ids))
            except Exception:
                pass

        servers = servers_q.all()

        now_ts = time.time()
        skipped_ids = set()
        if not force:
            for s in servers:
                try:
                    if _backoff_should_skip(int(s.id), now_ts):
                        skipped_ids.add(int(s.id))
                except Exception:
                    continue

        server_dicts = [{
            'id': s.id, 'name': s.name, 'host': s.host,
            'username': s.username, 'password': get_server_password(s),
            # Pass the (encrypted) v3 API token through so the concurrent
            # fetch_worker authenticates v3 panels with the Bearer token.
            # Without it server_is_v3() is False → cookie login → 403 on v3.
            'api_token': s.api_token,
            'panel_type': s.panel_type, 'sub_port': s.sub_port,
            'sub_path': s.sub_path, 'json_path': s.json_path
        } for s in servers if int(s.id) not in skipped_ids]

        # Release the database read lock before starting long-running network I/O
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()

        results = []
        if server_dicts:
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                future_to_id = {executor.submit(fetch_worker, s): s['id'] for s in server_dicts}
                for future in concurrent.futures.as_completed(future_to_id):
                    results.append(future.result())

        results_by_id = {r[0]: r for r in results if isinstance(r, tuple) and len(r) >= 7}

        existing_inbounds = GLOBAL_SERVER_DATA.get('inbounds') or []
        existing_by_server = defaultdict(list)
        for inbound in existing_inbounds:
            try:
                sid = int(inbound.get('server_id', -1))
                if sid > 0:
                    existing_by_server[sid].append(inbound)
            except Exception:
                continue

        existing_statuses = GLOBAL_SERVER_DATA.get('servers_status') or []
        status_map = {}
        for st in existing_statuses:
            try:
                if isinstance(st, dict) and 'server_id' in st:
                    status_map[int(st.get('server_id'))] = st
            except Exception:
                continue

        admin_user = Admin.query.filter(or_(Admin.is_superadmin == True, Admin.role == 'superadmin')).first()
        if not admin_user:
            admin_user = SimpleNamespace(role='superadmin', id=0, is_superadmin=True)

        now_iso = _utc_iso_now()
        new_by_server = dict(existing_by_server)

        for srv in servers:
            sid = int(srv.id)

            if sid in skipped_ids:
                info = _backoff_get(sid)
                st = status_map.get(sid) or {"server_id": sid}
                st['reachable'] = False
                st['reachable_error'] = (info.get('last_error') or 'Backoff')
                st['reachable_checked_at'] = now_iso
                st['backoff_until'] = int(info.get('next_allowed_at', 0) or 0)
                status_map[sid] = st
                continue

            res = results_by_id.get(sid) or (sid, None, None, None, None, "Timeout", 'auto')
            _, inbounds, online_index, status_payload, status_error, error, detected_type = res

            if error:
                _backoff_record_failure(sid, error)
                st = status_map.get(sid) or {"server_id": sid}
                # Keep cached stats if present to avoid UI dropping counts.
                if isinstance(st.get('stats'), dict) and st.get('stats'):
                    st['success'] = True
                else:
                    st['success'] = False
                st['error'] = error
                st['reachable'] = False
                st['reachable_error'] = error
                st['reachable_checked_at'] = now_iso
                # Always expose the error in panel_status_error so the UI badge shows it.
                st['panel_status_error'] = (status_error or error)
                st['panel_status_checked_at'] = now_iso
                if status_payload:
                    st['xui_version'] = status_payload.get('xui_version')
                    st['xray_version'] = status_payload.get('xray_version')
                    st['xray_state'] = status_payload.get('xray_state')
                    st['xray_core'] = status_payload.get('xray_core')
                    st['online_count'] = status_payload.get('online_count')
                status_map[sid] = st
                # keep existing inbounds block (if any)
                continue

            _backoff_record_success(sid)

            if persist_detected_panel_type(srv, detected_type):
                app.logger.info(f"Detected panel type for server {srv.id} as {detected_type}")

            if not isinstance(inbounds, list):
                inbounds = []
            processed, stats = process_inbounds(inbounds, srv, admin_user, '*', {}, online_index=online_index)
            new_by_server[sid] = list(processed or [])

            st = status_map.get(sid) or {"server_id": sid}
            status_payload = status_payload or {}
            st.update({
                "server_id": sid,
                "success": True,
                "stats": stats,
                "panel_type": srv.panel_type,
                "reachable": True,
                "reachable_error": None,
                "reachable_checked_at": now_iso,
                "error": None,
                "xui_version": status_payload.get('xui_version'),
                "xray_version": status_payload.get('xray_version'),
                "xray_state": status_payload.get('xray_state'),
                "xray_core": status_payload.get('xray_core'),
                "online_count": status_payload.get('online_count'),
                "panel_status_error": status_error if status_error else None,
                "panel_status_checked_at": now_iso
            })
            status_map[sid] = st

        # Flatten inbounds in stable order (server order)
        all_inbounds = []
        for srv in servers:
            all_inbounds.extend(new_by_server.get(int(srv.id), []))

        server_statuses = []
        for srv in servers:
            sid = int(srv.id)
            server_statuses.append(status_map.get(sid) or {"server_id": sid, "success": False, "error": "No data"})

        total_stats = _recompute_global_stats_from_server_statuses(server_statuses)

        GLOBAL_SERVER_DATA['inbounds'] = all_inbounds
        GLOBAL_SERVER_DATA['stats'] = total_stats
        GLOBAL_SERVER_DATA['servers_status'] = server_statuses
        GLOBAL_SERVER_DATA['last_update'] = now_iso

        # Share the freshly-computed snapshot with the other workers via Redis
        # (no-op when Redis is not configured/available).
        publish_snapshot_to_redis()

    except Exception as e:
        print(f"Background fetch error: {e}")
    finally:
        GLOBAL_SERVER_DATA['is_updating'] = False

def run_scheduler():
    while True:
        with app.app_context():
            try:
                freq_setting = db.session.get(SystemSetting, 'backup_frequency')
                if freq_setting and freq_setting.value != 'disabled':
                    last_backup = db.session.get(SystemSetting, 'last_auto_backup')
                    
                    should_backup = False
                    now = datetime.now()
                    
                    if not last_backup:
                        should_backup = True
                    else:
                        last_time = datetime.fromisoformat(last_backup.value)
                        if freq_setting.value == 'daily' and (now - last_time) > timedelta(days=1):
                            should_backup = True
                        elif freq_setting.value == 'weekly' and (now - last_time) > timedelta(weeks=1):
                            should_backup = True
                        elif freq_setting.value == 'monthly' and (now - last_time) > timedelta(days=30):
                            should_backup = True
                            
                    if should_backup:
                        try:
                            filename = _create_database_backup_file('auto')
                        except Exception as e:
                            print(f"Auto backup failed: {e}")
                            filename = None

                        if filename:
                            # Update last backup time
                            if not last_backup:
                                last_backup = SystemSetting(key='last_auto_backup', value=now.isoformat())
                                db.session.add(last_backup)
                            else:
                                last_backup.value = now.isoformat()
                            db.session.commit()
                            print(f"Auto backup created: {filename}")

                # Backup retention cleanup (delete files older than N days)
                try:
                    if _parse_bool(_get_system_setting_value('backup_retention_enabled', 'false')):
                        rdays = _parse_int(_get_system_setting_value('backup_retention_days', '14'), 14, min_value=1, max_value=3650)
                        last_clean = _parse_iso_datetime(_get_system_setting_value('backup_last_cleanup', ''))
                        # run at most once every 6 hours
                        if (not last_clean) or (datetime.utcnow() - last_clean) >= timedelta(hours=6):
                            res = _cleanup_old_backups(rdays)
                            _set_system_setting_value('backup_last_cleanup', datetime.utcnow().isoformat())
                            db.session.commit()
                            if res.get('deleted'):
                                print(f"[Backup retention] Deleted {res['deleted']} old backup(s), freed {res['freed_bytes']} bytes")
                except Exception as _ce:
                    print(f"Backup retention error: {_ce}")

                # Telegram backups
                tg_enabled = _parse_bool(_get_system_setting_value('telegram_backup_enabled', 'false'))
                if tg_enabled:
                    # Normalize any parsed datetime to naive-UTC for safe arithmetic
                    def _naive_utc(dt):
                        if not dt:
                            return None
                        return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt

                    schedule_mode = (_get_system_setting_value('telegram_backup_schedule_mode', 'interval') or 'interval').strip().lower()
                    now_utc = datetime.utcnow()
                    last_run_dt = _naive_utc(_parse_iso_datetime(_get_system_setting_value('telegram_backup_last_run', '')))
                    last_attempt_dt = _naive_utc(_parse_iso_datetime(_get_system_setting_value('telegram_backup_last_attempt', '')))
                    # Retry throttle: never re-attempt more than once per 15 min on failure
                    attempt_ok = (not last_attempt_dt) or ((now_utc - last_attempt_dt) >= timedelta(minutes=15))
                    should_run = False

                    if schedule_mode == 'daily':
                        # Fire once per day at a fixed local time (server timezone).
                        daily_time = (_get_system_setting_value('telegram_backup_daily_time', '00:00') or '00:00').strip()
                        try:
                            th, tm = (int(x) for x in daily_time.split(':'))
                        except Exception:
                            th, tm = 0, 0
                        try:
                            tz_local = _get_app_tzinfo()
                        except Exception:
                            tz_local = timezone(timedelta(hours=3, minutes=30))
                        now_local = datetime.now(tz_local)
                        target_today = now_local.replace(hour=th, minute=tm, second=0, microsecond=0)
                        last_local = None
                        if last_run_dt:
                            last_local = last_run_dt.replace(tzinfo=timezone.utc).astimezone(tz_local)
                        already_done_today = bool(last_local and last_local.date() == now_local.date()
                                                  and last_local >= target_today)
                        if now_local >= target_today and not already_done_today and attempt_ok:
                            should_run = True
                    else:
                        tg_interval = _parse_int(
                            _get_system_setting_value('telegram_backup_interval_minutes', str(TELEGRAM_BACKUP_DEFAULT_INTERVAL_MINUTES)),
                            TELEGRAM_BACKUP_DEFAULT_INTERVAL_MINUTES,
                            min_value=1,
                            max_value=TELEGRAM_BACKUP_MAX_INTERVAL_MINUTES
                        )
                        if not last_run_dt:
                            should_run = attempt_ok
                        elif (now_utc - last_run_dt) >= timedelta(minutes=tg_interval) and attempt_ok:
                            should_run = True

                    if should_run:
                        # Record attempt time first so a failure doesn't trigger a
                        # per-minute retry storm (next try is throttled to +15 min).
                        try:
                            _set_system_setting_value('telegram_backup_last_attempt', datetime.utcnow().isoformat())
                            db.session.commit()
                        except Exception:
                            pass
                        result = _run_telegram_backup(trigger='scheduled')
                        if not result.get('success'):
                            app.logger.warning(f"Telegram backup failed: {result.get('error')}")
                            
            except Exception as e:
                print(f"Scheduler error: {e}")
            
        time.sleep(60) # Check every minute

def update_session_lifetime():
    with app.app_context():
        try:
            # Check if table exists first to avoid error on fresh install
            inspector = inspect(db.engine)
            if 'system_settings' in inspector.get_table_names():
                setting = db.session.get(SystemSetting, 'session_timeout_hours')
                if setting:
                    hours = int(setting.value)
                    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=hours)
                    print(f"Session lifetime updated to {hours} hours")
        except Exception as e:
            print(f"Error updating session lifetime: {e}")


# ---------------------------------------------------------------------------
# Health Watchdog – background self-healing loop
# ---------------------------------------------------------------------------
HEALTH_CHECK_INTERVAL = 60  # seconds between checks

# Critical static files that must exist
_CRITICAL_STATIC_FILES = [
    'style.css',
    'tailwind.generated.css',
    'jquery-3.6.0.min.js',
    'jalalidatepicker.min.css',
    'jalalidatepicker.min.js',
]

def _health_check_db():
    """Verify DB connectivity. Auto-heal by recycling the connection pool."""
    try:
        db.session.execute(text('SELECT 1'))
        db.session.rollback()
        return True, None
    except Exception as exc:
        error_msg = str(exc)
        # Auto-heal: dispose the pool so new connections are created
        try:
            db.session.rollback()
            db.engine.dispose()
            _add_health_log('warning', 'db', 'Database connection lost – pool recycled',
                            action_taken='Disposed connection pool and recycled',
                            details={'error': error_msg}, resolved=True)
            return False, error_msg
        except Exception as heal_exc:
            _add_health_log('critical', 'db', f'Database unreachable and auto-heal failed: {error_msg}',
                            action_taken=f'Heal attempt failed: {heal_exc}',
                            details={'error': error_msg, 'heal_error': str(heal_exc)})
            return False, error_msg


def _health_check_static_files():
    """Ensure critical static files exist on disk."""
    static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
    missing = []
    for fname in _CRITICAL_STATIC_FILES:
        fpath = os.path.join(static_dir, fname)
        if not os.path.isfile(fpath):
            missing.append(fname)
    if missing:
        _add_health_log('error', 'static',
                        f'Missing critical static files: {", ".join(missing)}',
                        details={'missing': missing})
        return False, missing
    return True, None


def _health_check_disk():
    """Warn if disk usage is above 90%."""
    try:
        usage = shutil.disk_usage(os.path.dirname(os.path.abspath(__file__)))
        pct = (usage.used / usage.total) * 100
        if pct > 95:
            _add_health_log('critical', 'disk',
                            f'Disk nearly full: {pct:.1f}% used',
                            details={'used_pct': round(pct, 1),
                                     'free_gb': round(usage.free / (1024**3), 2)})
            return False, pct
        elif pct > 90:
            _add_health_log('warning', 'disk',
                            f'Disk usage high: {pct:.1f}% used',
                            details={'used_pct': round(pct, 1),
                                     'free_gb': round(usage.free / (1024**3), 2)})
            return False, pct
        return True, round(pct, 1)
    except Exception as exc:
        return True, str(exc)  # non-fatal


def _health_check_servers():
    """Check reachability of enabled servers, log any that are down."""
    try:
        servers = Server.query.filter_by(enabled=True).all()
    except Exception:
        return True, None  # if we can't query, the DB check will catch it
    down_servers = []
    for srv in servers:
        ok, err = _check_server_reachable(srv, timeout_sec=3.0)
        if not ok:
            down_servers.append({'id': srv.id, 'name': srv.name or srv.host, 'error': err})
    if down_servers:
        names = ', '.join(s['name'] for s in down_servers)
        _add_health_log('warning', 'server',
                        f'{len(down_servers)} server(s) unreachable: {names}',
                        details={'servers': down_servers})
        return False, down_servers
    return True, None


def _run_single_health_cycle():
    """Execute one full health-check cycle. Returns summary dict."""
    results = {}
    results['db'] = _health_check_db()
    results['static'] = _health_check_static_files()
    results['disk'] = _health_check_disk()
    results['servers'] = _health_check_servers()
    return results


def health_watchdog():
    """Long-running watchdog daemon – runs health checks every HEALTH_CHECK_INTERVAL seconds."""
    with app.app_context():
        _add_health_log('info', 'general', 'Health watchdog started',
                        details={'interval_seconds': HEALTH_CHECK_INTERVAL})
        while True:
            try:
                time.sleep(HEALTH_CHECK_INTERVAL)
                _run_single_health_cycle()
                # Prune old logs – keep last 500
                try:
                    count = HealthLog.query.count()
                    if count > 500:
                        cutoff = (HealthLog.query
                                  .order_by(HealthLog.id.desc())
                                  .offset(500)
                                  .first())
                        if cutoff:
                            HealthLog.query.filter(HealthLog.id <= cutoff.id).delete()
                            db.session.commit()
                except Exception:
                    db.session.rollback()
            except Exception as exc:
                print(f"[HealthWatchdog] Error in cycle: {exc}")
                try:
                    time.sleep(30)
                except Exception:
                    pass


_USAGE_SNAPSHOT_INTERVAL_DEFAULT_MIN = 30  # default: 30 minutes
_USAGE_SNAPSHOT_RETENTION_DAYS = 90  # keep 90 days of history
USAGE_SNAPSHOT_INTERVAL_KEY = 'usage_snapshot_interval_minutes'


def _take_usage_snapshots():
    """Read GLOBAL_SERVER_DATA and save one UsageSnapshot per active client per server."""
    try:
        inbounds = GLOBAL_SERVER_DATA.get('inbounds') or []
        if not inbounds:
            print("[UsageSnapshot] _take_usage_snapshots: no inbounds in cache, skipping.")
            return
        now = datetime.utcnow()
        new_snapshots = []
        renewals = []
        for inbound in inbounds:
            server_id = inbound.get('server_id')
            if not server_id:
                continue
            inbound_tag = (inbound.get('remark') or inbound.get('tag') or '').strip() or f"inbound-{inbound.get('id', '')}"
            for client in inbound.get('clients', []):
                sub_id = str(client.get('subId') or '').strip()
                if not sub_id:
                    sub_id = str(client.get('id') or '').strip()
                if not sub_id:
                    continue

                up = int(client.get('up') or 0)
                down = int(client.get('down') or 0)
                total_used = up + down
                # totalGB in 3x-ui API is stored in BYTES (the field name is a historical misnomer).
                # All other code in this project (process_inbounds, renewal, etc.) treats it as bytes.
                # DO NOT multiply by 1024^3 — that causes bigint overflow in PostgreSQL.
                try:
                    volume_limit_bytes = int(client.get('totalGB') or 0) or None
                except Exception:
                    volume_limit_bytes = None
                # Cap at PostgreSQL bigint max to guard against any corrupt panel values
                _PG_BIGINT_MAX = 9_223_372_036_854_775_807
                if volume_limit_bytes and volume_limit_bytes > _PG_BIGINT_MAX:
                    volume_limit_bytes = None
                remaining_bytes = max(volume_limit_bytes - total_used, 0) if volume_limit_bytes else None

                # Renewal detection: compare with the most recent snapshot
                prev = (UsageSnapshot.query
                        .filter_by(server_id=server_id, sub_id=sub_id)
                        .order_by(UsageSnapshot.recorded_at.desc())
                        .first())

                if prev:
                    prev_total = prev.total_bytes
                    prev_limit = prev.volume_limit_bytes or 0
                    # Traffic reset (current total_used < previous) = quota refill / renewal
                    if total_used < prev_total and prev_total > 0:
                        try:
                            expiry_ts = int(client.get('expiryTimestamp') or client.get('expiryTime') or 0)
                            days = None
                            is_unlimited_time = False
                            if expiry_ts and expiry_ts > 0:
                                expiry_dt = datetime.utcfromtimestamp(expiry_ts / 1000)
                                delta_days = (expiry_dt - now).days
                                days = max(delta_days, 0)
                            else:
                                is_unlimited_time = True
                            renewals.append(RenewalEvent(
                                server_id=server_id,
                                sub_id=sub_id,
                                renewed_at=now,
                                volume_bytes=volume_limit_bytes,
                                days=days,
                                is_unlimited_volume=(volume_limit_bytes is None),
                                is_unlimited_time=is_unlimited_time,
                            ))
                        except Exception:
                            pass

                new_snapshots.append(UsageSnapshot(
                    server_id=server_id,
                    sub_id=sub_id,
                    inbound_tag=inbound_tag,
                    recorded_at=now,
                    upload_bytes=up,
                    download_bytes=down,
                    total_bytes=total_used,
                    remaining_bytes=remaining_bytes,
                    volume_limit_bytes=volume_limit_bytes,
                ))

        if new_snapshots:
            db.session.bulk_save_objects(new_snapshots)
        if renewals:
            db.session.bulk_save_objects(renewals)
        if new_snapshots or renewals:
            db.session.commit()
            print(f"[UsageSnapshot] Saved {len(new_snapshots)} snapshots, {len(renewals)} renewals.")
        else:
            print("[UsageSnapshot] No snapshots to save (all clients may lack sub_id).")

        # Prune old snapshots
        cutoff = now - timedelta(days=_USAGE_SNAPSHOT_RETENTION_DAYS)
        deleted = UsageSnapshot.query.filter(UsageSnapshot.recorded_at < cutoff).delete()
        if deleted:
            db.session.commit()
            print(f"[UsageSnapshot] Pruned {deleted} old snapshots.")
        return True
    except Exception as exc:
        try:
            db.session.rollback()
        except Exception:
            pass
        print(f"[UsageSnapshot] Error in _take_usage_snapshots: {exc}")
        raise  # re-raise so the caller (worker) knows this cycle failed


def usage_snapshot_worker():
    """Singleton background daemon: takes periodic usage snapshots.

    Runs in exactly ONE gunicorn worker (whichever wins _claim_singleton).
    No dedup guard needed — only one writer exists.
    Errors are written to the health log so admins can see them.
    """
    print(f"[UsageSnapshot] Singleton worker started (PID={os.getpid()}), waiting for server data...")

    # Wait up to 10 minutes for background_data_fetcher to populate cache
    _waited = 0
    while _waited < 600:
        if GLOBAL_SERVER_DATA.get('inbounds'):
            break
        time.sleep(30)
        _waited += 30

    if not GLOBAL_SERVER_DATA.get('inbounds'):
        # Cache still empty — fetch once before starting cycles
        print("[UsageSnapshot] Cache empty after 10 min, fetching now...")
        try:
            with app.app_context():
                fetch_and_update_global_data(force=True)
        except Exception as exc:
            print(f"[UsageSnapshot] Initial fetch error: {exc}")

    # Take initial snapshot immediately on startup
    try:
        with app.app_context():
            print("[UsageSnapshot] Taking initial snapshot...")
            _take_usage_snapshots()
            print("[UsageSnapshot] Initial snapshot done.")
    except Exception as exc:
        print(f"[UsageSnapshot] Initial snapshot error: {exc}")
        try:
            with app.app_context():
                _add_health_log('warning', 'snapshot',
                                'Initial usage snapshot failed',
                                details={'error': str(exc)})
        except Exception:
            pass

    while True:
        try:
            # Read interval from DB in a fresh context
            interval_min = _USAGE_SNAPSHOT_INTERVAL_DEFAULT_MIN
            try:
                with app.app_context():
                    _raw = _get_or_create_system_setting(
                        USAGE_SNAPSHOT_INTERVAL_KEY,
                        str(_USAGE_SNAPSHOT_INTERVAL_DEFAULT_MIN)
                    )
                    interval_min = max(5, min(120, int(_raw or _USAGE_SNAPSHOT_INTERVAL_DEFAULT_MIN)))
            except Exception:
                pass

            print(f"[UsageSnapshot] Next snapshot in {interval_min} min...")
            time.sleep(interval_min * 60)

            # Refresh cache if empty (singleton worker may not serve HTTP requests)
            if not GLOBAL_SERVER_DATA.get('inbounds'):
                print("[UsageSnapshot] Cache empty, fetching fresh server data...")
                try:
                    with app.app_context():
                        fetch_and_update_global_data(force=True)
                except Exception as exc:
                    print(f"[UsageSnapshot] Fetch error: {exc}")

            # Take snapshot
            try:
                with app.app_context():
                    _take_usage_snapshots()
                print(f"[UsageSnapshot] Cycle complete (interval={interval_min}m).")
                # Log success to system logs every cycle
                try:
                    with app.app_context():
                        n_clients = len([
                            c for ib in (GLOBAL_SERVER_DATA.get('inbounds') or [])
                            for c in ib.get('clients', [])
                            if str(c.get('subId') or c.get('id') or '').strip()
                        ])
                        _add_health_log('info', 'snapshot',
                                        f'Usage snapshot saved ({n_clients} clients)',
                                        details={'interval_min': interval_min})
                except Exception:
                    pass
            except Exception as exc:
                print(f"[UsageSnapshot] Snapshot error: {exc}")
                try:
                    with app.app_context():
                        _add_health_log('warning', 'snapshot',
                                        'Usage snapshot failed',
                                        details={'error': str(exc), 'interval_min': interval_min})
                except Exception:
                    pass

        except Exception as exc:
            print(f"[UsageSnapshot] Worker loop error: {exc}")
            try:
                time.sleep(60)
            except Exception:
                pass


# File handles kept open so fcntl locks are held for the process lifetime.
_SINGLETON_LOCK_FDS = {}

def _claim_singleton(name):
    """Try to claim exclusive ownership of a singleton background thread.
    Uses a non-blocking fcntl exclusive lock on a /tmp file so:
    - Only one gunicorn worker wins (returns True).
    - If that worker dies, the OS releases the lock automatically.
    - Other workers return False and skip starting the thread.
    Gracefully falls back to True on non-Unix systems (Windows dev).
    """
    try:
        import fcntl as _fcntl
        lock_path = f'/tmp/eve_{name}.lock'
        fh = open(lock_path, 'w')
        _fcntl.flock(fh, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
        fh.write(str(os.getpid()))
        fh.flush()
        _SINGLETON_LOCK_FDS[name] = fh  # keep open — releasing closes the lock
        print(f"[Singleton] PID {os.getpid()} owns {name}")
        return True
    except (IOError, OSError):
        # Another worker already holds the lock
        return False
    except ImportError:
        # fcntl unavailable (Windows) — allow all threads (dev mode)
        return True


def ensure_background_threads_started():
    """Start background threads once per process.

    Singleton threads (scheduler, watchdog): only the gunicorn worker that
    wins the fcntl lock runs them — prevents duplicate health logs, double
    backups, and triple notifications.

    Per-worker threads (data fetcher, snapshot): run in every worker because
    they populate per-process memory caches; the snapshot worker has its own
    jitter + DB dedup to avoid duplicate writes.
    """
    global BACKGROUND_THREADS_STARTED
    if BACKGROUND_THREADS_STARTED:
        return
    BACKGROUND_THREADS_STARTED = True

    # Singleton: only one worker runs the scheduler (auto-backup, etc.)
    if _claim_singleton('scheduler'):
        try:
            threading.Thread(target=run_scheduler, daemon=True).start()
        except Exception as e:
            print(f"Failed to start scheduler thread: {e}")
    else:
        print("[Singleton] scheduler already owned by another worker, skipping.")

    # Data fetching:
    #  - Redis ON  : ONE worker (singleton) fetches+processes+publishes; the
    #                other workers only read the shared snapshot from Redis.
    #                → panels hit once, processing done once (not per-worker).
    #  - Redis OFF : fall back to every worker fetching into its own RAM cache.
    if redis_enabled():
        if _claim_singleton('data_fetcher'):
            try:
                threading.Thread(target=background_data_fetcher, daemon=True).start()
                print("[Redis] this worker is the data fetcher (singleton).")
            except Exception as e:
                print(f"Failed to start data fetcher thread: {e}")
        else:
            try:
                threading.Thread(target=snapshot_reader_worker, daemon=True).start()
                print("[Redis] this worker reads the shared snapshot.")
            except Exception as e:
                print(f"Failed to start snapshot reader thread: {e}")
    else:
        # Per-worker: every worker fetches server data into its own memory cache
        try:
            threading.Thread(target=background_data_fetcher, daemon=True).start()
        except Exception as e:
            print(f"Failed to start data fetcher thread: {e}")

    # Singleton: only one worker runs health watchdog (DB logs, notifications)
    if _claim_singleton('health_watchdog'):
        try:
            threading.Thread(target=health_watchdog, daemon=True).start()
        except Exception as e:
            print(f"Failed to start health watchdog thread: {e}")
    else:
        print("[Singleton] health_watchdog already owned by another worker, skipping.")

    # Singleton: only one worker runs usage snapshots — no race conditions, no dedup needed
    if _claim_singleton('snapshot_worker'):
        try:
            threading.Thread(target=usage_snapshot_worker, daemon=True).start()
        except Exception as e:
            print(f"Failed to start usage snapshot thread: {e}")
    else:
        print("[Singleton] snapshot_worker already owned by another worker, skipping.")

if not os.environ.get('DISABLE_BACKGROUND_THREADS'):
    # Start threads on module import (works under gunicorn as well)
    ensure_background_threads_started()


if __name__ == '__main__':
    # Create tables if not exist
    with app.app_context():
        db.create_all()
    
    update_session_lifetime()

    # Ensure background threads are running
    if not os.environ.get('DISABLE_BACKGROUND_THREADS'):
        ensure_background_threads_started()
    
    app.run(host='0.0.0.0', port=5000, debug=True)
