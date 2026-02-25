import os
from dotenv import load_dotenv
load_dotenv()  # Load environment variables from .env file

import io
import re
import json
import base64
import requests
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
from flask import Flask, render_template, jsonify, request, send_file, redirect, url_for, session, g
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from urllib.parse import urlparse, quote, urlencode, unquote
from jdatetime import datetime as jdatetime_class
from sqlalchemy import or_, func, text, inspect, case
from sqlalchemy.orm import joinedload

APP_VERSION = "1.8.2"
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

# Prevent overlapping forced refreshes (e.g. after rapid UI actions)
GLOBAL_REFRESH_LOCK = threading.Lock()

# Refresh job tracking (in-memory; per-process)
REFRESH_JOBS = {}  # job_id -> job dict
REFRESH_JOBS_LOCK = threading.Lock()
REFRESH_MAX_JOBS = 50

# Bulk job tracking (in-memory; per-process)
BULK_JOBS = {}  # job_id -> job dict
BULK_JOBS_LOCK = threading.Lock()
BULK_MAX_JOBS = 50

# Telegram backup job tracking (in-memory; per-process)
TELEGRAM_BACKUP_JOBS = {}  # job_id -> job dict
TELEGRAM_BACKUP_JOBS_LOCK = threading.Lock()
TELEGRAM_BACKUP_MAX_JOBS = 20

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

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
        'progress', 'error'
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


def _update_telegram_backup_job(job_id: str, **patch):
    with TELEGRAM_BACKUP_JOBS_LOCK:
        job = TELEGRAM_BACKUP_JOBS.get(job_id)
        if not job:
            return
        for k, v in patch.items():
            job[k] = v
        TELEGRAM_BACKUP_JOBS[job_id] = job


def _run_telegram_backup_job(job_id: str):
    with TELEGRAM_BACKUP_JOBS_LOCK:
        job = TELEGRAM_BACKUP_JOBS.get(job_id)
        if not job:
            return
        job['state'] = 'running'
        job['started_at'] = _utc_iso_now()
        job['stage'] = 'starting'
        TELEGRAM_BACKUP_JOBS[job_id] = job

    def progress_cb(update: dict):
        if not isinstance(update, dict):
            return
        stage = update.get('stage')
        progress = update.get('progress')
        patch = {}
        if stage is not None:
            patch['stage'] = stage
        if progress is not None:
            patch['progress'] = progress
        if patch:
            _update_telegram_backup_job(job_id, **patch)

    try:
        with app.app_context():
            result = _run_telegram_backup(trigger=str((TELEGRAM_BACKUP_JOBS.get(job_id) or {}).get('trigger') or 'manual'), progress_cb=progress_cb)
    except Exception as exc:
        _update_telegram_backup_job(job_id, state='error', finished_at=_utc_iso_now(), error=str(exc), stage='error')
        return

    if result.get('success'):
        _update_telegram_backup_job(
            job_id,
            state='done',
            finished_at=_utc_iso_now(),
            stage='done',
            success_count=int(result.get('success_count') or 0),
            total=int(result.get('total') or 0),
            results=result.get('results') or [],
            error=None,
        )
    else:
        _update_telegram_backup_job(
            job_id,
            state='error',
            finished_at=_utc_iso_now(),
            stage='error',
            success_count=int(result.get('success_count') or 0),
            total=int(result.get('total') or 0),
            results=result.get('results') or [],
            error=result.get('error') or 'Backup failed',
        )


def _prune_bulk_jobs_locked():
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


def _run_bulk_job(job_id: str):
    with BULK_JOBS_LOCK:
        job = BULK_JOBS.get(job_id)
        if not job:
            return
        job['state'] = 'running'
        job['started_at'] = _utc_iso_now()

    try:
        with app.app_context():
            job = None
            with BULK_JOBS_LOCK:
                job = BULK_JOBS.get(job_id) or {}

            action = job.get('action')
            clients = job.get('clients') or []
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

                # Push update to panel
                session_obj, error = get_xui_session(_server)
                if error:
                    return False, error, 400

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
                                errors.append(f"{template}: success false")
                                continue
                        except ValueError:
                            pass
                        return True, None, 200
                    errors.append(f"{template}: {resp.status_code}")

                app.logger.warning(f"Bulk update client failed for {_email}: {'; '.join(errors)}")
                return False, 'Update failed', 400

            for item in clients:
                client_ref = item
                if not isinstance(item, dict):
                    with BULK_JOBS_LOCK:
                        j = BULK_JOBS.get(job_id) or {}
                        pr = j.get('progress') or {}
                        pr['processed'] = int(pr.get('processed', 0) or 0) + 1
                        pr['failed'] = int(pr.get('failed', 0) or 0) + 1
                        j['progress'] = pr
                        BULK_JOBS[job_id] = j
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
                    with BULK_JOBS_LOCK:
                        j = BULK_JOBS.get(job_id) or {}
                        pr = j.get('progress') or {}
                        pr['processed'] = int(pr.get('processed', 0) or 0) + 1
                        pr['failed'] = int(pr.get('failed', 0) or 0) + 1
                        j['progress'] = pr
                        errs = j.get('errors') or []
                        if len(errs) < 50:
                            errs.append({'client': client_ref, 'error': 'server_id, inbound_id and email are required'})
                        j['errors'] = errs
                        BULK_JOBS[job_id] = j
                    continue

                server = servers_by_id.get(server_id)
                if not server:
                    with BULK_JOBS_LOCK:
                        j = BULK_JOBS.get(job_id) or {}
                        pr = j.get('progress') or {}
                        pr['processed'] = int(pr.get('processed', 0) or 0) + 1
                        pr['failed'] = int(pr.get('failed', 0) or 0) + 1
                        j['progress'] = pr
                        errs = j.get('errors') or []
                        if len(errs) < 50:
                            errs.append({'client': {'server_id': server_id, 'inbound_id': inbound_id, 'email': email}, 'error': 'Server not found'})
                        j['errors'] = errs
                        BULK_JOBS[job_id] = j
                    continue

                # Optional conditional targeting
                if normalized_conditions and (normalized_conditions.get('enable_state') != 'any' or normalized_conditions.get('expiry_type') != 'any'):
                    try:
                        snap, snap_err = _fetch_client_snapshot(user, server, inbound_id, email)
                        if snap_err:
                            raise RuntimeError(snap_err)
                        if not _matches_conditions(snap, normalized_conditions):
                            with BULK_JOBS_LOCK:
                                j = BULK_JOBS.get(job_id) or {}
                                pr = j.get('progress') or {}
                                pr['processed'] = int(pr.get('processed', 0) or 0) + 1
                                pr['skipped'] = int(pr.get('skipped', 0) or 0) + 1
                                j['progress'] = pr
                                BULK_JOBS[job_id] = j
                            continue
                    except Exception as exc:
                        with BULK_JOBS_LOCK:
                            j = BULK_JOBS.get(job_id) or {}
                            pr = j.get('progress') or {}
                            pr['processed'] = int(pr.get('processed', 0) or 0) + 1
                            pr['failed'] = int(pr.get('failed', 0) or 0) + 1
                            j['progress'] = pr
                            errs = j.get('errors') or []
                            if len(errs) < 50:
                                errs.append({'client': {'server_id': server_id, 'inbound_id': inbound_id, 'email': email}, 'error': str(exc) or 'Condition check failed'})
                            j['errors'] = errs
                            BULK_JOBS[job_id] = j
                        continue

                ok = False
                err = None

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

                with BULK_JOBS_LOCK:
                    j = BULK_JOBS.get(job_id) or {}
                    pr = j.get('progress') or {}
                    pr['processed'] = int(pr.get('processed', 0) or 0) + 1
                    if ok:
                        pr['success'] = int(pr.get('success', 0) or 0) + 1
                    else:
                        pr['failed'] = int(pr.get('failed', 0) or 0) + 1
                        errs = j.get('errors') or []
                        if len(errs) < 50:
                            errs.append({'client': {'server_id': server_id, 'inbound_id': inbound_id, 'email': email}, 'error': err or 'Failed'})
                        j['errors'] = errs
                    j['progress'] = pr
                    BULK_JOBS[job_id] = j

        with BULK_JOBS_LOCK:
            job = BULK_JOBS.get(job_id) or {}
            job['state'] = 'done'
            job['finished_at'] = _utc_iso_now()
            BULK_JOBS[job_id] = job
            _prune_bulk_jobs_locked()
    except Exception as e:
        with BULK_JOBS_LOCK:
            job = BULK_JOBS.get(job_id) or {}
            job['state'] = 'error'
            job['error'] = str(e)
            job['finished_at'] = _utc_iso_now()
            BULK_JOBS[job_id] = job
            _prune_bulk_jobs_locked()


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
                        servers_q = Server.query.filter_by(enabled=True)
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
    return total_stats


def fetch_and_update_server_data(server_id: int):
    """Fetch a single server's inbounds and update GLOBAL_SERVER_DATA in-place."""
    server = db.session.get(Server, int(server_id))
    if not server or not server.enabled:
        raise ValueError("Server not found or disabled")

    admin_user = Admin.query.filter(or_(Admin.is_superadmin == True, Admin.role == 'superadmin')).first()
    if not admin_user:
        admin_user = SimpleNamespace(role='superadmin', id=0, is_superadmin=True)

    session_obj, error = get_xui_session(server)
    if error:
        raise RuntimeError(error)

    inbounds, fetch_error, detected_type = fetch_inbounds(session_obj, server.host, server.panel_type)
    if fetch_error:
        raise RuntimeError(fetch_error)

    online_index, _ = fetch_onlines(session_obj, server.host, server.panel_type)
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


@app.after_request
def add_security_headers(response):
    # Baseline security headers (kept permissive to avoid breaking current inline scripts/styles)
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('Referrer-Policy', 'same-origin')
    response.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')

    nonce = getattr(g, 'csp_nonce', None) or ''
    
    # Debug endpoint
    # print(f"DEBUG: endpoint={getattr(request, 'endpoint', '')}", flush=True)

    # The public subscription page uses local compiled CSS (no Tailwind CDN runtime),
    # so we can keep a nonce-based style-src everywhere.
    style_src = f"style-src 'self' 'nonce-{nonce}'"

    style_src += " https://fonts.googleapis.com https://cdn.quilljs.com; "
    response.headers.setdefault(
        'Content-Security-Policy',
        (
            "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'self'; "
            "img-src 'self' data:; "
            "font-src 'self' data: https://fonts.gstatic.com; "
            f"{style_src}"
            "style-src-attr 'unsafe-inline'; "
            f"script-src 'self' 'nonce-{nonce}' https://code.jquery.com https://cdn.jsdelivr.net https://cdn.quilljs.com; "
            "script-src-attr 'unsafe-inline'; "
            "connect-src 'self'"
        )
    )
    return response
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_recycle': 1800,
    'pool_pre_ping': True
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


def _pg_dump_backup(dest_path: str) -> None:
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
        '--file', dest_path,
        '--dbname', uri,
    ]
    subprocess.run(cmd, check=True, env=env)


def _create_database_backup_file(prefix: str) -> str:
    """Create a DB backup in BACKUP_DIR and return filename."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    if _is_sqlite_db():
        db_path = os.path.join(app.instance_path, 'servers.db')
        if not os.path.exists(db_path):
            raise FileNotFoundError('Database file not found')

        filename = f'{prefix}_{timestamp}.db'
        dest = os.path.join(BACKUP_DIR, filename)
        shutil.copy2(db_path, dest)
        return filename

    if _is_postgres_db():
        filename = f'{prefix}_{timestamp}.dump'
        dest = os.path.join(BACKUP_DIR, filename)
        _pg_dump_backup(dest)
        return filename

    raise RuntimeError('Unsupported database backend for backup')


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
        return datetime.fromisoformat(value)
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
    return {
        'enabled': enabled,
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


def _telegram_get_me(token: str, proxies: dict | None = None, timeout_sec: int = 10):
    url = f"https://api.telegram.org/bot{token}/getMe"
    return requests.get(url, proxies=proxies, timeout=timeout_sec)


def _telegram_send_document(token: str, chat_id: str, file_path: str, caption: str | None, proxies: dict | None = None):
    url = f"https://api.telegram.org/bot{token}/sendDocument"
    data = {'chat_id': chat_id}
    if caption:
        data['caption'] = caption
    with open(file_path, 'rb') as handle:
        files = {'document': (os.path.basename(file_path), handle)}
        return requests.post(url, data=data, files=files, proxies=proxies, timeout=30)


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

        now = datetime.utcnow()
        _set_system_setting_value('telegram_backup_last_run', now.isoformat())
        db.session.commit()

        servers = Server.query.filter_by(enabled=True).all()
        if not servers:
            return {'success': False, 'error': 'No enabled servers found'}

        if progress_cb:
            try:
                progress_cb({'stage': 'fetching_servers', 'progress': {'total': len(servers), 'processed': 0}})
            except Exception:
                pass

        tmp_dir = tempfile.mkdtemp(prefix='telegram_backup_', dir=TELEGRAM_BACKUP_TMP_DIR)
        results = []

        total_servers = len(servers)
        processed_servers = 0

        for server in servers:
            if progress_cb:
                try:
                    progress_cb({'stage': f"xui_login:{server.name}", 'progress': {'total': total_servers, 'processed': processed_servers}})
                except Exception:
                    pass

            session_obj, error = get_xui_session(server)
            if error:
                results.append({'server_id': server.id, 'server_name': server.name, 'success': False, 'error': f"X-UI Connection Failed: {error}"})
                processed_servers += 1
                if progress_cb:
                    try:
                        progress_cb({'stage': f"xui_failed:{server.name}", 'progress': {'total': total_servers, 'processed': processed_servers}})
                    except Exception:
                        pass
                continue

            if progress_cb:
                try:
                    progress_cb({'stage': f"xui_download_backup:{server.name}", 'progress': {'total': total_servers, 'processed': processed_servers}})
                except Exception:
                    pass

            payload, ext, err = _fetch_xui_backup(session_obj, server)
            if err or not payload:
                results.append({'server_id': server.id, 'server_name': server.name, 'success': False, 'error': f"X-UI Backup Download Failed: {err or 'Empty response'}"})
                processed_servers += 1
                if progress_cb:
                    try:
                        progress_cb({'stage': f"xui_failed:{server.name}", 'progress': {'total': total_servers, 'processed': processed_servers}})
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

            caption = f"{server.name} - {format_jalali(now) or now.isoformat()}"
            if progress_cb:
                try:
                    progress_cb({'stage': f"telegram_upload:{server.name}", 'progress': {'total': total_servers, 'processed': processed_servers}})
                except Exception:
                    pass
            try:
                resp = _telegram_send_document(token, chat_id, file_path, caption, proxies=proxies)
            except Exception as exc:
                results.append({'server_id': server.id, 'server_name': server.name, 'success': False, 'error': f"Telegram Upload Failed (Network/Proxy): {str(exc)}"})
                processed_servers += 1
                if progress_cb:
                    try:
                        progress_cb({'stage': f"telegram_failed:{server.name}", 'progress': {'total': total_servers, 'processed': processed_servers}})
                    except Exception:
                        pass
                continue

            resp_json, resp_err = _safe_response_json(resp)
            if resp_err:
                results.append({'server_id': server.id, 'server_name': server.name, 'success': False, 'error': f"Telegram API Error: {resp_err}"})
                continue
            if isinstance(resp_json, dict) and resp_json.get('ok'):
                results.append({'server_id': server.id, 'server_name': server.name, 'success': True})
            else:
                msg = None
                if isinstance(resp_json, dict):
                    msg = resp_json.get('description') or resp_json.get('error')
                results.append({'server_id': server.id, 'server_name': server.name, 'success': False, 'error': f"Telegram API Refused: {msg or 'Unknown error'}"})

            processed_servers += 1
            if progress_cb:
                try:
                    progress_cb({'stage': f"server_done:{server.name}", 'progress': {'total': total_servers, 'processed': processed_servers}})
                except Exception:
                    pass

        success_count = sum(1 for r in results if r.get('success'))
        
        # specific top-level error generation
        main_error = None
        if success_count == 0 and results:
            # Collect unique error prefixes
            errs = sorted(list(set(r.get('error', 'Unknown') for r in results)))
            if len(errs) == 1:
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

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["5000 per day", "500 per hour"]
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
    allowed_servers = db.Column(db.Text, default='[]')
    enabled = db.Column(db.Boolean, default=True)
    discount_percent = db.Column(db.Integer, default=0)
    custom_cost_per_day = db.Column(db.Integer, nullable=True)
    custom_cost_per_gb = db.Column(db.Integer, nullable=True)
    telegram_id = db.Column(db.String(100), nullable=True)
    support_telegram = db.Column(db.String(100), nullable=True)
    support_whatsapp = db.Column(db.String(64), nullable=True)
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
            'allowed_servers': parse_allowed_servers(self.allowed_servers),
            'enabled': self.enabled,
            'discount_percent': self.discount_percent,
            'custom_cost_per_day': self.custom_cost_per_day,
            'custom_cost_per_gb': self.custom_cost_per_gb,
            'telegram_id': self.telegram_id,
            'support_telegram': self.support_telegram,
            'support_whatsapp': self.support_whatsapp,
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
    panel_type = db.Column(db.String(50), default='auto')
    sub_path = db.Column(db.String(50), default='/sub/')
    json_path = db.Column(db.String(50), default='/json/')
    sub_port = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'host': self.host,
            'username': self.username,
            'enabled': self.enabled,
            'panel_type': self.panel_type,
            'sub_path': self.sub_path,
            'json_path': self.json_path,
            'sub_port': self.sub_port,
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
            'tutorial_link': self.tutorial_link
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
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'days': self.days,
            'volume': self.volume,
            'price': self.price,
            'reseller_price': self.reseller_price,
            'enabled': self.enabled
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

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'content': self.content,
            'type': self.type,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None
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
        }


class SystemSetting(db.Model):
    __tablename__ = 'system_settings'
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.Text)


RENEW_TEMPLATE_SETTING_KEY = 'renew_template'
DEFAULT_RENEW_TEMPLATE = """🔰{email}\n⌛{days_label} 📊{volume_label}\nتمدید شد"""

MONITOR_SETTINGS_KEY = 'monitor_settings'
GENERAL_TIMEZONE_SETTING_KEY = 'general_timezone'
PANEL_UI_LANG_SETTING_KEY = 'panel_ui_lang'
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
        "soon": "مشترک گرامی {user}، تنها {time} از زمان سرویس شما باقی مانده است.\nتمدید میفرمایید؟"
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
    low_volume_gb = max(0.1, min(low_volume_gb, 1024.0))

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

    if not enabled:
        return {'key': 'inactive', 'label': labels['inactive'], 'emoji': '⏸️', 'tag': 'inactive'}

    low_volume_threshold_gb = float((thresholds or {}).get('low_volume_gb') or 1.0)
    near_expiry_days = int((thresholds or {}).get('near_expiry_days') or 0)
    near_expiry_hours = int((thresholds or {}).get('near_expiry_hours') or 0)
    near_expiry_ms = ((near_expiry_days * 24) + near_expiry_hours) * 3600 * 1000

    if total_bytes > 0 and remaining_bytes is not None and remaining_bytes <= 0:
        return {'key': 'volume_ended', 'label': labels['volume_ended'], 'emoji': '🚫', 'tag': 'ended'}

    if str((expiry_info or {}).get('type') or '').lower() == 'expired':
        return {'key': 'expired', 'label': labels['expired'], 'emoji': '⛔', 'tag': 'expired'}

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


def _get_whatsapp_runtime_settings() -> dict:
    region = _normalize_whatsapp_region(_get_system_config_text(WHATSAPP_DEPLOYMENT_REGION_KEY, 'outside'))
    provider = _normalize_whatsapp_provider(_get_system_config_text(WHATSAPP_PROVIDER_KEY, 'baileys'))

    enabled_requested = _get_system_config_bool(WHATSAPP_ENABLED_KEY, False)
    enabled = bool(enabled_requested and region != 'iran')

    config = {
        'deployment_region': region,
        'provider': provider,
        'enabled_requested': enabled_requested,
        'enabled': enabled,
        'trigger_renew_success': _get_system_config_bool(WHATSAPP_TRIGGER_RENEW_KEY, True),
        'trigger_welcome': _get_system_config_bool(WHATSAPP_TRIGGER_WELCOME_KEY, False),
        'trigger_pre_expiry': _get_system_config_bool(WHATSAPP_TRIGGER_PRE_EXPIRY_KEY, False),
        'min_interval_seconds': _get_system_config_int(WHATSAPP_MIN_INTERVAL_SECONDS_KEY, 45, min_value=45, max_value=3600),
        'daily_limit': _get_system_config_int(WHATSAPP_DAILY_LIMIT_KEY, 100, min_value=1, max_value=50000),
        'pre_expiry_hours': _get_system_config_int(WHATSAPP_PRE_EXPIRY_HOURS_KEY, 24, min_value=1, max_value=720),
        'retry_count': _get_system_config_int(WHATSAPP_RETRY_COUNT_KEY, 3, min_value=0, max_value=10),
        'backoff_seconds': _get_system_config_int(WHATSAPP_BACKOFF_SECONDS_KEY, 30, min_value=5, max_value=3600),
        'circuit_breaker': _get_system_config_bool(WHATSAPP_CIRCUIT_BREAKER_KEY, True),
        'template_renew': _get_system_config_text(WHATSAPP_TEMPLATE_RENEW_KEY, DEFAULT_WHATSAPP_TEMPLATE_RENEW).strip() or DEFAULT_WHATSAPP_TEMPLATE_RENEW,
        'template_welcome': _get_system_config_text(WHATSAPP_TEMPLATE_WELCOME_KEY, DEFAULT_WHATSAPP_TEMPLATE_WELCOME).strip() or DEFAULT_WHATSAPP_TEMPLATE_WELCOME,
        'template_pre_expiry': _get_system_config_text(WHATSAPP_TEMPLATE_PRE_EXPIRY_KEY, DEFAULT_WHATSAPP_TEMPLATE_PRE_EXPIRY).strip() or DEFAULT_WHATSAPP_TEMPLATE_PRE_EXPIRY,
        'gateway_url': _normalize_whatsapp_gateway_url(_get_system_config_text(WHATSAPP_GATEWAY_URL_KEY, '')),
        'gateway_api_key': _get_system_config_text(WHATSAPP_GATEWAY_API_KEY, '').strip(),
        'gateway_timeout_seconds': _get_system_config_int(WHATSAPP_GATEWAY_TIMEOUT_KEY, 10, min_value=3, max_value=60),
    }

    if region == 'iran':
        config['blocked_reason'] = 'deployment_in_iran'
    return config


def _normalize_ascii_digits(value: str | None) -> str:
    val = str(value or '')
    table = str.maketrans('۰۱۲۳۴۵۶۷۸۹٠١٢٣٤٥٦٧٨٩', '01234567890123456789')
    return val.translate(table)


def _extract_iran_mobile_from_text(value: str | None) -> str:
    text_value = _normalize_ascii_digits(value)
    if not text_value:
        return ''
    match = re.search(r'(?:^|[^0-9])(?:\+?98|0098|0)?(9\d{9})(?=$|[^0-9])', text_value)
    if not match:
        return ''
    return f"+98{match.group(1)}"


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


def _send_whatsapp_message(event_name: str, recipient_source: str, message_text: str) -> dict:
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

    recipient = _extract_iran_mobile_from_text(recipient_source)
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

with app.app_context():
    db.create_all()
    
    # Ensure expected columns exist on admins table (older DBs)
    try:
        inspector = inspect(db.engine)
        columns = [c['name'] for c in inspector.get_columns('admins')]
        print(f"Current columns in admins: {columns}")

        admin_missing_cols = [
            ('telegram_id', 'VARCHAR(100)'),
            ('support_telegram', 'VARCHAR(100)'),
            ('support_whatsapp', 'VARCHAR(64)'),
            ('channel_telegram', 'TEXT'),
            ('channel_whatsapp', 'TEXT'),
        ]

        for col_name, col_type in admin_missing_cols:
            if col_name in columns:
                continue
            print(f"{col_name} column missing on admins, attempting to add...")
            with db.engine.connect() as conn:
                conn.execute(text(f'ALTER TABLE admins ADD COLUMN {col_name} {col_type}'))
                conn.commit()
            print(f"Added {col_name} column to admins table")
    except Exception as e:
        print(f"Migration error: {e}")

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
                SubAppConfig(app_code='v2rayng', name='v2rayNG (Android)', title_fa='راهنمای v2rayNG', description_fa='۱. برنامه را دانلود کنید.\n۲. لینک را کپی و Import کنید.', title_en='v2rayNG Guide', description_en='1. Download app.\n2. Copy link and Import.', download_link='https://github.com/2dust/v2rayNG/releases/download/1.8.19/v2rayNG_1.8.19.apk', store_link='https://play.google.com/store/apps/details?id=com.v2ray.ang'),
                SubAppConfig(app_code='nekobox', name='NekoBox (Android)', title_fa='راهنمای NekoBox', description_fa='جایگزین عالی برای v2rayNG.', title_en='NekoBox Guide', description_en='Great alternative.', download_link='https://github.com/MatsuriDayo/NekoBoxForAndroid/releases'),
                SubAppConfig(app_code='streisand', name='Streisand (iOS)', title_fa='راهنمای Streisand', description_fa='پیشنهاد برای آیفون.', title_en='Streisand Guide', description_en='Recommended for iOS.', store_link='https://apps.apple.com/us/app/streisand/id6450534064')
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

def get_xui_session(server):
    # Try to reuse session from cache
    now = time.time()
    if server.id in XUI_SESSION_CACHE:
        cached = XUI_SESSION_CACHE[server.id]
        if now < cached['expiry']:
            return cached['session'], None
        else:
            XUI_SESSION_CACHE.pop(server.id, None)

    session_obj = requests.Session()
    # Explicitly disable proxies for X-UI connections as requested
    session_obj.trust_env = False
    session_obj.proxies = {'http': None, 'https': None}

    try:
        base, webpath = extract_base_and_webpath(server.host)
        normalized_type = (getattr(server, 'panel_type', None) or 'auto').strip().lower()
        panel_api = get_panel_api(normalized_type)
        login_ep = (getattr(panel_api, 'login_endpoint', None) if panel_api else None) or '/login'
        login_url = login_ep if login_ep.startswith('http') else f"{base}{webpath}{login_ep}"
        # Keep login timeout short so refresh endpoints stay responsive.
        panel_password = get_server_password(server)
        login_resp = session_obj.post(login_url, data={"username": server.username, "password": panel_password}, verify=False, timeout=3)
        login_json, login_err = _safe_response_json(login_resp)
        if login_err:
            return None, f"Login failed: {login_err}. Check server Panel URL / webpath and panel type."

        if login_resp.status_code == 200 and isinstance(login_json, dict) and login_json.get('success'):
            # Cache the successful session
            XUI_SESSION_CACHE[server.id] = {
                'session': session_obj,
                'expiry': now + XUI_SESSION_TTL
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
                continue

            data = resp.json()
            if not isinstance(data, dict) or not data.get('success'):
                continue

            if 'obj' in data:
                return data['obj'], None, detected_type
            if 'data' in data:
                d = data['data']
                return (d if isinstance(d, list) else d.get('list', [])), None, detected_type
        except Exception as e:
            app.logger.debug(f"Failed inbounds endpoint {ep}: {str(e)}")
            continue

    return None, "Failed to fetch inbounds", 'auto'


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
                ('POST', '/panel/api/inbounds/onlines'),
                ('GET', '/panel/api/inbounds/onlines'),
            ])
        if normalized_type in ('alireza', 'alireza0', 'xui', 'x-ui', 'auto', ''):
            candidates.extend([
                ('POST', '/xui/API/inbounds/onlines'),
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

                return index, None
            except Exception as e:
                last_error = str(e)
                continue

        # If we tried endpoints but none worked, return a hint (caller still treats it best-effort).
        if candidates:
            hint = last_error or (f"HTTP {last_status}" if last_status is not None else "No response")
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

    xui_version = _pick_first_value(payload, ['xui_version', 'xuiVersion', 'xui'])
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
        try:
            settings = json.loads(inbound.get('settings', '{}'))
        except Exception:
            settings = {}
        for client in settings.get('clients', []):
            if client.get('email') == email:
                return client, inbound
    return None, None

def process_inbounds(inbounds, server, user, allowed_map='*', assignments=None, app_base_url=None, online_index=None):
    processed = []
    stats = {"total_inbounds": 0, "active_inbounds": 0, "total_clients": 0, "online_clients": 0, "active_clients": 0, "inactive_clients": 0, "not_started_clients": 0, "unlimited_expiry_clients": 0, "unlimited_volume_clients": 0, "upload_raw": 0, "download_raw": 0}
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

    for inbound in inbounds:
        try:
            inbound_id_raw = inbound.get('id')
            try:
                inbound_id = int(inbound_id_raw)
            except (TypeError, ValueError):
                inbound_id = inbound_id_raw

            if user.role == 'reseller':
                accessible = is_inbound_accessible(server.id, inbound_id, allowed_map, assignments)
                app.logger.info(f"Reseller check: server={server.id}, inbound={inbound_id}, accessible={accessible}, allowed_map={allowed_map}, assignments={assignments}")
                if not accessible:
                    continue

            settings = json.loads(inbound.get('settings', '{}'))
            clients = settings.get('clients', [])
            client_stats = inbound.get('clientStats', [])
            
            processed_clients = []
            for client in clients:
                email = client.get('email', '')
                email_l = (str(email or '').strip().lower())
                
                if user.role == 'reseller' and email.lower() not in owned_emails:
                    continue 
                
                sub_id = client.get('subId', '')
                parsed_host = urlparse(server.host)
                hostname = parsed_host.hostname
                scheme = parsed_host.scheme
                final_port = server.sub_port if server.sub_port else parsed_host.port
                port_str = f":{final_port}" if final_port else ""
                
                sub_url = ""
                json_url = ""
                dash_sub_url = ""
                
                if sub_id or (server.panel_type == 'sanaei' and client.get('id')):
                    final_id = sub_id if sub_id else client.get('id')
                    base_sub = f"{scheme}://{hostname}{port_str}"
                    s_path = server.sub_path.strip('/')
                    j_path = server.json_path.strip('/')
                    
                    if app_base_url:
                        app_base = app_base_url
                    else:
                        try:
                            app_base = request.url_root.rstrip('/')
                        except RuntimeError:
                            app_base = "" # Fallback for background thread

                    sub_url = f"{base_sub}/{s_path}/{final_id}"
                    json_url = f"{base_sub}/{j_path}/{final_id}"
                    dash_sub_url = f"{app_base}/s/{server.id}/{final_id}"

                client_up = 0
                client_down = 0
                for stat in client_stats:
                    if stat.get('email') == email:
                        client_up = stat.get('up', 0)
                        client_down = stat.get('down', 0)
                        break

                total_bytes = client.get('totalGB', 0) or 0
                remaining_bytes = max(total_bytes - (client_up + client_down), 0) if total_bytes > 0 else None
                total_formatted = format_bytes_gb_tb(total_bytes) if total_bytes > 0 else "Unlimited"

                if total_bytes <= 0:
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

                if is_online:
                    stats["online_clients"] += 1
                
                if client.get('enable', True): stats["active_clients"] += 1
                else: stats["inactive_clients"] += 1
                stats["upload_raw"] += client_up
                stats["download_raw"] += client_down
            
            # استخراج network و security از settings
            streamSettings = settings.get('streamSettings', {})
            network = streamSettings.get('network', 'tcp')
            security = streamSettings.get('security', 'none')
            
            processed.append({
                "id": inbound.get('id'),
                "remark": inbound.get('remark', ''),
                "port": inbound.get('port', ''),
                "protocol": inbound.get('protocol', ''),
                "network": network,
                "security": security,
                "clients": processed_clients,
                "client_count": len(processed_clients),
                "enable": inbound.get('enable', False),
                "server_id": server.id,
                "server_name": server.name,
                "total_up": format_bytes(inbound.get('up', 0)),
                "total_down": format_bytes(inbound.get('down', 0)),
                "up_raw": inbound.get('up', 0),
                "down_raw": inbound.get('down', 0)
            })
            
            stats["total_clients"] += len(processed_clients)
            if inbound.get('enable', False): stats["active_inbounds"] += 1
            
        except Exception as e:
            continue
            
    stats["total_inbounds"] = len(processed)
    stats["total_upload"] = format_bytes(stats["upload_raw"])
    stats["total_download"] = format_bytes(stats["download_raw"])
    stats["total_traffic"] = format_bytes(stats["upload_raw"] + stats["download_raw"])
            
    return processed, stats

# --- ROUTES ---

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if 'admin_id' in session: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        data = request.form if request.form else request.json
        username = data.get('username', '').strip().lower()
        # Case-insensitive lookup to support legacy usernames stored with uppercase.
        user = Admin.query.filter(
            func.lower(Admin.username) == username,
            Admin.enabled == True
        ).first()
        if user and user.check_password(data.get('password')):
            session.permanent = True
            session['admin_id'] = user.id
            session['admin_username'] = user.username
            session['role'] = user.role
            session['is_superadmin'] = (user.role == 'superadmin' or user.is_superadmin)
            user.last_login = datetime.utcnow()
            db.session.commit()
            return jsonify({"success": True}) if request.is_json else redirect(url_for('dashboard'))
        app.logger.warning(f"Failed login attempt for user: {data.get('username')} from IP: {request.remote_addr}")
        return jsonify({"success": False, "error": "Invalid credentials"}) if request.is_json else render_template('login.html', error="Invalid credentials")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    user = db.session.get(Admin, session['admin_id'])
    servers = get_accessible_servers(user)
    
    base_cost_day = get_config('cost_per_day', 0)
    base_cost_gb = get_config('cost_per_gb', 0)
    
    # Calculate user-specific costs
    user_cost_day = calculate_reseller_price(user, base_price=base_cost_day, cost_type='day')
    user_cost_gb = calculate_reseller_price(user, base_price=base_cost_gb, cost_type='gb')
    
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


@app.route('/healthz', methods=['GET'])
def healthz():
    """Lightweight health endpoint for reverse-proxy / uptime checks."""
    return jsonify({
        'success': True,
        'status': 'ok',
        'version': APP_VERSION,
        'uptime_seconds': int(max(0, time.time() - APP_START_TS)),
        'timestamp_utc': datetime.utcnow().isoformat() + 'Z',
    })


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
    if timezone_name:
        if not _is_valid_timezone_name(timezone_name):
            return jsonify({'success': False, 'error': 'Invalid timezone. Example: Asia/Tehran'}), 400
        _set_system_setting_value(GENERAL_TIMEZONE_SETTING_KEY, timezone_name)

    normalized = _normalize_monitor_settings(payload)
    _set_system_setting_value(
        MONITOR_SETTINGS_KEY,
        json.dumps(normalized, ensure_ascii=False)
    )
    db.session.commit()
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
        'ok': 'OK'
    }
    status_order = {
        'ended': 0,
        'expired': 1,
        'low': 2,
        'soon': 3,
        'ok': 4
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
            if not enabled and not debug:
                continue

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

            if total_bytes > 0 and remaining_bytes is not None:
                if remaining_bytes <= 0:
                    status = 'ended'
                    status_rank = 4
                elif remaining_gb is not None and remaining_gb < warning_gb:
                    status = 'low'
                    status_rank = 2

            if expiry_ts and expiry_info.get('type') == 'expired':
                if status_rank < 3:
                    status = 'expired'
                    status_rank = 3
            elif expiry_ts and expiry_info.get('type') in ('today', 'soon'):
                if int(expiry_info.get('days') or 0) <= warning_days and status_rank < 1:
                    status = 'soon'
                    status_rank = 1

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
        online_index, _ = fetch_onlines(session_obj, server_obj.host, server_obj.panel_type)
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

    # If cache is empty and nothing is running, kick off a refresh job (non-blocking)
    if not data.get('inbounds') and not GLOBAL_SERVER_DATA.get('is_updating') and not job:
        job = enqueue_refresh_job(mode='full', server_id=server_id, force=False)
    
    if not data.get('inbounds'):
        return jsonify({
            "success": True, 
            "inbounds": [], 
            "stats": {"total_inbounds": 0, "active_inbounds": 0, "total_clients": 0, 
                      "online_clients": 0, "active_clients": 0, "inactive_clients": 0, "not_started_clients": 0, "unlimited_expiry_clients": 0, "unlimited_volume_clients": 0, "total_traffic": "0 B", 
                      "total_upload": "0 B", "total_download": "0 B"}, 
            "servers": (data.get('servers_status') or []),
            "server_count": len(data.get('servers_status') or [])
            ,
            "is_updating": bool(GLOBAL_SERVER_DATA.get('is_updating')),
            "refresh_job": _summarize_job(job)
        }), (202 if job and job.get('state') in ('queued', 'running') else 200)

    user = db.session.get(Admin, session['admin_id'])
    
    # === حالت سوپرادمین (یا ادمین معمولی غیر ریسلر) ===
    if user.role != 'reseller':
        # Enrich payload with ownership info (who this client is assigned to) for admins/superadmins.
        # This is computed on-demand to avoid changing the background refresh pipeline.
        try:
            server_ids = set()
            email_pairs = set()  # (server_id, email_lower)
            uuid_pairs = set()   # (server_id, client_uuid)

            for inbound in (data.get('inbounds') or []):
                try:
                    sid = int(inbound.get('server_id'))
                except Exception:
                    continue
                server_ids.add(sid)
                for c in (inbound.get('clients') or []):
                    em = (c.get('email') or '').strip().lower()
                    if em:
                        email_pairs.add((sid, em))
                    cu = str(c.get('id') or '').strip()
                    if cu:
                        uuid_pairs.add((sid, cu))

            email_values = {e for (_sid, e) in email_pairs}
            uuid_values = {u for (_sid, u) in uuid_pairs}

            owner_email_map = {}
            owner_uuid_map = {}

            if server_ids and (email_values or uuid_values):
                q = (
                    db.session.query(ClientOwnership, Admin)
                    .join(Admin, ClientOwnership.reseller_id == Admin.id)
                    .filter(ClientOwnership.server_id.in_(list(server_ids)))
                )
                filters = []
                if uuid_values:
                    # Use case-insensitive matching for UUIDs
                    lower_uuid_values = [u.lower() for u in uuid_values if u]
                    if lower_uuid_values:
                        filters.append(func.lower(ClientOwnership.client_uuid).in_(lower_uuid_values))
                if email_values:
                    filters.append(func.lower(ClientOwnership.client_email).in_(list(email_values)))
                if not filters:
                    filters.append(ClientOwnership.id == -1)  # No matches if no filters
                q = q.filter(or_(*filters))

                for own, reseller in (q.all() or []):
                    try:
                        sid = int(own.server_id)
                    except Exception:
                        continue

                    created = own.created_at or datetime.min

                    ou = (own.client_uuid or '').strip().lower()
                    if ou:
                        key_u = (sid, ou)
                        existing_u = owner_uuid_map.get(key_u)
                        ex_created_u = existing_u.get('created_at') if existing_u else datetime.min
                        if (not existing_u) or (created >= ex_created_u):
                            owner_uuid_map[key_u] = {
                                'id': int(reseller.id) if reseller else None,
                                'username': reseller.username if reseller else None,
                                'created_at': created,
                            }

                    em = (own.client_email or '').strip().lower()
                    if em:
                        key = (sid, em)
                        existing = owner_email_map.get(key)
                        ex_created = existing.get('created_at') if existing else datetime.min
                        if (not existing) or (created >= ex_created):
                            owner_email_map[key] = {
                                'id': int(reseller.id) if reseller else None,
                                'username': reseller.username if reseller else None,
                                'created_at': created,
                            }

            if owner_email_map or owner_uuid_map:
                for inbound in (data.get('inbounds') or []):
                    try:
                        sid = int(inbound.get('server_id'))
                    except Exception:
                        continue
                    for c in (inbound.get('clients') or []):
                        cu = str(c.get('id') or '').strip().lower()
                        em = (c.get('email') or '').strip().lower()
                        info = owner_uuid_map.get((sid, cu)) if cu else None
                        if not info and em:
                            info = owner_email_map.get((sid, em))

                        if info and info.get('username'):
                            c['owner_reseller_id'] = info.get('id')
                            c['owner_username'] = info.get('username')
                        else:
                            c.pop('owner_reseller_id', None)
                            c.pop('owner_username', None)
        except Exception:
            pass

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
def api_refresh_job(job_id):
    with REFRESH_JOBS_LOCK:
        job = REFRESH_JOBS.get(job_id)
        job_copy = copy.deepcopy(job) if job else None
    if not job_copy:
        return jsonify({"success": False, "error": "Job not found"}), 404
    return jsonify({
        "success": True,
        "job": _summarize_job(job_copy),
        "is_updating": bool(GLOBAL_SERVER_DATA.get('is_updating')),
        "last_update": GLOBAL_SERVER_DATA.get('last_update')
    })

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
    """Return last user per inbound from cache only (fast path)."""
    last_users = {}
    for inbound in (GLOBAL_SERVER_DATA.get('inbounds') or []):
        try:
            if int(inbound.get('server_id', -1)) != int(server_id):
                continue
        except Exception:
            continue

        inbound_id = inbound.get('id')
        if inbound_id is None:
            continue

        last_email = None
        clients = inbound.get('clients') or []
        if isinstance(clients, list) and clients:
            last_client = clients[-1] if isinstance(clients[-1], dict) else None
            if last_client and last_client.get('email'):
                last_email = last_client.get('email')

        last_users[str(inbound_id)] = last_email

    return jsonify({
        'success': True,
        'server_id': server_id,
        'last_users': last_users,
        'last_update': GLOBAL_SERVER_DATA.get('last_update')
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
@superadmin_required
def get_subscription_page_settings():
    lang = (_get_or_create_system_setting('subscription_page_lang', 'en') or 'en').strip().lower()
    if lang not in ('fa', 'en'):
        lang = 'en'
    return jsonify({'success': True, 'lang': lang})


@app.route('/api/settings/subscription-page', methods=['POST'])
@superadmin_required
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
@superadmin_required
def get_general_settings():
    thresholds = _get_dashboard_status_thresholds()
    return jsonify({
        'success': True,
        'timezone': _get_app_timezone_name(),
        'timezone_options': _get_standard_timezone_options(),
        'panel_lang': _get_panel_ui_lang(),
        'near_expiry_days': thresholds.get('near_expiry_days', 3),
        'near_expiry_hours': thresholds.get('near_expiry_hours', 0),
        'low_volume_gb': thresholds.get('low_volume_gb', 1.0),
    })


@app.route('/api/settings/general', methods=['POST'])
@superadmin_required
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
    low_volume_gb = max(0.1, min(low_volume_gb, 1024.0))

    _set_system_setting_value(GENERAL_TIMEZONE_SETTING_KEY, tz_name)
    _set_system_setting_value(PANEL_UI_LANG_SETTING_KEY, panel_lang)
    _set_system_setting_value(GENERAL_EXPIRY_WARNING_DAYS_KEY, str(near_expiry_days))
    _set_system_setting_value(GENERAL_EXPIRY_WARNING_HOURS_KEY, str(near_expiry_hours))
    _set_system_setting_value(GENERAL_LOW_VOLUME_WARNING_GB_KEY, str(low_volume_gb))
    db.session.commit()
    return jsonify({
        'success': True,
        'message': 'General settings saved',
        'timezone': tz_name,
        'timezone_options': _get_standard_timezone_options(),
        'panel_lang': panel_lang,
        'near_expiry_days': near_expiry_days,
        'near_expiry_hours': near_expiry_hours,
        'low_volume_gb': low_volume_gb,
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
            c_email = client.get('email', '')
            if c_email and query in c_email.lower():
                # کلاینت پیدا شد
                matches.append({
                    "server_id": sid,
                    "server_name": inbound.get('server_name'),
                    # پنل تایپ را از روی سرور پیدا می‌کنیم (چون در کش اینباند نیست)
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

    if user.role == 'reseller' and price > user.credit:
        return False, f"Insufficient credit. Required: {price}, Available: {user.credit}", 402

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
        if charge_amount > user.credit:
            return jsonify({"success": False, "error": f"Insufficient credit. Required: {charge_amount}, Available: {user.credit}"}), 402
    
    session_obj, error = get_xui_session(server)
    if error: return jsonify({"success": False, "error": error}), 400
    
    try:
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
                
                if charge_amount > 0:
                    sender_card = data.get('sender_card', '') or ''
                    card_id = data.get('card_id')
                    if user.role == 'reseller':
                        user.credit -= charge_amount
                        log_transaction(user.id, -charge_amount, 'reset_traffic', "Reset traffic (Credit Usage)", server_id=server.id, sender_card=sender_card, card_id=card_id, category='usage', client_email=email)
                    else:
                        log_transaction(user.id, charge_amount, 'reset_traffic', "Reset traffic (Income)", server_id=server.id, sender_card=sender_card, card_id=card_id, category='income', client_email=email)
                    db.session.commit()

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
            
        target_client, _ = find_client(inbounds, inbound_id, email)
        if not target_client:
            return jsonify({"success": False, "error": "Client not found"}), 404
            
        # Check for duplicate email on the same server (excluding current client)
        if new_email != email:
            for ib in inbounds:
                settings = ib.get('settings', '{}')
                if isinstance(settings, str):
                    try:
                        settings = json.loads(settings)
                    except:
                        settings = {}
                clients = settings.get('clients', [])
                for c in clients:
                    if c.get('email') == new_email:
                        return jsonify({"success": False, "error": f"Client with email '{new_email}' already exists on this server."}), 400

        # Extract ID before modification to ensure we target the correct client
        client_id = target_client.get('id', target_client.get('password', email))
        
        # Update email
        target_client['email'] = new_email
        
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
                        errors.append(f"{template}: success false")
                        continue
                except ValueError:
                    pass
                
                success = True
                break
            
            errors.append(f"{template}: {resp.status_code}")
            
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
            
            return jsonify({"success": True})
        else:
            app.logger.warning(f"Edit client failed for {email}: {'; '.join(errors)}")
            return jsonify({"success": False, "error": "Update failed"}), 400
            
    except Exception as e:
        app.logger.error(f"Edit client error: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/api/client/<int:server_id>/<int:inbound_id>/<email>/delete', methods=['POST'])
@login_required
def delete_client(server_id, inbound_id, email):
    user = db.session.get(Admin, session['admin_id'])
    if not user:
        return jsonify({"success": False, "error": "User not found"}), 401

    server = Server.query.get_or_404(server_id)

    ok, error_message, status_code = _delete_client_core(user, server, inbound_id, email)
    if ok:
        return jsonify({"success": True})
    return jsonify({"success": False, "error": error_message}), status_code


def _delete_client_core(user, server, inbound_id: int, email: str):
    """Core implementation for deleting a client; returns (ok, error, status_code)."""
    if not _has_client_access(user, server.id, email, inbound_id=inbound_id):
        return False, "Access denied", 403

    target_client = _get_cached_raw_client(server.id, inbound_id, email)

    session_obj, error = get_xui_session(server)
    if error:
        return False, error, 400

    try:
        if not target_client:
            inbounds, fetch_err, detected_type = fetch_inbounds(session_obj, server.host, server.panel_type)
            if fetch_err:
                return False, "Failed to fetch inbounds", 400

            persist_detected_panel_type(server, detected_type)
            target_client, _ = find_client(inbounds, inbound_id, email)
            if not target_client:
                return False, "Client not found", 404

        client_id = target_client.get('id', target_client.get('password', email))

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
                        errors.append(f"{template}: success false")
                        continue
                except ValueError:
                    pass

                success = True
                break

            errors.append(f"{template}: {resp.status_code}")

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

            try:
                log_transaction(user.id, 0, 'delete_client', f"Deleted client {email}", server_id=server.id, client_email=email)
            except Exception:
                pass

            return True, None, 200

        app.logger.warning(f"Delete client failed for {email}: {'; '.join(errors)}")
        return False, "Delete failed", 400

    except Exception as exc:
        app.logger.error(f"Delete client error: {str(exc)}")
        return False, str(exc), 400


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

    allowed_actions = {'enable', 'disable', 'delete', 'assign_owner', 'unassign_owner', 'add_days', 'add_volume'}
    if action not in allowed_actions:
        return jsonify({"success": False, "error": "Invalid action"}), 400
    if not isinstance(clients, list) or len(clients) == 0:
        return jsonify({"success": False, "error": "Clients list required"}), 400

    reseller_id = None
    if action in ('assign_owner', 'unassign_owner'):
        if session.get('role') == 'reseller':
            return jsonify({"success": False, "error": "Access denied"}), 403

    if action in ('add_days', 'add_volume'):
        # Basic payload validation here; deep validation happens in the worker.
        if not isinstance(data, dict):
            return jsonify({"success": False, "error": "Invalid data"}), 400
        if action == 'add_days':
            if 'days_delta' not in data:
                return jsonify({"success": False, "error": "days_delta required"}), 400
        if action == 'add_volume':
            if 'volume_gb_delta' not in data:
                return jsonify({"success": False, "error": "volume_gb_delta required"}), 400

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
    job_id = secrets.token_hex(8)
    job = {
        'id': job_id,
        'state': 'queued',
        'action': action,
        'clients': clients,
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
        'error': None,
    }
    with BULK_JOBS_LOCK:
        BULK_JOBS[job_id] = job
        _prune_bulk_jobs_locked()

    if wait_for_completion:
        _run_bulk_job(job_id)
        with BULK_JOBS_LOCK:
            done_job = BULK_JOBS.get(job_id)
            summary = _summarize_bulk_job(done_job) if done_job else None
        return jsonify({'success': True, 'job_id': job_id, 'done': True, 'job': summary})

    t = threading.Thread(target=_run_bulk_job, args=(job_id,), daemon=True)
    t.start()
    return jsonify({'success': True, 'job_id': job_id})


@app.route('/api/client/bulk/job/<job_id>', methods=['GET'])
@login_required
def bulk_client_job(job_id):
    user = db.session.get(Admin, session['admin_id'])
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 401

    with BULK_JOBS_LOCK:
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
    
    server = Server.query.get_or_404(server_id)
    
    try:
        data = request.get_json() or {}
    except:
        return _finish({"success": False, "error": "Invalid data"}, 400)

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
            if days_to_add <= 0:
                return _finish({"success": False, "error": "Package is misconfigured"}, 400)
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
            
            base_cost_day = get_config('cost_per_day', 0)
            base_cost_gb = get_config('cost_per_gb', 0)
            
            user_cost_day = calculate_reseller_price(user, base_price=base_cost_day, cost_type='day')
            user_cost_gb = calculate_reseller_price(user, base_price=base_cost_gb, cost_type='gb')
            
            price = (days_to_add * user_cost_day) + (volume_gb_to_add * user_cost_gb)
            days_label = f"{days_to_add} Days" if days_to_add > 0 else "Unlimited Days"
            if not volume_provided:
                vol_label = "Keep Volume"
            else:
                vol_label = f"{volume_gb_to_add} GB" if volume_gb_to_add > 0 else "Unlimited Volume"
            description = f"Renew Custom: {days_label}, {vol_label} - {email}"
    except (ValueError, TypeError):
        return _finish({"success": False, "error": "Invalid data"}, 400)

    if is_free:
        price = 0
    
    if user.role == 'reseller':
        if not _has_client_access(user, server_id, email, inbound_id=inbound_id):
            return _finish({"success": False, "error": "Access denied"}, 403)
        if price > 0 and user.credit < price:
            return _finish({"success": False, "error": f"Insufficient credit. Required: {price}, Available: {user.credit}"}, 402)
    
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
        
        # Update client
        target_client['expiryTime'] = new_expiry
        target_client['totalGB'] = new_volume
        
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

        templates = collect_endpoint_templates(server.panel_type, 'client_update', CLIENT_UPDATE_FALLBACKS)
        errors = []
        t_update0 = time.perf_counter()
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
                if reset_traffic:
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
                        log_transaction(user.id, -price, 'renew', "User Renewal (Credit Usage)", server_id=server.id, sender_card=sender_card, card_id=card_id, category='usage', client_email=email)
                    else:
                        log_transaction(user.id, price, 'renew', "User Renewal (Income)", server_id=server.id, sender_card=sender_card, card_id=card_id, category='income', client_email=email)
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
                    msg_days = 0
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
                        msg_volume = 0
                        volume_label = "♾️"
                    else:
                        msg_volume = int(remaining_gb_before)
                        volume_label = f"{remaining_gb_before_exact:.2f}GB"
                elif volume_gb_to_add == 0:
                    msg_volume = 0
                    volume_label = "♾️"
                elif reset_traffic:
                    msg_volume = int(volume_gb_to_add)
                    volume_label = f"{msg_volume}GB"
                else:
                    if not has_limited_volume:
                        msg_volume = 0
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
                copy_text = _render_text_template(tpl_content, {
                    'email': email,
                    'days': msg_days,
                    'days_label': days_label,
                    'volume': msg_volume,
                    'volume_label': volume_label,
                    'date': date_label,
                    'server_name': getattr(server, 'name', '') or '',
                    'mode': mode,
                    'dashboard_link': dashboard_link,
                })

                whatsapp_runtime = _get_whatsapp_runtime_settings()
                whatsapp_delivery = _send_whatsapp_message('renew_success', email, copy_text)
                whatsapp_meta = {
                    'enabled': whatsapp_runtime.get('enabled', False),
                    'deployment_region': whatsapp_runtime.get('deployment_region', 'outside'),
                    'provider': whatsapp_runtime.get('provider', 'baileys'),
                    'trigger_renew_success': whatsapp_runtime.get('trigger_renew_success', False),
                    'blocked_reason': whatsapp_runtime.get('blocked_reason') if not whatsapp_runtime.get('enabled', False) else None,
                    'delivery': whatsapp_delivery,
                }

                return _finish({"success": True, "copy_text": copy_text, "verify": verify, "whatsapp": whatsapp_meta})

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
        allowed_servers=serialize_allowed_servers(data.get('allowed_servers', [])),
        enabled=data.get('enabled', True),
        discount_percent=int(data.get('discount_percent', 0)),
        custom_cost_per_day=int(data.get('custom_cost_per_day')) if data.get('custom_cost_per_day') is not None else None,
        custom_cost_per_gb=int(data.get('custom_cost_per_gb')) if data.get('custom_cost_per_gb') is not None else None,
        telegram_id=sanitize_html(data.get('telegram_id')),
        support_telegram=_clean_telegram_username(data.get('support_telegram')),
        support_whatsapp=_clean_whatsapp_number(data.get('support_whatsapp')),
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

    return jsonify(payload)

@app.route('/api/servers', methods=['POST'])
@login_required
def add_server():
    if session.get('role') == 'reseller':
        return jsonify({"success": False, "error": "Only admins can add servers"}), 403
    
    data = request.json
    server_password = (data.get('password') or '').strip()
    if not server_password:
        return jsonify({"success": False, "error": "Password is required"}), 400
    server = Server(
        name=sanitize_html(data['name']),
        host=sanitize_html(data['host']),
        username=sanitize_html(data['username']),
        password=encrypt_server_password(server_password),
        panel_type=data.get('panel_type', 'auto'),
        sub_path=data.get('sub_path', '/sub/'),
        json_path=data.get('json_path', '/json/'),
        sub_port=data.get('sub_port')
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
    db.session.commit()
    return jsonify({"success": True})

@app.route('/api/servers/<int:server_id>', methods=['DELETE'])
@login_required
def delete_server(server_id):
    if session.get('role') == 'reseller':
        return jsonify({"success": False, "error": "Only admins can delete servers"}), 403
    
    server = Server.query.get_or_404(server_id)
    db.session.delete(server)
    db.session.commit()
    return jsonify({"success": True})

@app.route('/api/servers/<int:server_id>/test', methods=['POST'])
@login_required
def test_server_connection(server_id):
    server = Server.query.get_or_404(server_id)
    session_obj, error = get_xui_session(server)
    if error:
        return jsonify({"success": False, "error": error}), 400
    return jsonify({"success": True, "panel_type": server.panel_type})

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
        return jsonify({"success": True})
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
        
        base_cost_day = get_config('cost_per_day', 0)
        base_cost_gb = get_config('cost_per_gb', 0)
        
        user_cost_day = calculate_reseller_price(user, base_price=base_cost_day, cost_type='day')
        user_cost_gb = calculate_reseller_price(user, base_price=base_cost_gb, cost_type='gb')
        
        price = (days * user_cost_day) + (volume_gb * user_cost_gb)
        description = f"Custom Plan: {days} Days, {volume_gb} GB - {email}"

    if is_free:
        price = 0

    if user.role == 'reseller':
        if not is_server_accessible(server_id, allowed_map, assignments):
            return jsonify({"success": False, "error": "Access to this server is denied"}), 403
        if not is_inbound_accessible(server_id, inbound_id, allowed_map, assignments):
            return jsonify({"success": False, "error": "Access to this inbound is denied"}), 403
        
        if price > 0 and user.credit < price:
            return jsonify({"success": False, "error": f"Insufficient credit. Required: {price}, Available: {user.credit}"}), 402

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
            "enable": True,
            "expiryTime": expiry_time,
            "totalGB": volume_gb * 1024 * 1024 * 1024 if volume_gb > 0 else 0,
            "subId": client_sub_id,
            "limitIp": 0,
            "flow": "",
            "tgId": "",
            "reset": 0
        }

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

        settings = json.loads(inbound_data['settings'])
        
        for c in settings['clients']:
            if c['email'] == email: return jsonify({"success": False, "error": f"Email '{email}' already exists on server"})
            
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
            
            # Fetch direct link from upstream subscription instead of generating manually
            direct_link = None
            try:
                sub_resp = requests.get(
                    sub_url, 
                    headers={'User-Agent': 'v2rayng'}, 
                    timeout=10, 
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

            return jsonify({
                "success": True,
                "client": {
                    "email": email,
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
    user = db.session.get(Admin, session['admin_id'])
    packages = Package.query.filter_by(enabled=True).all()
    
    result = []
    for p in packages:
        p_dict = p.to_dict()
        # Calculate price for this user
        p_dict['price'] = calculate_reseller_price(user, package=p)
        result.append(p_dict)
        
    return jsonify(result)

@app.route('/admin/packages', methods=['POST'])
@superadmin_required
def create_package():
    data = request.json
    package = Package(
        name=data.get('name'),
        days=int(data.get('days')),
        volume=int(data.get('volume')),
        price=int(data.get('price')),
        reseller_price=int(data.get('reseller_price')) if data.get('reseller_price') is not None else None,
        enabled=data.get('enabled', True)
    )
    db.session.add(package)
    db.session.commit()
    return jsonify({"success": True, "id": package.id})

@app.route('/admin/packages/<int:package_id>', methods=['PUT'])
@superadmin_required
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
    db.session.commit()
    return jsonify({"success": True})

@app.route('/admin/packages/<int:package_id>', methods=['DELETE'])
@superadmin_required
def delete_package(package_id):
    package = Package.query.get_or_404(package_id)
    db.session.delete(package)
    db.session.commit()
    return jsonify({"success": True})

@app.route('/admin/config', methods=['POST'])
@superadmin_required
def update_config():
    data = request.json
    for key, value in data.items():
        config = db.session.get(SystemConfig, key)
        if config:
            config.value = str(value)
        else:
            db.session.add(SystemConfig(key=key, value=str(value)))
    db.session.commit()
    return jsonify({"success": True})

@app.route('/admin/charge', methods=['POST'])
@superadmin_required
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
@superadmin_required
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
@superadmin_required
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
            try:
                settings = json.loads(inbound.get('settings', '{}'))
            except Exception:
                continue
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
    fallback_headers = {
        'Subscription-Userinfo': user_info_header,
        'Profile-Update-Interval': '3600',
        'Content-Type': 'text/plain; charset=utf-8',
        'Profile-Title': f"{server.name} - {client_email}"
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
        'hiddify', 'happ',  # <--- 'happ' placed in universal/cross-platform

        # --- iOS Clients ---
        'shadowrocket', 'streisand', 'v2box', 'kitsunebi', 'quantumult', 
        'surge', 'loon', 'stash', 'fair', 'pepi', 'i2ray', 'foxray', 'potatso',
        'oneclick',
        
        # --- Android Clients ---
        'v2rayng', 'sagernet', 'nekobox', 'matsuri', 'bifrostv', 
        'igniter', 'anxray', 'surfboard', 'v2raytun', 'mahsa', 'napstarnet',
        
        # --- Desktop (Windows, Mac, Linux) ---
        'nekoray', 'v2rayn', 'v2raya', 'qv2ray', 'mellow', 'flclash', 'furious'
    ]
    wants_b64 = request.args.get('format', '').lower() == 'b64'
    accept = (request.headers.get('Accept') or '').lower()
    accept_prefers_html = ('text/html' in accept) or ('application/xhtml+xml' in accept)
    is_client_app = wants_b64 or any(token in user_agent for token in agent_tokens) or (accept and not accept_prefers_html)

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
            # Fetch from upstream - disable redirects to prevent SSRF via redirection
            resp = requests.get(
                upstream_sub_url, 
                headers={'User-Agent': 'v2rayng'}, 
                timeout=15, 
                verify=False,
                allow_redirects=False
            )
            if resp.status_code == 200:
                # Decode base64 if needed, then split into lines
                raw_content = resp.content or b''
                try:
                    decoded = base64.b64decode(raw_content).decode('utf-8')
                except Exception:
                    decoded = raw_content.decode('utf-8', errors='ignore')
                upstream_configs = [line.strip() for line in decoded.splitlines() if line.strip()]
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

            # Fetch from upstream - disable redirects to prevent SSRF via redirection
            resp = requests.get(
                upstream_sub_url, 
                headers={'User-Agent': request.headers.get('User-Agent')}, 
                timeout=15, 
                verify=False,
                allow_redirects=False
            )
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
    if not subscription_entries:
        subscription_entries.append(sub_url)
    subscription_blob = '\n'.join(subscription_entries)
    encoded_blob = base64.b64encode((subscription_blob or '').encode('utf-8')).decode('utf-8') if subscription_blob else ''

    if encoded_blob and is_client_app and not wants_html_view:
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
        'whatsapp': support_whatsapp.value if support_whatsapp else ''
    }

    channels_info = {
        'telegram': _normalize_url(channel_telegram.value if channel_telegram else '', default_prefix='https://t.me/'),
        'whatsapp': _normalize_url(channel_whatsapp.value if channel_whatsapp else '')
    }

    # If this client is assigned to a reseller, use reseller-defined support/channels instead of global SystemConfig.
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
        announcements_payload = [a.to_dict() for a in active if _announcement_allows(a, server_id=server.id, inbound_id=inbound_id)]
    except Exception:
        announcements_payload = []

    return render_template(
        'subscription.html',
        client=client_payload,
        apps=apps_payload,
        faqs=faqs_payload,
        support=support_info,
        channels=channels_info,
        announcements=announcements_payload,
        page_lang=page_lang,
    )

@app.route('/sub-manager')
@superadmin_required
def sub_manager_page():
    user = db.session.get(Admin, session['admin_id'])
    
    support_telegram = db.session.get(SystemConfig, 'support_telegram')
    support_whatsapp = db.session.get(SystemConfig, 'support_whatsapp')
    channel_telegram = db.session.get(SystemConfig, 'channel_telegram')
    channel_whatsapp = db.session.get(SystemConfig, 'channel_whatsapp')
    whatsapp_cfg = _get_whatsapp_runtime_settings()
    
    return render_template('sub_manager.html',
                         admin_username=session.get('admin_username'),
                         is_superadmin=session.get('is_superadmin', False),
                         role=session.get('role', 'admin'),
                         support_telegram=support_telegram.value if support_telegram else '',
                         support_whatsapp=support_whatsapp.value if support_whatsapp else '',
                         channel_telegram=channel_telegram.value if channel_telegram else '',
                         channel_whatsapp=channel_whatsapp.value if channel_whatsapp else '',
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
    apps = SubAppConfig.query.all()
    return jsonify([a.to_dict() for a in apps])

@app.route('/api/sub-apps', methods=['POST'])
@superadmin_required
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
        tutorial_link=data.get('tutorial_link')
    )
    
    try:
        db.session.add(new_app)
        db.session.commit()
        return jsonify({'success': True, 'app': new_app.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sub-apps/<int:app_id>', methods=['PUT'])
@superadmin_required
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
    
    try:
        db.session.commit()
        return jsonify({'success': True, 'app': app_config.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sub-apps/<int:app_id>', methods=['DELETE'])
@superadmin_required
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
def get_faqs():
    faqs = FAQ.query.order_by(FAQ.created_at.desc()).all()
    return jsonify([f.to_dict() for f in faqs])

@app.route('/api/faqs', methods=['POST'])
@superadmin_required
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
@superadmin_required
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
@superadmin_required
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
@superadmin_required
def get_announcements():
    items = Announcement.query.order_by(Announcement.created_at.desc()).all()
    return jsonify([a.to_dict() for a in items])


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
@superadmin_required
def create_announcement():
    data = request.get_json() or {}
    payload, err = _parse_announcement_payload(data)
    if err:
        return jsonify({'success': False, 'error': err}), 400

    user = db.session.get(Admin, session.get('admin_id')) if session.get('admin_id') else None
    created_by = (getattr(user, 'username', None) or session.get('admin_username') or '').strip() or None

    ann = Announcement(
        message=sanitize_html(payload['message']),
        all_servers=payload['all_servers'],
        targets=payload['targets'],
        start_at=payload['start_at'],
        end_at=payload['end_at'],
        created_by=created_by,
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
@superadmin_required
def update_announcement(announcement_id):
    ann = db.session.get(Announcement, announcement_id)
    if not ann:
        return jsonify({'success': False, 'error': 'Announcement not found'}), 404

    data = request.get_json() or {}
    payload, err = _parse_announcement_payload(data)
    if err:
        return jsonify({'success': False, 'error': err}), 400

    ann.message = sanitize_html(payload['message'])
    ann.all_servers = payload['all_servers']
    ann.targets = payload['targets']
    ann.start_at = payload['start_at']
    ann.end_at = payload['end_at']

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
@superadmin_required
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

@app.route('/api/upload', methods=['POST'])
@superadmin_required
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
@superadmin_required
def packages_page():
    cost_gb = db.session.get(SystemConfig, 'cost_per_gb')
    cost_day = db.session.get(SystemConfig, 'cost_per_day')
    
    return render_template('packages.html', 
                         base_cost_gb=int(cost_gb.value) if cost_gb else 0,
                         base_cost_day=int(cost_day.value) if cost_day else 0,
                         admin_username=session.get('admin_username'),
                         is_superadmin=session.get('is_superadmin', False),
                         role=session.get('role', 'admin'))

@app.route('/bank-cards')
@superadmin_required
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
@superadmin_required
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
@superadmin_required
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
@superadmin_required
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
@superadmin_required
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
@superadmin_required
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
@superadmin_required
def list_auto_windows():
    windows = AutoApprovalWindow.query.order_by(AutoApprovalWindow.starts_at.desc()).all()
    return jsonify({'success': True, 'windows': [w.to_dict() for w in windows]})

@app.route('/api/receipts/auto-windows', methods=['POST'])
@superadmin_required
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
@superadmin_required
def disable_auto_window(window_id):
    window = db.session.get(AutoApprovalWindow, window_id)
    if not window:
        return jsonify({'success': False, 'error': 'Window not found'}), 404
    window.status = 'disabled'
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/templates', methods=['GET'])
@superadmin_required
def get_templates():
    templates = NotificationTemplate.query.order_by(NotificationTemplate.created_at.desc()).all()
    return jsonify({'success': True, 'templates': [t.to_dict() for t in templates]})

@app.route('/api/templates', methods=['POST'])
@superadmin_required
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
@superadmin_required
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
@superadmin_required
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
@superadmin_required
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

@app.route('/api/backups', methods=['GET'])
@login_required
def list_backups():
    backups = []
    if os.path.exists(BACKUP_DIR):
        patterns = ('*.db', '*.dump', '*.sql')
        files = []
        for pat in patterns:
            files.extend(glob.glob(os.path.join(BACKUP_DIR, pat)))
        files.sort(key=os.path.getmtime, reverse=True)
        for f in files:
            name = os.path.basename(f)
            size = os.path.getsize(f)
            date = datetime.fromtimestamp(os.path.getmtime(f)).strftime('%Y-%m-%d %H:%M:%S')
            restore_supported = _is_sqlite_db() and name.lower().endswith('.db')
            
            # Determine type
            if name.startswith('upload_'):
                b_type = 'Uploaded'
            elif name.startswith('auto_'):
                b_type = 'Automatic'
            elif name.startswith('pre_restore_'):
                b_type = 'Safety'
            else:
                b_type = 'System'
                
                backups.append({'name': name, 'size': size, 'date': date, 'type': b_type, 'restore_supported': restore_supported})
            return jsonify({'success': True, 'backups': backups, 'restore_supported': _is_sqlite_db()})

@app.route('/api/backups', methods=['POST'])
@login_required
def create_backup():
    try:
        filename = _create_database_backup_file('backup')
        return jsonify({'success': True, 'message': 'Backup created', 'filename': filename})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

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
    if file_length > MAX_FILE_SIZE:
        return jsonify({'success': False, 'error': 'File too large'}), 413
    
    allowed_exts = {'.db', '.dump', '.sql'}
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
    return jsonify({'success': False, 'error': 'Invalid file type. Allowed: .db, .dump, .sql'})

@app.route('/api/settings/backup', methods=['GET'])
@login_required
def get_backup_settings():
    freq = db.session.get(SystemSetting, 'backup_frequency')
    return jsonify({
        'success': True,
        'frequency': freq.value if freq else 'disabled'
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
    
    db.session.commit()
    return jsonify({'success': True, 'message': 'Settings saved'})


@app.route('/api/settings/telegram-backup', methods=['GET'])
@superadmin_required
def get_telegram_backup_settings():
    settings = _get_telegram_backup_settings()
    return jsonify({'success': True, **settings})


@app.route('/api/settings/telegram-backup', methods=['POST'])
@superadmin_required
def save_telegram_backup_settings():
    try:
        data = request.get_json() or {}
    except Exception:
        data = {}

    enabled = bool(data.get('enabled'))
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
    proxy_port = _parse_int(data.get('proxy_port'), 0, min_value=0, max_value=65535)
    proxy_username = (data.get('proxy_username') or '').strip()
    proxy_password = (data.get('proxy_password') or '').strip()

    if use_proxy:
        if proxy_mode == 'hostport' and (not proxy_host or not proxy_port):
            return jsonify({'success': False, 'error': 'Proxy host and port are required'}), 400
        if proxy_mode == 'url' and not proxy_url:
            return jsonify({'success': False, 'error': 'Proxy URL is required'}), 400

    _set_system_setting_value('telegram_backup_enabled', 'true' if enabled else 'false')
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
@superadmin_required
def test_telegram_backup_settings():
    settings = _get_telegram_backup_settings()
    token = (settings.get('bot_token') or '').strip()
    if not token:
        return jsonify({'success': False, 'error': 'Bot token is required'}), 400

    proxies = _build_telegram_proxies(
        bool(settings.get('use_proxy')),
        settings.get('proxy_mode') or 'url',
        settings.get('proxy_url') or '',
        settings.get('proxy_host') or '',
        int(settings.get('proxy_port') or 0),
        settings.get('proxy_username') or '',
        settings.get('proxy_password') or ''
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
@superadmin_required
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
        TELEGRAM_BACKUP_JOBS[job_id] = job
        _prune_telegram_backup_jobs_locked()

    t = threading.Thread(target=_run_telegram_backup_job, args=(job_id,), daemon=True)
    t.start()
    return jsonify({'success': True, 'job_id': job_id})


@app.route('/api/telegram-backup/job/<job_id>', methods=['GET'])
@superadmin_required
def telegram_backup_job_status(job_id):
    with TELEGRAM_BACKUP_JOBS_LOCK:
        job = TELEGRAM_BACKUP_JOBS.get(job_id)
        if not job:
            return jsonify({'success': False, 'error': 'Job not found'}), 404
        return jsonify({'success': True, 'job': _summarize_telegram_backup_job(job)})

@app.route('/api/settings/ssl', methods=['GET'])
@login_required
def get_ssl_settings():
    cert = db.session.get(SystemSetting, 'ssl_cert_path')
    key = db.session.get(SystemSetting, 'ssl_key_path')
    return jsonify({
        'success': True,
        'cert_path': cert.value if cert else '',
        'key_path': key.value if key else ''
    })

@app.route('/api/settings/ssl', methods=['POST'])
@login_required
def save_ssl_settings():
    data = request.json
    cert_path = data.get('cert_path', '').strip()
    key_path = data.get('key_path', '').strip()
    
    # Save cert path
    cert_setting = db.session.get(SystemSetting, 'ssl_cert_path')
    if not cert_setting:
        cert_setting = SystemSetting(key='ssl_cert_path', value=cert_path)
        db.session.add(cert_setting)
    else:
        cert_setting.value = cert_path
        
    # Save key path
    key_setting = db.session.get(SystemSetting, 'ssl_key_path')
    if not key_setting:
        key_setting = SystemSetting(key='ssl_key_path', value=key_path)
        db.session.add(key_setting)
    else:
        key_setting.value = key_path
    
    db.session.commit()
    return jsonify({'success': True, 'message': 'SSL settings saved'})

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


@app.route('/api/renew-templates', methods=['GET'])
@superadmin_required
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
@superadmin_required
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
@superadmin_required
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
@superadmin_required
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
@superadmin_required
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
    return send_file(path, as_attachment=True)

@app.route('/api/backups/<filename>/restore', methods=['POST'])
@login_required
def restore_backup(filename):
    filename = secure_filename(filename)
    backup_path = os.path.join(BACKUP_DIR, filename)
    if not os.path.exists(backup_path):
        return jsonify({'success': False, 'error': 'Backup not found'}), 404
        
    try:
        if not _is_sqlite_db():
            return jsonify({
                'success': False,
                'error': 'Restore via web UI is only supported for SQLite. For PostgreSQL use pg_restore/psql on the server.'
            }), 400

        db_path = os.path.join(app.instance_path, 'servers.db')
        # Create a safety backup before restore
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safety_backup = os.path.join(BACKUP_DIR, f'pre_restore_{timestamp}.db')
        if os.path.exists(db_path):
            shutil.copy2(db_path, safety_backup)
            
        # 1. بازگردانی دیتابیس
        shutil.copy2(backup_path, db_path)
        
        # 2. پاک کردن سشن برای امنیت (Log out current user)
        session.clear()
        
        # 3. برگرداندن پاسخ موفقیت + ریدارکت سمت کلاینت
        return jsonify({
            'success': True, 
            'message': 'Database restored successfully. Please login again.',
            'redirect': url_for('login')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

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


def fetch_and_update_global_data(force: bool = False, server_ids=None):
    """یک بار داده‌ها را از سرورها واکشی و در RAM به‌روزرسانی می‌کند."""
    try:
        GLOBAL_SERVER_DATA['is_updating'] = True

        servers_q = Server.query.filter_by(enabled=True)
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
                if status_payload:
                    st['xui_version'] = status_payload.get('xui_version')
                    st['xray_version'] = status_payload.get('xray_version')
                    st['xray_state'] = status_payload.get('xray_state')
                    st['xray_core'] = status_payload.get('xray_core')
                    st['online_count'] = status_payload.get('online_count')
                    st['panel_status_error'] = status_error if status_error else None
                    st['panel_status_checked_at'] = now_iso
                status_map[sid] = st
                # keep existing inbounds block (if any)
                continue

            _backoff_record_success(sid)

            if persist_detected_panel_type(srv, detected_type):
                app.logger.info(f"Detected panel type for server {srv.id} as {detected_type}")

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

                # Telegram backups
                tg_enabled = _parse_bool(_get_system_setting_value('telegram_backup_enabled', 'false'))
                if tg_enabled:
                    tg_interval = _parse_int(
                        _get_system_setting_value('telegram_backup_interval_minutes', str(TELEGRAM_BACKUP_DEFAULT_INTERVAL_MINUTES)),
                        TELEGRAM_BACKUP_DEFAULT_INTERVAL_MINUTES,
                        min_value=1,
                        max_value=TELEGRAM_BACKUP_MAX_INTERVAL_MINUTES
                    )
                    last_run_value = _get_system_setting_value('telegram_backup_last_run', '')
                    last_run_dt = _parse_iso_datetime(last_run_value)
                    now_utc = datetime.utcnow()
                    should_run = False
                    if not last_run_dt:
                        should_run = True
                    elif (now_utc - last_run_dt) >= timedelta(minutes=tg_interval):
                        should_run = True

                    if should_run:
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


def ensure_background_threads_started():
    """Start background threads (scheduler + fetcher) once per process."""
    global BACKGROUND_THREADS_STARTED
    if BACKGROUND_THREADS_STARTED:
        return

    BACKGROUND_THREADS_STARTED = True

    try:
        scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
        scheduler_thread.start()
    except Exception as e:
        print(f"Failed to start scheduler thread: {e}")

    try:
        data_thread = threading.Thread(target=background_data_fetcher, daemon=True)
        data_thread.start()
    except Exception as e:
        print(f"Failed to start data fetcher thread: {e}")

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
