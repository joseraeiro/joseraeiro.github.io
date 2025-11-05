---
layout: post
title: "Bridging CrowdStrike to Wazuh/OpenSearch with Two Lean Daemons"
date: 2025-11-05
categories: [notes]
tags: [intro]
---

# Bridging CrowdStrike to Wazuh/OpenSearch with Two Lean Daemons

I wanted CrowdStrike detections and incidents to land in my Wazuh/OpenSearch stack with minimal friction, complete context, and predictable formats—so analysts can pivot, correlate, and alert inside the tools they already live in. The goals were reliability first, elegance second.

> **Quick lookup:** All artifacts—the Python scripts, custom Wazuh detection rules, and the `systemd` unit files—are bundled in the **Appendix** at the end of this document.

---

## High-Level Architecture

Two small Python services run under `systemd`:

* **Detections pipeline**
  Polls `detects/*`, expands **behaviors** into flat rows, and appends **NDJSON** (one JSON per line) to `crowdstrike_detections.jsonl`.

* **Incidents pipeline**
  Polls `incidents/*`, merges **host** objects into the parent incident with a `crowdstrike.` **key prefix** to avoid collisions, and appends NDJSON to `crowdstrike_incidents.jsonl`.

Both services persist state to avoid replays:

* `last_*_timestamp.txt` → last processed time
* `last_*_ids.json` → a set of already-seen IDs

The Wazuh manager tails the NDJSON files and ships parsed JSON straight into OpenSearch. No Logstash/Filebeat required.

---

## Secrets Done Right (No Hardcoded Keys)

The services read credentials from environment variables:

* `CROWDSTRIKE_CLIENT_ID`
* `CROWDSTRIKE_CLIENT_SECRET`

If either is missing, the scripts **fail fast** with a clear error. I load them from an env file owned by `root` (`chmod 600`) to keep secrets out of code, repos, and process args.

> **Tip:** If you prefer a vault, generate the env file at boot via your secret manager agent and use a `systemd` drop-in to point to it.

---

## The Detections Pipeline

* **Query window**: `first_behavior >= last_timestamp`
* **Details endpoint**: `detects/entities/summaries/GET/v1`
* **Flattening**: each behavior becomes a dedicated JSON line, retaining top-level context (host, aid, user, severity, tactics/techniques).
* **Output**: `crowdstrike_detections.jsonl` (append-only)

Why NDJSON? It’s stream-friendly, append-only, and trivial for Wazuh to parse line-by-line without multiline gymnastics.

**Key benefits**

* Clean per-behavior analytics (severity distribution, top techniques, noisy hosts)
* Easier correlation with your own telemetry (process, netflow, auth)

---

## The Incidents Pipeline

* **Query window**: `modified_timestamp > last_timestamp`
* **Details endpoint**: `incidents/entities/incidents/GET/v1`
* **Host merge**: denormalizes `hosts[]` into the parent incident
* **Prefixing**: every incident/host key gets `crowdstrike.` (e.g., `crowdstrike.incident_id`, `crowdstrike.hostname`)
* **Output**: `crowdstrike_incidents.jsonl`

This yields analyst-friendly rows with fewer joins and fewer naming collisions in OpenSearch.

---

## Idempotency & Replay Protection

Each loop:

1. Pull IDs in the time window.
2. **Filter** out IDs seen in `last_*_ids.json`.
3. Fetch details only for new IDs.
4. Write to NDJSON.
5. Update both the last timestamp and the ID set.

This survives restarts and prevents “Groundhog Day” alerts.

---

## Rate Limiting, Backoff, & Stability

* On HTTP **429**, back off (sleep) and retry.
* A polling interval around **30s** balances freshness with rate limits—tune to taste.
* `systemd` keeps services healthy (`Restart=always`, `RestartSec=5`).
* Token retrieval is centralized; caching until expiry is on the roadmap to further reduce auth noise.

---

## Logging, Observability, & Troubleshooting

Both services log to files in the integration directory (detections and incidents use separate log files). Expect:

* `Getting OAuth2 token...` on start
* Counts like `Retrieved N detection IDs`
* `Writing N ... to <file>`
* Full error bodies for non-200 responses

**Tips**

* Rotate logs via logrotate or journald.
* Emit a single-line **health** event each loop (e.g., `status=ok`, last timestamp, batch size) for external scraping.

---

## Shipping into Wazuh/OpenSearch (Zero-Middleware)

Instead of a shipper, I point the **Wazuh Manager** directly at both NDJSON files. Because each line is valid JSON, Wazuh’s JSON log collector parses it cleanly and ships to OpenSearch.

**`ossec.conf` (Manager)**

```xml
<localfile>
  <log_format>json</log_format>
  <location>/home/user/Crowdstrike_integration/*.jsonl</location>
</localfile>
```

**What you’ll see in OpenSearch**

* Fields under the parsed JSON path (commonly `data.*` in Wazuh), e.g.,
  `data.detection_id`, `data.severity`, `data.behaviors.technique`,
  `data.crowdstrike.incident_id`, `data.crowdstrike.hostname`, etc.
* Events in the standard Wazuh indices (e.g., `wazuh-alerts-*`).

**Gotchas**

* Ensure the Wazuh agent’s user can **read** the `.jsonl` files.
* NDJSON is **append-only**—end each record with a newline.
* If you rotate files, **move** old files and write to a new one rather than truncating in place.

---

## Custom Wazuh Rules (Detections & Incidents)

I keep a dedicated rule file at:

```
/var/ossec/etc/rules/crowdstrike.xml
```

> Full XML is included in the **Appendix** with the scripts, as promised.

**What the rules do**

* **Grouping**: everything sits under the `crowdstrike,` group.
* **Entry conditions**:

  * Detections match on JSON fields like `device.platform_id` or `crowdstrike.device_id`.
  * Incidents match on `crowdstrike.device_id` plus incident-specific fields.
* **Severity mapping → Wazuh level**

  * *Detections* (field `severity`, 10–100):

    * 80–100 → Level 15 (Critical)
    * 60–70  → Level 11 (High)
    * 40–50  → Level 9  (Medium)
    * 20–30  → Level 5  (Low)
    * 10     → Level 3  (Informational)
  * *Incidents* (field `crowdstrike.fine_score`, 0–100):

    * 80–100 → Level 15 (Critical)
    * 60–79  → Level 15 (High)
    * 40–59  → Level 15 (Medium)
    * 20–39  → Level 10 (Low)
    * 0–19   → Level 5  (Informational)

**KQL quick filters**

* Detections: `rule.groups: "crowdstrike" AND data.detection_id:*`
* Incidents: `rule.groups: "crowdstrike" AND data.crowdstrike.incident_id:*`
* Critical only: `(data.severity:[80 TO 100]) OR (data.crowdstrike.fine_score:[80 TO 100])`
* Technique pivot (example): `data.behaviors.technique.keyword:"T1059"`

---

## Deploying with `systemd`

Each pipeline runs as its own service with a dedicated working directory. I load the CrowdStrike credentials via an env file and keep write permissions scoped to just the NDJSON and state files.

**Operational checklist**

* Place scripts + state files under a fixed directory (e.g., `/home/user/Crowdstrike_integration/`).
* Point `WorkingDirectory` there in both units.
* Load `/etc/crowdstrike.env` with `CROWDSTRIKE_CLIENT_ID` and `CROWDSTRIKE_CLIENT_SECRET` (`chmod 600`).
* `systemctl daemon-reload && systemctl enable --now Crowdstrike.service Crowdstrike_incidents.service`

> **Hardening:** Consider `ProtectSystem=strict`, `ReadWritePaths=/home/user/Crowdstrike_integration`, `NoNewPrivileges=true`, and running under a dedicated service user once paths/permissions are sorted.

---


## Lessons Learned & Roadmap

* **Environment variables** for creds are painless and safer than hardcoding.
* **NDJSON** keeps ingestion simple, resilient, and fast.
* **Denormalize** where it removes joins (prefixing avoids naming fights).
* **Persisted state** (timestamps + IDs) is the difference between “nice demo” and “production.”

**Next up**

* **Enrichment**: join CrowdStrike host IDs to CMDB (owner, BU) at write time.
* **Dashboards & alerts**: convert the useful KQLs into panels and notifications.

---

## Appendix (Scripts & Rules)

### Python scripts: **Detections** and **Incidents**

#### detections.py

```python
#!/usr/bin/env python3
"""
CrowdStrike Alerts → NDJSON writer (Wazuh/OpenSearch ingestion)

- Uses POST /alerts/combined/alerts/v1 (after-token pagination)
- Sorts & watermarks on created_timestamp (stable, spec-aligned)
- Auth via CROWDSTRIKE_CLIENT_ID / CROWDSTRIKE_CLIENT_SECRET env vars
- Writes NDJSON to crowdstrike_alerts.jsonl
- Persists last_alert_timestamp.txt and last_alert_ids.json for idempotency
"""

import os
import json
import time
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple

import requests
import jsonlines

# ----------------------------- Configuration ---------------------------------

# Files
OUTFILE = 'crowdstrike_alerts.jsonl'
LAST_TIMESTAMP_FILE = 'last_alert_timestamp.txt'
LAST_IDS_FILE = 'last_alert_ids.json'
LOG_FILE = 'crowdstrike_integration.log'

# CrowdStrike cloud base (EU-1 here; change if needed: https://api.crowdstrike.com for US-1, etc.)
BASE_URL = 'https://api.eu-1.crowdstrike.com'

# Poll interval
POLL_SECONDS = 30

# Page size (spec max 1000)
PAGE_LIMIT = 1000

# Default backfill window if no state exists
DEFAULT_BACKFILL_DAYS = 1

# HTTP timeouts
REQUEST_TIMEOUT_SECS = 120

# --- Auth (from environment) -------------------------------------------------

CLIENT_ID = os.environ.get('CROWDSTRIKE_CLIENT_ID')
CLIENT_SECRET = os.environ.get('CROWDSTRIKE_CLIENT_SECRET')



# ------------------------------- Logging -------------------------------------

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)

# ------------------------------- Helpers -------------------------------------


def _require_creds() -> None:
    if not CLIENT_ID or not CLIENT_SECRET:
        msg = "Missing CROWDSTRIKE_CLIENT_ID or CROWDSTRIKE_CLIENT_SECRET environment variables."
        logging.error(msg)
        raise RuntimeError(msg)


def _iso_utc_now_minus(days: int) -> str:
    """Return ISO8601 Z time (no microseconds) for now minus N days."""
    return (datetime.utcnow() - timedelta(days=days)).isoformat(timespec='seconds') + 'Z'


def _pick_watermark_timestamp(alert: Dict) -> Optional[str]:
    """
    Choose a stable timestamp for watermark advancement.
    Prefer created_timestamp (stable), then timestamp, then updated_timestamp.
    """
    for key in ('created_timestamp', 'timestamp', 'updated_timestamp'):
        val = alert.get(key)
        if isinstance(val, str) and val:
            return val
    return None


def _parse_retry_after_ms(header_val: Optional[str]) -> Optional[float]:
    """
    X-RateLimit-RetryAfter: milliseconds since epoch (per spec).
    Returns seconds to wait (float) if header is valid and in the future.
    """
    if not header_val:
        return None
    try:
        ms = int(header_val)
        now = time.time()
        wait = (ms / 1000.0) - now
        return wait if wait > 0 else 0.0
    except Exception:
        return None


# ------------------------------- OAuth2 --------------------------------------




def get_oauth2_token() -> str:
    _require_creds()
    logging.info("Getting OAuth2 token...")
    url = f'{BASE_URL}/oauth2/token'
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    data = {'client_id': CLIENT_ID, 'client_secret': CLIENT_SECRET}
    resp = requests.post(url, headers=headers, data=data, timeout=REQUEST_TIMEOUT_SECS)

    # Treat any 2xx as success; only log errors for >=400
    if not resp.ok:
        logging.error("OAuth2 HTTP %s: %s", resp.status_code, resp.text)
    resp.raise_for_status()

    try:
        token = resp.json()['access_token']
    except Exception as e:
        # Defensive: surface unexpected payloads loudly
        logging.error("OAuth2 response parse error: %s | body=%s", e, resp.text)
        raise
    logging.info("Obtained OAuth2 token.")
    return token


# ------------------------------- Alerts API ----------------------------------


def get_alerts_page(
    token: str,
    start_time: str,
    after: Optional[str] = None,
    limit: int = PAGE_LIMIT,
) -> Tuple[List[Dict], Optional[str]]:
    """
    POST /alerts/combined/alerts/v1
    - filter on created_timestamp (stable)
    - sort ascending to advance watermark safely
    - paginate using 'after' token from meta.pagination.after
    Returns: (resources, next_after)
    """
    url = f'{BASE_URL}/alerts/combined/alerts/v1'
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
    }
    body = {
        'filter': f'created_timestamp:>="{start_time}"',
        'limit': limit,
        'sort': 'created_timestamp|asc',
    }
    if after:
        body['after'] = after

    resp = requests.post(url, headers=headers, json=body, timeout=REQUEST_TIMEOUT_SECS)
    if resp.status_code != 200:
        logging.error("Alerts API error %s: %s", resp.status_code, resp.text)
    resp.raise_for_status()

    obj = resp.json() if resp.content else {}
    resources = obj.get('resources') or []
    meta = obj.get('meta') or {}
    pagination = meta.get('pagination') or {}
    next_after = pagination.get('after')

    return resources, next_after


# --------------------------------- State -------------------------------------


def load_last_processed_data(
    ts_file: str, ids_file: str
) -> Tuple[str, set]:
    """Load last watermark timestamp and processed alert IDs."""
    if os.path.exists(ts_file):
        with open(ts_file, 'r') as f:
            last_ts = f.readline().strip()
        logging.info("Loaded last timestamp: %s", last_ts)
    else:
        last_ts = _iso_utc_now_minus(DEFAULT_BACKFILL_DAYS)
        logging.info("No last timestamp found. Using default: %s", last_ts)

    processed_ids = set()
    if os.path.exists(ids_file):
        try:
            with open(ids_file, 'r') as f:
                processed_ids = set(json.load(f))
            logging.info("Loaded processed alert IDs: %d", len(processed_ids))
        except Exception as e:
            logging.warning("Could not load %s (%s). Starting fresh.", ids_file, e)
            processed_ids = set()

    return last_ts, processed_ids


def save_last_processed_data(
    ts_file: str, ids_file: str, last_ts: str, processed_ids: set
) -> None:
    with open(ts_file, 'w') as f:
        f.write(last_ts)
    logging.info("Saved last timestamp: %s", last_ts)

    # sort for stable diffs
    with open(ids_file, 'w') as f:
        json.dump(sorted(processed_ids), f)
    logging.info("Saved processed alert IDs: %d", len(processed_ids))


# --------------------------------- IO ----------------------------------------


def write_alerts_to_jsonl(alerts: List[Dict], filename: str) -> None:
    logging.info("Writing %d alerts to %s...", len(alerts), filename)
    with jsonlines.open(filename, mode='a') as writer:
        for a in alerts:
            writer.write(a)
    logging.info("Writing complete.")


# --------------------------------- Main --------------------------------------


def main() -> None:
    logging.info("Starting Alerts pipeline...")
    last_timestamp, processed_ids = load_last_processed_data(LAST_TIMESTAMP_FILE, LAST_IDS_FILE)

    while True:
        try:
            token = get_oauth2_token()

            after = None
            total_seen = 0
            batch_new: List[Dict] = []

            while True:
                alerts, after = get_alerts_page(token, last_timestamp, after=after)
                count = len(alerts)
                total_seen += count

                if count == 0:
                    break

                # Deduplicate new alerts by id
                for alert in alerts:
                    aid = alert.get('id')
                    if aid and aid not in processed_ids:
                        batch_new.append(alert)

                if not after:
                    break  # last page for this cycle

            if batch_new:
                write_alerts_to_jsonl(batch_new, OUTFILE)

                # Update processed IDs
                for a in batch_new:
                    aid = a.get('id')
                    if aid:
                        processed_ids.add(aid)

                # Advance watermark using max created/timestamp
                ts_candidates = [t for t in (_pick_watermark_timestamp(a) for a in batch_new) if t]
                if ts_candidates:
                    last_timestamp = max(ts_candidates)

                save_last_processed_data(LAST_TIMESTAMP_FILE, LAST_IDS_FILE, last_timestamp, processed_ids)
                logging.info("Cycle complete: total_seen=%d, new_written=%d", total_seen, len(batch_new))
            else:
                logging.info("No new alerts found (seen=%d).", total_seen)

            time.sleep(POLL_SECONDS)

        except requests.exceptions.HTTPError as e:
            status = getattr(e.response, 'status_code', None)
            text = getattr(e.response, 'text', '')
            logging.error("HTTPError %s: %s", status, text)

            if status == 429:
                # Respect dynamic retry header if present
                retry_hdr = e.response.headers.get('X-RateLimit-RetryAfter') if e.response else None
                wait = _parse_retry_after_ms(retry_hdr)
                if wait is None or wait <= 0:
                    wait = 60.0
                # clamp absurd waits
                wait = min(wait, 600.0)
                logging.warning("Rate limit exceeded. Sleeping for %.1f seconds.", wait)
                time.sleep(wait)
            else:
                raise

        except Exception as e:
            logging.error("Unhandled error: %s", e)
            raise


if __name__ == '__main__':
    main()


```

#### incidents.py

```python

import requests
import jsonlines
import time
import os
from datetime import datetime, timedelta
import logging
import json

LAST_TIMESTAMP_FILE = 'last_incident_timestamp.txt'
LAST_INCIDENT_IDS_FILE = 'last_incident_ids.json'
LOG_FILE = 'crowdstrike_incidents_integration.log'
KEY_PREFIX = 'crowdstrike.'

# Read CrowdStrike API credentials from environment
CLIENT_ID = os.environ.get('CROWDSTRIKE_CLIENT_ID')
CLIENT_SECRET = os.environ.get('CROWDSTRIKE_CLIENT_SECRET')

# Set up logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def get_oauth2_token():
    if not CLIENT_ID or not CLIENT_SECRET:
        msg = "Missing CROWDSTRIKE_CLIENT_ID or CROWDSTRIKE_CLIENT_SECRET environment variables."
        logging.error(msg)
        raise RuntimeError(msg)

    logging.info("Getting OAuth2 token...")
    url = 'https://api.eu-1.crowdstrike.com/oauth2/token'
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    data = {'client_id': CLIENT_ID, 'client_secret': CLIENT_SECRET}
    response = requests.post(url, headers=headers, data=data)
    response.raise_for_status()
    token = response.json()['access_token']
    logging.info("Obtained OAuth2 token.")
    return token

def get_incident_ids(token, start_time):
    logging.info(f"Retrieving incident IDs starting from {start_time}...")
    url = 'https://api.eu-1.crowdstrike.com/incidents/queries/incidents/v1'
    headers = {'Authorization': f'Bearer {token}'}
    params = {'limit': 500, 'filter': f'modified_timestamp:>"{start_time}"'}
    response = requests.get(url, headers=headers, params=params)
    if response.status_code != 200:
        logging.error(f"Error {response.status_code}: {response.content}")
    response.raise_for_status()
    incidents = response.json()
    logging.info(f"Retrieved {len(incidents.get('resources', []))} incident IDs.")
    return incidents

def get_incident_details(token, incident_ids):
    logging.info(f"Retrieving details for {len(incident_ids)} incidents...")
    url = 'https://api.eu-1.crowdstrike.com/incidents/entities/incidents/GET/v1'
    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
    data = {'ids': incident_ids}
    response = requests.post(url, headers=headers, json=data)
    if response.status_code != 200:
        logging.error(f"Error {response.status_code}: {response.content}")
    response.raise_for_status()
    details = response.json()
    logging.info(f"Retrieved details for {len(details.get('resources', []))} incidents.")
    return details

def flatten_incidents(incidents):
    flattened_incidents = []
    for incident in incidents:
        base_info = {f"{KEY_PREFIX}{k}": v for k, v in incident.items() if k != 'hosts'}
        hosts = incident.get('hosts', [])
        for host in hosts:
            flattened_host = {f"{KEY_PREFIX}{k}": v for k, v in host.items()}
            flattened_incident = {**base_info, **flattened_host}
            flattened_incidents.append(flattened_incident)
    return flattened_incidents

def write_incidents_to_jsonl(incidents, filename):
    logging.info(f"Writing {len(incidents)} incidents to {filename}...")
    with jsonlines.open(filename, mode='a') as writer:
        for incident in incidents:
            writer.write(incident)
    logging.info("Writing complete.")

def load_last_processed_data(timestamp_file, incident_ids_file):
    last_timestamp = None
    processed_ids = set()
    if os.path.exists(timestamp_file):
        with open(timestamp_file, 'r') as file:
            last_timestamp = file.readline().strip()
            logging.info(f"Loaded last timestamp: {last_timestamp}")
    else:
        last_timestamp = (datetime.utcnow() - timedelta(days=5)).strftime('%Y-%m-%dT%H:%M:%SZ')
        logging.info(f"No last timestamp found. Using default: {last_timestamp}")

    if os.path.exists(incident_ids_file):
        with open(incident_ids_file, 'r') as file:
            processed_ids = set(json.load(file))
            logging.info(f"Loaded processed incident IDs: {len(processed_ids)} IDs")

    return last_timestamp, processed_ids

def save_last_processed_data(timestamp_file, incident_ids_file, last_timestamp, processed_ids):
    with open(timestamp_file, 'w') as file:
        file.write(last_timestamp)
    logging.info(f"Saved last timestamp: {last_timestamp}")
    with open(incident_ids_file, 'w') as file:
        json.dump(list(processed_ids), file)
    logging.info(f"Saved processed incident IDs: {len(processed_ids)} IDs")

def main():
    logging.info("Starting script...")
    last_timestamp, processed_ids = load_last_processed_data(LAST_TIMESTAMP_FILE, LAST_INCIDENT_IDS_FILE)
    filename = 'crowdstrike_incidents.jsonl'

    while True:
        try:
            token = get_oauth2_token()
            ids_response = get_incident_ids(token, last_timestamp)
            incident_ids = ids_response.get('resources', [])

            incident_ids = [id for id in incident_ids if id not in processed_ids]

            if incident_ids:
                details_response = get_incident_details(token, incident_ids)
                incidents = details_response.get('resources', [])
                if incidents:
                    flattened_incidents = flatten_incidents(incidents)
                    write_incidents_to_jsonl(flattened_incidents, filename)
                    for incident in incidents:
                        processed_ids.add(incident['incident_id'])
                    last_timestamp = max(i['modified_timestamp'] for i in incidents)
                    save_last_processed_data(LAST_TIMESTAMP_FILE, LAST_INCIDENT_IDS_FILE, last_timestamp, processed_ids)
                else:
                    logging.info("No incident details found.")
            else:
                logging.info("No new incidents found.")

            time.sleep(30)

        except requests.exceptions.HTTPError as e:
            logging.error(f"HTTPError encountered: {e}")
            logging.error(f"Response content: {getattr(e.response, 'content', None)}")
            if getattr(e.response, 'status_code', None) == 429:
                logging.warning("Rate limit exceeded. Sleeping for a while...")
                time.sleep(60)
            else:
                raise
        except Exception as e:
            logging.error(f"An error occurred: {e}")
            raise

if __name__ == '__main__':
    main()

```

### `systemd` unit files for both services

#### /etc/systemd/system/Crowdstrike.service (Detections)

```bash
[Unit]
Description=CrowdStrike → Wazuh Detections Pipeline
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/user/Crowdstrike_integration/
EnvironmentFile=/etc/crowdstrike.env
ExecStart=/usr/bin/python3 /home/user/Crowdstrike_integration/detections.py
Restart=always
RestartSec=5

# (optional hardening; keep if paths match your setup)
NoNewPrivileges=true
ProtectSystem=full
ReadWritePaths=/home/user/Crowdstrike_integration/
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

#### /etc/systemd/system/Crowdstrike_incidents.service (Incidents)

```bash
[Unit]
Description=CrowdStrike → Wazuh Incidents Pipeline
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/user/Crowdstrike_integration/
EnvironmentFile=/etc/crowdstrike.env
ExecStart=/usr/bin/python3 /home/user/Crowdstrike_integration/incidents.py
Restart=always
RestartSec=5

# (optional hardening; keep if paths match your setup)
NoNewPrivileges=true
ProtectSystem=full
ReadWritePaths=/home/user/Crowdstrike_integration/
PrivateTmp=true

[Install]
WantedBy=multi-user.target

```

* Wazuh rules: `/var/ossec/etc/rules/crowdstrike.xml`

```xml

<!-- Crowstrike rules -->

<group name="crowdstrike,">
<rule id="222296" level="0">
<field name="device.platform_id">\.+</field>
<description>Crowdstrike detection!</description>
</rule>


<rule id="222303" level="0">
<field name="crowdstrike.device_id">\.+</field>
<description>Crowdstrike detection!</description>
</rule>

<!-- Detection -->

    <!-- Critical Severity -->
    <rule id="222297" level="15">
      <if_sid>222296</if_sid>
      <field name="severity" type="pcre2">^([8-9][0-9]|100)$</field>
      <description>Crowdstrike Critical Alert - $(description)</description>
    </rule>

    <!-- High Severity -->
    <rule id="222298" level="11">
      <if_sid>222296</if_sid>
      <field name="severity" type="pcre2">^(6[0-9]|70)$</field>
      <description>Crowdstrike High Alert - $(description)</description>
    </rule>

    <!-- Medium Severity -->
    <rule id="222299" level="9">
      <if_sid>222296</if_sid>
      <field name="severity" type="pcre2">^(4[0-9]|50)$</field>
      <description>Crowdstrike Medium Alert - $(description)</description>
    </rule>

    <!-- Low Severity -->
    <rule id="222300" level="5">
      <if_sid>222296</if_sid>
      <field name="severity" type="pcre2">^(2[0-9]|30)$</field>
      <description>Crowdstrike Low Alert - $(description)</description>
    </rule>

    <!-- Informational Severity -->
    <rule id="222301" level="3">
      <if_sid>222296</if_sid>
      <field name="severity" type="pcre2">^10$</field>
      <description>Crowdstrike Informational Alert - $(description)</description>
    </rule>

<!-- Incident rules -->

<!-- Critical Severity -->
<rule id="222304" level="15">
  <if_sid>222303</if_sid>
  <field name="crowdstrike.fine_score" type="pcre2">^(8[0-9]|9[0-9]|100)$</field>
  <description>Crowdstrike Critical Incident - $(crowdstrike.techniques)</description>
</rule>

<!-- High Severity -->
<rule id="222305" level="15">
  <if_sid>222303</if_sid>
  <field name="crowdstrike.fine_score" type="pcre2">^(6[0-9]|7[0-9])$</field>
  <description>Crowdstrike High Incident - $(crowdstrike.techniques)</description>
</rule>

<!-- Medium Severity -->
<rule id="222306" level="15">
  <if_sid>222303</if_sid>
  <field name="crowdstrike.fine_score" type="pcre2">^(4[0-9]|5[0-9])$</field>
  <description>Crowdstrike Medium Incident - $(crowdstrike.techniques)</description>
</rule>

<!-- Low Severity -->
<rule id="222307" level="10">
  <if_sid>222303</if_sid>
  <field name="crowdstrike.fine_score" type="pcre2">^(2[0-9]|3[0-9])$</field>
  <description>Crowdstrike Low Incident - $(crowdstrike.techniques)</description>
</rule>

<!-- Informational Severity -->
<rule id="222308" level="5">
  <if_sid>222303</if_sid>
  <field name="crowdstrike.fine_score" type="pcre2">^(0|1[0-9])$</field>
  <description>Crowdstrike Informational Incident - $(crowdstrike.techniques)</description>
</rule>




</group>
```



