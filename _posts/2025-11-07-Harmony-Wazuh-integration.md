# Check Point Harmony → Wazuh/OpenSearch with a Cron-Driven Collector

*As told by someone who has almost certainly misplaced their towel.*
*Nov 7, 2025*

In a universe bristling with daemons, containers, and elaborate message buses that insist they’re “simple,” I built a tiny Python collector that quietly ferries **Check Point Harmony** security events into **Wazuh/OpenSearch**. No orchestral overture. No service mesh. No drama. Just one script, summoned by **cron every five minutes**, emitting **NDJSON** that Wazuh inhales natively like it’s been doing it all its life.

The guiding principle here was production sanity: secrets stay out of code, re-runs are **idempotent** (a word which here means “it won’t panic and duplicate everything”), and the pipeline is as brittle as a rubber duck. If the machine reboots or a run face-plants, the next cron tick strolls in and carries on from the last known good moment, as if nothing untoward ever happened.

---

## How it works (in language your future self won’t hate)

Each run performs four dignified acts:

1. **Authenticate** to the Check Point Cloud using credentials sourced from environment variables. Nothing hardcoded. Nothing that will embarrass you in a code review.
2. **Query events** newer than the last saved timestamp, following `scrollId` pagination until the well goes dry (or reality ends, whichever comes first).
3. **Write outputs** as **NDJSON** to `/var/ossec/events_YYYY-MM-DD.jsonl`, one immaculate JSON object per line. (Optional: a syslog-ish line for those who prefer to tail their destiny.)
4. **Advance state** by saving the latest `eventCreated` watermark and appending any **new** `eventId`s to a tidy little text file with a very small ego and a simple rotation.

Because every run reuses the watermark and a set of seen IDs, you can call the script as often as you like without duplicating events—even if you are feeling particularly enthusiastic with cron.

---

## Credentials: environment variables, not archaeological layers of secrets

The script doesn’t hardcode secrets because we are civilized. It expects:

```bash
# /etc/harmony.env  (chmod 600; owned by root)
export CHECKPOINT_HARMONY_CLIENT_ID="xxxx-xxxxx-xxxx"
export CHECKPOINT_HARMONY_ACCESS_KEY="yyyy-yyyyy-yyyy"
```

Cron, being the minimalist ascetic that it is, does not load your shell environment. So we use a **wrapper** that politely sources the env file and then runs Python:

```bash
# /usr/local/sbin/run-harmony.sh
#!/usr/bin/env bash
set -euo pipefail
source /etc/harmony.env
/usr/bin/python3 /opt/harmony-collector/harmony_collector.py >>/var/log/harmony_cron.log 2>&1
```

Then, in root’s crontab (or a suitably privileged service account):

```cron
*/5 * * * * /usr/local/sbin/run-harmony.sh
```

And that’s the whole security opera: one file for secrets, one wrapper, one script. No choruses.

> Tip: If you prefer a vault, have your agent render `/etc/harmony.env` at boot and keep it `600` with root ownership. Your auditor will smile, which is rare and therefore valuable.

---

## Wazuh ingestion (no middleware, no fuss)

Because NDJSON is line-oriented and each line is perfectly valid JSON, the Wazuh Manager can parse it directly. Add a `<localfile>` to `ossec.conf` like so:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/ossec/events_*.jsonl</location>
</localfile>
```
*(Footnote for the cautious:)* Wazuh is delightfully unbothered by unfamiliar JSON fields. If Check Point decides tomorrow that “saas” should actually be “cloudThingy,” Wazuh will simply shrug, index it, and carry on. It’s that rare parser that doesn’t panic at the sight of novelty.

Each new line becomes a document in OpenSearch. Query by `data.eventId`, `data.severity`, or go full cosmological taxonomy with `data.saas.keyword:"Exchange"`.

---

## Operational notes (a small field guide)

* **State files** live under `/var/ossec/logs/`:

  * `last_alert_timestamp.txt` — the watermark for the next expedition.
  * `processed_event_ids.txt` — one `eventId` per line; rotated before it grows a memoir.
* **Logging** goes to `/var/ossec/logs/harmony_api_log.log` and the wrapper’s `/var/log/harmony_cron.log`. Enough breadcrumbs to retrace your steps without feeding any ducks.
* **Permissions**: run via root or a dedicated account that can write to `/var/ossec/`. Otherwise you will experience the unique joy of “Permission denied” at 03:00.
* **Failure behavior**: HTTP errors raise and log. The watermark + ID-set design means the next tick retries safely without duplicating existential crises or events.

If you ever find yourself debugging at 03:00 again, know that you are not alone, there are countless other beings across the galaxy doing exactly the same thing, all of them wondering why they didn’t choose to be poets instead.

---

## Roadmap (nice-to-haves that would impress my future self)

* Respect API rate-limit headers with dynamic backoff (the polite thing to do).
* Switch to a single `requests.Session()` with timeouts and retries (fewer TCP handshakes, more tea).
* Optional enrichment (tenant/owner) before writing (because context is delightful).
* Emit a tiny health line each run (status, batch size, watermark) for external monitoring; observability is not a luxury, it’s life support.

---

## Appendix A — Full script (env-ready, mercifully small)

```python
#!/usr/bin/env python3
import requests
import json
import datetime
import logging
import uuid
from datetime import timedelta
import os
from datetime import timezone  # Adjusted import for direct access to datetime and timezone

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logging.basicConfig(
    filename='/var/ossec/logs/harmony_api_log.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)

logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# Simple rotation for the processed IDs file
# -----------------------------------------------------------------------------
def rotate_event_id_file(filename='/var/ossec/logs/processed_event_ids.txt', max_size=32 * 1024, backup_count=3):
    """
    Rotate the event ID file if it exceeds the specified size.
    :param filename: The name of the file to rotate.
    :param max_size: The maximum file size in bytes before rotating.
    :param backup_count: The number of backup files to keep.
    """
    if os.path.exists(filename) and os.path.getsize(filename) > max_size:
        for i in range(backup_count - 1, 0, -1):
            src = f"{filename}.{i}"
            dst = f"{filename}.{i + 1}"
            if os.path.exists(src):
                os.rename(src, dst)
        os.rename(filename, f"{filename}.1")
        logger.info("Log file successfully rotated")

# -----------------------------------------------------------------------------
# Auth
# -----------------------------------------------------------------------------
def get_access_token(client_id, access_key):
    logger.debug("Attempting to get access token for Check Point Cloud")
    try:
        url = 'https://cloudinfra-gw.portal.checkpoint.com/auth/external'
        headers = {'Content-Type': 'application/json'}
        payload = {'clientId': client_id, 'accessKey': access_key}
        response = requests.post(url, headers=headers, data=json.dumps(payload), timeout=60)
        response.raise_for_status()
        token = response.json()['data']['token']
        logger.info("Successfully obtained access token.")
        return token
    except Exception as e:
        logger.error(f"Error obtaining access token: {e}", exc_info=True)
        raise

# -----------------------------------------------------------------------------
# State (timestamp watermark)
# -----------------------------------------------------------------------------
def store_last_retrieved_alert_timestamp(timestamp):
    logger.debug(f"Storing last retrieved alert timestamp: {timestamp}")
    try:
        with open('/var/ossec/logs/last_alert_timestamp.txt', 'w') as file:
            file.write(timestamp.isoformat())
        logger.info("Last retrieved alert timestamp stored successfully.")
    except Exception as e:
        logger.error(f"Error storing last retrieved alert timestamp: {e}", exc_info=True)
        raise

def get_last_retrieved_alert_timestamp():
    logger.debug("Retrieving last alert timestamp.")
    try:
        with open('/var/ossec/logs/last_alert_timestamp.txt', 'r') as file:
            timestamp = datetime.datetime.fromisoformat(file.read().strip())
        logger.info(f"Last retrieved alert timestamp: {timestamp}")
        return timestamp
    except FileNotFoundError:
        default_timestamp = datetime.datetime.utcnow() - timedelta(minutes=5)
        logger.warning(f"last_alert_timestamp.txt not found. Using default timestamp: {default_timestamp}")
        return default_timestamp
    except Exception as e:
        logger.error(f"Error retrieving last alert timestamp: {e}", exc_info=True)
        raise

# -----------------------------------------------------------------------------
# Fetch events
# -----------------------------------------------------------------------------
def fetch_security_event_logs(access_token):
    logger.debug("Fetching security event logs.")
    try:
        latest_timestamp = get_last_retrieved_alert_timestamp()
        formatted_start_time = latest_timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        logger.info(f"Fetching logs starting from: {formatted_start_time}")

        url = 'https://cloudinfra-gw.portal.checkpoint.com/app/hec-api/v1.0/event/query'
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json',
            'x-av-req-id': str(uuid.uuid4())
        }
        payload = {'requestData': {'startDate': formatted_start_time}}

        all_responses = []
        while True:
            response = requests.post(url, headers=headers, data=json.dumps(payload), timeout=120)
            response.raise_for_status()
            data = response.json()

            all_responses.append(data)

            if not data.get('responseData') or (data.get('responseEnvelope', {}) or {}).get('scrollId') is None:
                logger.debug("No more data to fetch or scrollId is None.")
                break

            payload['requestData']['scrollId'] = data['responseEnvelope']['scrollId']

        latest_alert_timestamp = datetime.datetime.min.replace(tzinfo=timezone.utc)
        logger.info(f"latest alert timestamp (init): {latest_alert_timestamp}")

        for response in all_responses:
            for alert in response.get('responseData', []):
                event_created_str = alert.get('eventCreated')
                if not event_created_str:
                    continue
                try:
                    event_created = datetime.datetime.strptime(event_created_str, '%Y-%m-%dT%H:%M:%S.%f%z')
                except ValueError:
                    event_created = datetime.datetime.strptime(event_created_str, '%Y-%m-%dT%H:%M:%S%z')

                if event_created > latest_alert_timestamp:
                    latest_alert_timestamp = event_created

        if latest_alert_timestamp > datetime.datetime.min.replace(tzinfo=timezone.utc):
            store_last_retrieved_alert_timestamp(latest_alert_timestamp)
            logger.info(f"Updated last retrieved alert timestamp: {latest_alert_timestamp}")
        else:
            logger.info("No new alerts found to update the timestamp.")

        return all_responses
    except Exception as e:
        logger.error(f"Error fetching security event logs: {e}", exc_info=True)
        raise

# -----------------------------------------------------------------------------
# Output writers
# -----------------------------------------------------------------------------
def json_to_syslog(json_data):
    logger.info("Starting to store syslog data.")
    syslog_output = []
    global processed_event_ids  # Ensure this variable is defined in the global scope

    if not json_data:
        logger.debug("No JSON data provided to the function.")
        return syslog_output

    logger.debug(f"Currently known processed_event_ids: {processed_event_ids}")

    for response in json_data:
        if 'responseData' not in response:
            logger.debug("Missing 'responseData' in one of the responses.")
            continue

        for event in response['responseData']:
            event_id = event.get('eventId')
            if not event_id:
                logger.debug("Event ID not found in event.")
                continue

            if event_id in processed_event_ids:
                logger.debug(f"Event ID {event_id} already processed. Skipping.")
                continue

            logger.debug(f"Processing new event ID: {event_id}")
            processed_event_ids.add(event_id)
            store_processed_event_id(event_id)

            try:
                timestamp = datetime.datetime.strptime(event['eventCreated'], '%Y-%m-%dT%H:%M:%S.%f%z').strftime('%b %d %H:%M:%S')
                log_message = (
                    f"{timestamp} "
                    f"EventId: {event.get('eventId', 'N/A')} "
                    f"CustomerId: {event.get('customerId', 'N/A')} "
                    f"Saas: {event.get('saas', 'N/A')} "
                    f"EntityId: {event.get('entityId', 'N/A')} "
                    f"State: {event.get('state', 'N/A')} "
                    f"Type: {event.get('type', 'N/A')} "
                    f"ConfidenceIndicator: {event.get('confidenceIndicator', 'N/A')} "
                    f"Severity: {event.get('severity', 'N/A')} "
                    f"Description: {event.get('description', 'N/A')} "
                    f"Data: {event.get('data', 'N/A')} "
                    f"Actions: {event.get('actions', 'N/A')} "
                    f"SenderAddress: {event.get('senderAddress', 'N/A')} "
                    f"EntityLink: {event.get('entityLink', 'N/A')}"
                )
                syslog_output.append(log_message)
                logger.debug(f"Processed and stored syslog message for event ID: {event_id}")
            except KeyError as e:
                logger.warning(f"Missing field in event data: {e}. Event ID: {event_id}")
            except Exception as e:
                logger.error(f"Error processing event data for event ID: {event_id}: {e}")

    logger.info("Completed storing syslog data.")
    return syslog_output

def write_syslog_to_file(syslog_messages, filename='/var/ossec/logs/syslog_output.log'):
    with open(filename, 'a') as file:
        for message in syslog_messages:
            file.write(message + '\n')
            logging.info(f"Syslog entry written to file: {message}")

def json_to_jsonl(json_data):
    """Append JSON data to a JSONL file, creating a new file each day."""
    date_str = datetime.datetime.now().strftime("%Y-%m-%d")
    filename = f'/var/ossec/events_{date_str}.jsonl'
    global processed_event_ids
    for response in json_data:
        for event in response.get('responseData', []):
            event_id = event.get('eventId')
            if event_id and event_id not in processed_event_ids:
                with open(filename, 'a') as file:
                    json.dump(event, file)
                    file.write('\n')
                processed_event_ids.add(event_id)
                store_processed_event_id(event_id)

# -----------------------------------------------------------------------------
# Processed IDs helpers
# -----------------------------------------------------------------------------
def read_processed_event_ids(filename='/var/ossec/logs/processed_event_ids.txt'):
    logger.info("Reading processed event IDs")
    try:
        with open(filename, 'r') as file:
            return set(file.read().splitlines())
    except FileNotFoundError:
        return set()

def store_processed_event_id(event_id, filename='/var/ossec/logs/processed_event_ids.txt'):
    logger.info("Storing processed event IDs")
    with open(filename, 'a') as file:
        file.write(event_id + '\n')

# -----------------------------------------------------------------------------
# Main (cron-friendly)
# -----------------------------------------------------------------------------
if __name__ == '__main__':
    logger.info("Script execution started.")
    processed_event_ids = read_processed_event_ids()
    rotate_event_id_file()  # Check and rotate if necessary

    # Read credentials from environment (fail fast if missing)
    CLIENT_ID = os.environ.get('CHECKPOINT_HARMONY_CLIENT_ID')
    ACCESS_KEY = os.environ.get('CHECKPOINT_HARMONY_ACCESS_KEY')
    if not CLIENT_ID or not ACCESS_KEY:
        logger.error("Missing CHECKPOINT_HARMONY_CLIENT_ID or CHECKPOINT_HARMONY_ACCESS_KEY environment variables.")
        raise SystemExit(1)

    try:
        access_token = get_access_token(CLIENT_ID, ACCESS_KEY)
        security_events = fetch_security_event_logs(access_token)

        # Primary output: NDJSON
        json_to_jsonl(security_events)

        # Optional secondary: syslog-style (uncomment to enable)
        # syslog_lines = json_to_syslog(security_events)
        # write_syslog_to_file(syslog_lines)

    except Exception as e:
        logger.error(f"Error in main execution: {e}", exc_info=True)
        raise
    finally:
        logger.info("Script execution completed.")
```

---

## Appendix B — Paths and wrappers (copy-paste, no rituals required)

**Directory layout**

```
/opt/harmony-collector/
  harmony_collector.py
/usr/local/sbin/run-harmony.sh
/etc/harmony.env
```

**Wrapper** `/usr/local/sbin/run-harmony.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail
source /etc/harmony.env
/usr/bin/python3 /opt/harmony-collector/harmony_collector.py >>/var/log/harmony_cron.log 2>&1
```

**Crontab**

```cron
*/5 * * * * /usr/local/sbin/run-harmony.sh
```

**Wazuh** (Manager)

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/ossec/events_*.jsonl</location>
</localfile>
```

That’s the whole arrangement: cron calls the collector, the collector writes NDJSON, and Wazuh faithfully ushers it into OpenSearch. Clean, predictable, and restart-proof. Mostly harmless.

At this point, if nothing has exploded, you may consider yourself improbably lucky. The universe, of course, disapproves of such things, so do keep a towel near `/etc/harmony.env` and an eye on your logs. And remember: in the grand tradition of systems engineering, improbability is just another word for uptime.
