import gzip, json, glob, os, subprocess, sys
from pathlib import Path
from elasticsearch import Elasticsearch, helpers

ES_URL = "http://localhost:9200"
INDEX = "cloudtrail-logs"
RAW = Path(__file__).resolve().parent / "cloudtrail_raw"

bucket = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("CT_BUCKET")
if not bucket:
    sys.exit("Usage: python ingest_cloudtrail.py <cloudtrail-bucket-name>")

RAW.mkdir(exist_ok=True)
print("Syncing CloudTrail logs from s3://%s ..." % bucket)
subprocess.run(["aws", "s3", "sync", f"s3://{bucket}/AWSLogs/", str(RAW)], check=True)

# longer timeout + retries so a slow bulk batch doesn't abort the run
es = Elasticsearch(ES_URL, request_timeout=60, retry_on_timeout=True, max_retries=3)

def actions():
    for fp in glob.glob(str(RAW / "**" / "*.json.gz"), recursive=True):
        with gzip.open(fp, "rt") as f:
            data = json.load(f)
        for rec in data.get("Records", []):
            ui = rec.get("userIdentity", {})
            doc = {
                "eventTime": rec.get("eventTime"),
                "eventName": rec.get("eventName"),
                "eventSource": rec.get("eventSource"),
                "awsRegion": rec.get("awsRegion"),
                "sourceIPAddress": rec.get("sourceIPAddress"),
                "userName": ui.get("userName") or ui.get("type"),
                "userArn": ui.get("arn"),
                "userType": ui.get("type"),
                "readOnly": rec.get("readOnly"),
                "raw": rec,
            }
            yield {"_index": INDEX, "_id": rec.get("eventID"), "_source": doc}

# smaller chunks so ES on a 1GB heap keeps up
ok, errs = helpers.bulk(es, actions(), chunk_size=200, request_timeout=60, raise_on_error=False)
print("indexed:", ok, "errors:", len(errs) if isinstance(errs, list) else errs)
