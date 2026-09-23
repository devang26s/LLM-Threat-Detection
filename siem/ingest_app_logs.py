import json
from pathlib import Path
from elasticsearch import Elasticsearch, helpers

ES_URL = "http://localhost:9200"
INDEX = "llm-app-logs"
LOG = Path(__file__).resolve().parent.parent / "logs" / "app.jsonl"

es = Elasticsearch(ES_URL)

def actions():
    if not LOG.exists():
        print(f"No log file at {LOG}"); return
    with open(LOG) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                doc = json.loads(line)
            except json.JSONDecodeError:
                continue
            yield {"_index": INDEX, "_id": doc.get("request_id"), "_source": doc}

ok, errs = helpers.bulk(es, actions(), raise_on_error=False)
print("indexed:", ok, "errors:", len(errs) if isinstance(errs, list) else errs)
