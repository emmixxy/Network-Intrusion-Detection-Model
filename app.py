"""
Real-time intrusion detection console.

Wraps a scikit-learn Pipeline (SimpleImputer -> RandomForestClassifier) trained on
CICFlowMeter flow features and serves it three ways:

  POST /api/score    synchronous scoring, for integrations
  POST /api/flows    fire-and-forget ingest, for live sensors
  GET  /api/stream   server-sent events feed of every scored flow

Run:  python app.py
"""

from __future__ import annotations

import json
import os
import queue
import re
import threading
import time
from collections import deque
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from flask import Flask, Response, jsonify, render_template, request

# --------------------------------------------------------------------------- config

MODEL_PATH = os.environ.get("MODEL_PATH", "network_intrusion_detection_model.pkl")
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", 8000))
DEFAULT_THRESHOLD = float(os.environ.get("THRESHOLD", 0.5))

BATCH_WINDOW_S = 0.05   # how long the scorer waits to gather a micro-batch
BATCH_MAX = 512         # flows per predict_proba call
LEDGER_SIZE = 400       # scored flows kept in memory for late-joining browsers
QUEUE_MAX = 20000       # backpressure bound on the ingest queue

# --------------------------------------------------------------------------- model

print(f"Loading model from {MODEL_PATH} ...")
_t0 = time.time()
MODEL = joblib.load(MODEL_PATH)
FEATURES: list[str] = list(MODEL.steps[0][1].feature_names_in_)
MEDIANS = dict(zip(FEATURES, MODEL.steps[0][1].statistics_))
CLASSIFIER = MODEL.steps[-1][1]
IMPORTANCE = dict(zip(FEATURES, CLASSIFIER.feature_importances_))
ATTACK_COL = list(CLASSIFIER.classes_).index(1)
print(f"Loaded in {time.time() - _t0:.1f}s - {len(FEATURES)} features, "
      f"{len(CLASSIFIER.estimators_)} trees")

# Header spellings drift between CICFlowMeter builds ("Fwd Packets/s",
# "fwd_packets_s", "Total Length of Fwd Packets"). Normalise once, match loosely.
def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(name).lower())

ALIASES = {_norm(f): f for f in FEATURES}
ALIASES.update({
    _norm("Total Length of Fwd Packets"): "Fwd Packets Length Total",
    _norm("Total Length of Bwd Packets"): "Bwd Packets Length Total",
    _norm("Min Packet Length"): "Packet Length Min",
    _norm("Max Packet Length"): "Packet Length Max",
    _norm("Average Packet Size"): "Avg Packet Size",
    _norm("Init_Win_bytes_forward"): "Init Fwd Win Bytes",
    _norm("Init_Win_bytes_backward"): "Init Bwd Win Bytes",
    _norm("act_data_pkt_fwd"): "Fwd Act Data Packets",
    _norm("min_seg_size_forward"): "Fwd Seg Size Min",
    _norm("CWR Flag Count"): "CWE Flag Count",
    _norm("Fwd Header Length.1"): "Fwd Header Length",
})

META_KEYS = ("flow_id", "src_ip", "src_port", "dst_ip", "dst_port",
             "protocol_name", "timestamp", "label", "source")

# Anything the imputer can't use must arrive as NaN, not a string or an inf.
def to_number(value) -> float:
    try:
        f = float(value)
    except (TypeError, ValueError):
        return np.nan
    return f if np.isfinite(f) else np.nan


def split_flow(raw: dict) -> tuple[dict, dict]:
    """Separate model features from passthrough metadata."""
    feats: dict[str, float] = {}
    meta: dict[str, object] = {}
    for key, value in raw.items():
        canonical = ALIASES.get(_norm(key))
        if canonical is not None:
            feats[canonical] = to_number(value)
        elif key.lower() in META_KEYS:
            meta[key.lower()] = value
    return feats, meta


def parse_payload(body) -> list[tuple[dict, dict]]:
    """Accept one flow, a list of flows, {'flows': [...]}, or a bare 77-vector."""
    if isinstance(body, dict) and "flows" in body:
        body = body["flows"]
    if isinstance(body, dict):
        body = [body]
    if not isinstance(body, list):
        raise ValueError("expected an object or a list of objects")

    parsed = []
    for item in body:
        if isinstance(item, list):
            if len(item) != len(FEATURES):
                raise ValueError(
                    f"vector has {len(item)} values, model expects {len(FEATURES)}")
            parsed.append((dict(zip(FEATURES, (to_number(v) for v in item))), {}))
        elif isinstance(item, dict):
            feats, meta = split_flow(item)
            if not feats:
                raise ValueError("no recognised feature names in flow")
            parsed.append((feats, meta))
        else:
            raise ValueError("flow entries must be objects or numeric arrays")

    # Stamp arrival here rather than at scoring time: a micro-batch is scored in
    # one call, so a batch-level timestamp would flatten every flow in it to the
    # same instant.
    arrived = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    for _, meta in parsed:
        meta.setdefault("received_at", arrived)
    return parsed


def score(batch: list[tuple[dict, dict]]) -> list[dict]:
    """Score a batch of (features, metadata) pairs in one pass."""
    frame = pd.DataFrame([f for f, _ in batch], columns=FEATURES)
    probs = MODEL.predict_proba(frame)[:, ATTACK_COL]
    now = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    threshold = STATE.threshold

    results = []
    for (feats, meta), p in zip(batch, probs):
        p = float(p)
        results.append({
            "id": meta.get("flow_id") or f"{time.time_ns():x}",
            "scored_at": meta.pop("received_at", now),
            "observed_at": meta.get("timestamp"),
            "attack_probability": round(p, 4),
            "verdict": "attack" if p >= threshold else "benign",
            "threshold": threshold,
            "confidence": round(abs(p - threshold) / max(threshold, 1 - threshold), 3),
            "features_supplied": len(feats),
            "meta": meta,
            "drivers": drivers(feats, top=5),
        })
    return results


def drivers(feats: dict, top: int = 5) -> list[dict]:
    """
    Cheap per-flow context: the influential features this flow departs from most.

    Ranked by (global tree importance x deviation from the training-set median the
    imputer stored). It explains which inputs pushed the verdict, but it is a
    heuristic, not a SHAP attribution -- do not present it as one.
    """
    scored = []
    for name, value in feats.items():
        if value is None or not np.isfinite(value):
            continue
        median = float(MEDIANS.get(name, 0.0))
        scale = max(abs(median), 1.0)
        deviation = abs(value - median) / scale
        weight = IMPORTANCE.get(name, 0.0) * min(deviation, 20.0)
        if weight > 0:
            scored.append({
                "feature": name,
                "value": round(float(value), 4),
                "training_median": round(median, 4),
                "weight": round(float(weight), 5),
            })
    scored.sort(key=lambda d: -d["weight"])
    return scored[:top]

# --------------------------------------------------------------------------- state


class Console:
    """Shared runtime state: ingest queue, subscribers, ledger, counters."""

    def __init__(self) -> None:
        self.threshold = DEFAULT_THRESHOLD
        self.ingest: queue.Queue = queue.Queue(maxsize=QUEUE_MAX)
        self.ledger: deque = deque(maxlen=LEDGER_SIZE)
        self.subscribers: set[queue.Queue] = set()
        self.lock = threading.Lock()
        self.started = time.time()
        self.counts = {"scored": 0, "attacks": 0, "dropped": 0}

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=1000)
        with self.lock:
            self.subscribers.add(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self.lock:
            self.subscribers.discard(q)

    def publish(self, results: list[dict]) -> None:
        with self.lock:
            for r in results:
                self.ledger.append(r)
                self.counts["scored"] += 1
                if r["verdict"] == "attack":
                    self.counts["attacks"] += 1
            targets = list(self.subscribers)
        payload = json.dumps({"type": "flows", "flows": results})
        for q in targets:
            try:
                q.put_nowait(payload)
            except queue.Full:
                pass  # a stalled browser must never slow the scorer

    def snapshot(self) -> dict:
        with self.lock:
            recent = list(self.ledger)[-120:]
            counts = dict(self.counts)
        window = [r for r in recent
                  if time.time() - _epoch(r["scored_at"]) < 60]
        return {
            "uptime_s": round(time.time() - self.started, 1),
            "threshold": self.threshold,
            "queue_depth": self.ingest.qsize(),
            "subscribers": len(self.subscribers),
            "flows_per_minute": len(window),
            **counts,
        }


def _epoch(iso: str) -> float:
    try:
        return datetime.fromisoformat(iso).timestamp()
    except ValueError:
        return 0.0


STATE = Console()


def scoring_worker() -> None:
    """Drain the ingest queue in micro-batches; one predict_proba per batch."""
    while True:
        batch = [STATE.ingest.get()]
        deadline = time.time() + BATCH_WINDOW_S
        while len(batch) < BATCH_MAX:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            try:
                batch.append(STATE.ingest.get(timeout=remaining))
            except queue.Empty:
                break
        try:
            STATE.publish(score(batch))
        except Exception as exc:  # a malformed batch must not kill the worker
            print(f"scoring error on {len(batch)} flows: {exc}")


threading.Thread(target=scoring_worker, daemon=True, name="scorer").start()

# --------------------------------------------------------------------------- routes

app = Flask(__name__)


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/meta")
def meta():
    ranked = sorted(IMPORTANCE.items(), key=lambda kv: -kv[1])
    return jsonify({
        "model": os.path.basename(MODEL_PATH),
        "estimator": type(CLASSIFIER).__name__,
        "trees": len(getattr(CLASSIFIER, "estimators_", [])),
        "classes": {"0": "benign", "1": "attack"},
        "threshold": STATE.threshold,
        "feature_count": len(FEATURES),
        "features": FEATURES,
        "top_features": [{"feature": f, "importance": round(float(i), 5)}
                         for f, i in ranked[:15]],
    })


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", **STATE.snapshot()})


@app.get("/api/stats")
def stats():
    return jsonify(STATE.snapshot())


@app.get("/api/ledger")
def ledger():
    limit = min(int(request.args.get("limit", 100)), LEDGER_SIZE)
    return jsonify({"flows": list(STATE.ledger)[-limit:]})


@app.post("/api/score")
def score_sync():
    """Score now and return verdicts in the response. Use this from other services."""
    try:
        batch = parse_payload(request.get_json(force=True))
    except (ValueError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400

    started = time.perf_counter()
    results = score(batch)
    STATE.publish(results)
    return jsonify({
        "count": len(results),
        "latency_ms": round((time.perf_counter() - started) * 1000, 2),
        "results": results,
    })


@app.post("/api/flows")
def ingest():
    """Queue flows for the live console. Returns immediately; sensors use this."""
    try:
        batch = parse_payload(request.get_json(force=True))
    except (ValueError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400

    accepted = 0
    for item in batch:
        try:
            STATE.ingest.put_nowait(item)
            accepted += 1
        except queue.Full:
            STATE.counts["dropped"] += 1
    status = 202 if accepted == len(batch) else 429
    return jsonify({"accepted": accepted,
                    "dropped": len(batch) - accepted,
                    "queue_depth": STATE.ingest.qsize()}), status


@app.post("/api/threshold")
def set_threshold():
    body = request.get_json(force=True) or {}
    try:
        value = float(body.get("threshold"))
    except (TypeError, ValueError):
        return jsonify({"error": "threshold must be a number"}), 400
    if not 0.0 <= value <= 1.0:
        return jsonify({"error": "threshold must be between 0 and 1"}), 400
    STATE.threshold = round(value, 3)
    return jsonify({"threshold": STATE.threshold})


@app.get("/api/stream")
def stream():
    def events():
        q = STATE.subscribe()
        try:
            yield f"data: {json.dumps({'type': 'hello', 'stats': STATE.snapshot()})}\n\n"
            backlog = list(STATE.ledger)[-60:]
            if backlog:
                yield f"data: {json.dumps({'type': 'flows', 'flows': backlog})}\n\n"
            last_stats = 0.0
            while True:
                try:
                    yield f"data: {q.get(timeout=1.0)}\n\n"
                except queue.Empty:
                    yield ": keepalive\n\n"
                if time.time() - last_stats > 2:
                    last_stats = time.time()
                    yield f"data: {json.dumps({'type': 'stats', 'stats': STATE.snapshot()})}\n\n"
        finally:
            STATE.unsubscribe(q)

    return Response(events(), mimetype="text/event-stream", headers={
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
        "Connection": "keep-alive",
    })


if __name__ == "__main__":
    # Warm the trees so the first real flow isn't the slow one.
    MODEL.predict_proba(pd.DataFrame(np.zeros((1, len(FEATURES))), columns=FEATURES))
    print(f"Console on http://{HOST}:{PORT}")
    app.run(host=HOST, port=PORT, threaded=True, debug=False)
