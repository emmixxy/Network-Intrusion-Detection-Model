# Flow monitor

A real-time web console for the network intrusion detection model in
`network_intrusion_detection_model.pkl`.

The model is a scikit-learn `Pipeline`: a median `SimpleImputer` feeding a
`RandomForestClassifier` with 150 trees, over 77 CICFlowMeter flow features,
predicting benign (0) against attack (1).

The console serves that model three ways:

| Route | Shape | Use |
|---|---|---|
| `POST /api/score` | request/response | scoring from another service |
| `POST /api/flows` | fire-and-forget | sensors pushing live flows |
| `GET /api/stream` | server-sent events | the dashboard, and anything else watching |

---

## Setup

The version pin matters. The pipeline was pickled under scikit-learn 1.5.1, and
on 1.8 it loads without complaint and then throws `AttributeError: 'SimpleImputer'
object has no attribute '_fill_dtype'` the first time you score anything. Install
from `requirements.txt` rather than into an existing environment.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# put the pickle next to app.py, or point MODEL_PATH at it
cp /path/to/network_intrusion_detection_model.pkl .

python app.py
```

Open http://127.0.0.1:8000. The strip across the top stays empty until something
feeds it, so in a second terminal:

```bash
python sensor.py demo --rate 30
```

Environment variables: `MODEL_PATH`, `HOST`, `PORT`, `THRESHOLD`.

---

## Feeding it real traffic

`sensor.py` has three modes. Only the third is a deployment.

```bash
python sensor.py demo --rate 30 --attack-ratio 0.15   # synthetic, no capture needed
python sensor.py replay flows.csv --rate 40 --loop    # an existing CICFlowMeter CSV
python sensor.py follow /var/log/cicflowmeter/live.csv # tail a file being written now
```

For `follow`, point CICFlowMeter (or any tool emitting per-flow features) at an
interface and have it append to a CSV. The sensor tails that file and pushes each
completed flow to `/api/flows`. Note what this implies about latency: the model
scores a *flow*, not a packet, so a verdict cannot arrive until the flow record is
written. Your detection delay is dominated by the capture tool's flow timeout,
not by the model.

Column names are matched loosely. Case, spacing and punctuation are ignored, and
the common CICFlowMeter spelling variants are mapped (`Total Length of Fwd Packets`
→ `Fwd Packets Length Total`, `Init_Win_bytes_forward` → `Init Fwd Win Bytes`, and
so on). Unrecognised columns are ignored; `src_ip`, `dst_ip`, `src_port`,
`dst_port`, `protocol_name`, `timestamp` and `flow_id` are carried through to the
UI as metadata.

Missing features are left as NaN and filled by the pipeline's own imputer, so a
partial flow scores fine. `inf` and non-numeric junk (CICFlowMeter emits `Infinity`
in `Flow Bytes/s` on zero-duration flows) become NaN rather than crashing the call.

---

## API

Score one flow and get the answer back:

```bash
curl -X POST localhost:8000/api/score -H 'Content-Type: application/json' -d '{
  "Protocol": 6,
  "Flow Duration": 120000,
  "Bwd Packet Length Mean": 1400,
  "src_ip": "10.0.0.5", "dst_ip": "203.0.113.9", "dst_port": 443
}'
```

```json
{"count": 1, "latency_ms": 14.73, "results": [{
  "attack_probability": 0.0467,
  "verdict": "benign",
  "threshold": 0.5,
  "confidence": 0.907,
  "features_supplied": 3,
  "scored_at": "2026-09-20T18:52:28.492+00:00",
  "drivers": [{"feature": "Bwd Packet Length Mean", "value": 1400.0,
               "training_median": 103.0, "weight": 1.00345}],
  "meta": {"src_ip": "10.0.0.5", "dst_ip": "203.0.113.9", "dst_port": 443}}]}
```

Worth noticing in that response: three features out of 77 were supplied, the other
74 came from the imputer's medians, and the result is a confident benign. A single
unusual feature does not move this model much — which is the correct behaviour for
a flow classifier, but also why partial flows are cheap to score and rarely
interesting. Feed it complete flow records when you can.

The body may be a single object, a list of objects, `{"flows": [...]}`, or a bare
array of 77 numbers in the model's feature order (`GET /api/meta` returns that
order).

`POST /api/flows` takes the same payloads, returns `202` immediately, and queues
for the live console. It returns `429` with a `dropped` count if the queue is full
— that is backpressure, not an error to retry blindly.

Other routes: `GET /api/meta` (feature list, importances, threshold),
`GET /api/health`, `GET /api/stats`, `GET /api/ledger?limit=100`,
`POST /api/threshold`.

---

## How the scoring path is built

Flows posted to `/api/flows` land on a bounded queue. A single worker thread drains
it in micro-batches — up to 512 flows, or whatever has arrived within 50 ms — and
makes one `predict_proba` call per batch. Measured on this model: ~108,000 flows/sec
batched against ~4 ms for a single flow, so batching is worth roughly three orders
of magnitude and the queue is what absorbs bursts.

Each flow is timestamped when it is parsed, not when its batch is scored, so a burst
does not collapse to one instant in the ledger.

Results fan out to every connected browser over SSE. A browser that stalls has its
queue overflow and drops frames rather than slowing the scorer.

---

## Reading the dashboard

The strip is one tick per flow, height being attack probability, oldest at the left,
with the alert threshold as the dashed line. Amber marks flows sitting just under
the threshold — the band worth auditing when you tune.

The slider re-bands everything already on screen as you drag, then persists the new
threshold to the server on release. Verdicts are recomputed client-side from the
stored probability, so moving it never requires re-scoring.

"Inputs furthest from normal" ranks features by the forest's global importance
multiplied by how far this flow sits from the training median the imputer stored.
**This is a heuristic, not an attribution method.** It tells you what is unusual
about a flow; it does not tell you what the forest actually keyed on. If you need
defensible per-flow explanations, swap in `shap.TreeExplainer` — it is well suited
to this model and the `drivers()` function in `app.py` is the only thing to replace.

---

## Three things about the model itself

**1. It never gets very confident about attacks.** Searching the forest's own split
thresholds by coordinate ascent, the highest attack probability reachable by *any*
input is about 0.66. Benign traffic clusters at 0.00–0.07. So the separation is
clean but the attack side is compressed against a low ceiling, and a 0.5 threshold
sits near the top of the model's usable range — it will be unforgiving of any
attack that scores even slightly weakly. Calibrate on a labelled holdout
(precision/recall against replayed CICIDS traffic) rather than taking 0.5 as given.

**2. The demo traffic proves nothing about accuracy.** The attack profiles in
`demo_profiles.json` were derived from the model's own decision regions so the
console has something to display. They are not captured intrusions. Any claim about
detection performance needs labelled data through `sensor.py replay`.

**3. Binary output, no attack class.** The pipeline predicts attack or not. It does
not tell you whether something is a port scan or a DoS. If your training data had
per-attack labels, a multiclass head would make the inspector considerably more
useful to an analyst.

---

## Running it somewhere other than your laptop

`app.py` uses Flask's development server and binds to `127.0.0.1`. For anything
beyond local use:

```bash
gunicorn -w 1 -k gthread --threads 32 -b 127.0.0.1:8000 app:app
```

**One worker.** The queue, the ledger and the SSE subscriber set all live in
process memory, so multiple workers would each hold a different slice of the
traffic and browsers would see whichever one they happened to connect to. If you
need to scale past one process, move the fan-out to Redis pub/sub and let the
workers share it.

There is no authentication, and the console displays internal IP addresses and
your detection threshold. Keep it behind your existing auth proxy or on a
management VLAN; do not expose it to the network it is watching.

Finally: the model file is a pickle, which executes code on load. This one is
yours so that is fine, but it is worth treating the `.pkl` as a trusted artifact
— checksum it in your deployment pipeline rather than fetching it from anywhere
writable.

---

## Files

```
app.py               Flask app: model loading, batched scorer, SSE, REST API
sensor.py            demo / replay / follow feeders
demo_profiles.json   synthetic flow profiles for demo mode
sample_flows.csv     3-row CSV for trying replay mode; deliberately uses alternate
                     CICFlowMeter header spellings and an Infinity value, so it
                     doubles as a check that ingest normalisation still works
templates/index.html dashboard markup
static/style.css     dashboard styles
static/app.js        SSE client, signal strip, ledger, inspector
requirements.txt     pinned — scikit-learn 1.5.1 is required, not preferred
```
