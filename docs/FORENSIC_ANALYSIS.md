# Forensic Analysis — PitCrypt-F1

**Document:** FORENSIC_ANALYSIS.md  
**Version:** 1.0  
**Project:** PitCrypt-F1  
**Status:** Authoritative

---

## Overview

This document describes the forensic telemetry
analysis methodology used in PitCrypt-F1 to
establish statistical baselines, calibrate anomaly
detection thresholds, and generate the visualisations
used for security assessment.

The forensic analysis module processes real 2025
Formula 1 telemetry data from Mercedes AMG and
Red Bull Racing sourced via the FastF1 API.

---

## Data Sources

### FastF1 API

FastF1 is an open-source Python library providing
access to official Formula 1 timing and telemetry
data from the F1 Live Timing API.

```python
import fastf1

session = fastf1.get_session(2025, 'Bahrain', 'R')
session.load(telemetry=True, laps=True)
```

### Coverage
Constructors:  Mercedes AMG Petronas
Red Bull Racing
Circuits:      Abu Dhabi, Australia, Bahrain,
Baku, Japan, Monaco, Monza,
Netherlands, Qatar, Saudi Arabia,
Silverstone, Singapore, São Paulo
Sessions:      Race (R), Qualifying (Q), Sprint (S)
Total rows:    1,814,537 (Mercedes)
~1,566,769 (Red Bull, subset)
Channels:      Speed (km/h), RPM, Throttle (%),
Brake (0/1), nGear (0-8), DRS (0-14)
### Data Quality
Missing values: 0 rows dropped across all datasets
Encoding:       UTF-8, São Paulo handled correctly
Negative speed: -0.04 to -0.06 km/h observed
(pit lane rollback — legitimate)
DRS encoding:   FastF1 integer 0-14 (not boolean)
---

## Forensic Pipeline
FastF1 API
│
▼
fetch_telemetry.py          ← Download raw CSVs
│  data/raw/.csv
▼
forensic_analysis.py        ← Load + clean + baseline
│  data/processed/_baseline.csv
│  data/processed/thresholds.json
▼
calibrate_thresholds.py     ← Per-team bounds
│  data/processed/thresholds.json (updated)
▼
visualise_telemetry.py      ← Generate plots
│  architecture/diagrams/*.png
▼
AnomalyFilter               ← Load thresholds at runtime
(relay-node/src/anomaly_filters.py)
---

## Statistical Baseline Computation

### Method

For each team, circuit, and session combination,
`forensic_analysis.py` computes:

```python
for channel in ['Speed', 'RPM', 'Throttle',
                'Brake', 'nGear', 'DRS']:
    baseline[channel] = {
        'mean':   df[channel].mean(),
        'std':    df[channel].std(),
        'min':    df[channel].min(),
        'max':    df[channel].max(),
        'p01':    df[channel].quantile(0.01),
        'p05':    df[channel].quantile(0.05),
        'p95':    df[channel].quantile(0.95),
        'p99':    df[channel].quantile(0.99),
    }
```

### Z-Score Anomaly Detection

Anomaly detection uses Z-score against the
global baseline (all races combined):

```python
z_score = abs(value - channel_mean) / channel_std

ANOMALY_THRESHOLD = 3.0  # 3 standard deviations

if z_score > ANOMALY_THRESHOLD:
    flag_as_anomaly(channel, value, z_score)
```

Values beyond 3 standard deviations from the
mean represent less than 0.3% of the distribution
under normality — flagged for review.

### Baseline Statistics (Mercedes AMG)

Computed from 1,814,537 rows across all 13 circuits:

| Channel | Mean | Std Dev | Min | Max | P95 |
|---|---|---|---|---|---|
| Speed (km/h) | 187.3 | 89.2 | -0.06 | 345.1 | 308.4 |
| RPM | 9842.1 | 2891.4 | 0 | 13812 | 13204 |
| Throttle (%) | 58.7 | 43.8 | 0 | 100 | 100 |
| Brake (0/1) | 0.14 | 0.35 | 0 | 1 | 1 |
| nGear | 5.2 | 1.8 | 0 | 8 | 8 |
| DRS | 2.1 | 4.8 | 0 | 14 | 12 |

*Exact values vary by run — regenerate with
`python forensic/forensic_analysis.py`*

---

## Threshold Calibration

### Method

`calibrate_thresholds.py` derives anomaly filter
thresholds from the baseline statistics. Two
approaches are combined:

**Statistical bounds:**
```python
lower = max(physical_min, mean - 3 * std)
upper = min(physical_max, mean + 3 * std)
```

**Hard physical limits:**
```python
PHYSICAL_LIMITS = {
    'Speed':    {'min': -5.0,  'max': 400},
    'RPM':      {'min': 0,     'max': 16000},
    'Throttle': {'min': 0,     'max': 100},
    'Brake':    {'min': 0,     'max': 1},
    'nGear':    {'min': 0,     'max': 8},
    'DRS':      {'min': 0,     'max': 14},
}
```

Physical limits are hard — any violation is
an immediate REJECT. Statistical bounds violations
produce a FLAG (forwarded with annotation).

### Why Speed Min = -5.0

Real FastF1 telemetry contains slightly negative
speed values (-0.04 to -0.06 km/h) for cars
stationary or slowly rolling backwards in the
pit lane. Setting `min = 0` would incorrectly
reject legitimate pit lane data. Setting
`min = -5.0` provides a small margin while
still catching physically impossible values.

### Threshold Output Format

```json
{
  "mercedes": {
    "Speed":    {"lower": 0.0, "upper": 345.0},
    "RPM":      {"lower": 0.0, "upper": 13500.0},
    "Throttle": {"lower": 0.0, "upper": 100.0},
    "Brake":    {"lower": 0.0, "upper": 1.0},
    "nGear":    {"lower": 0.0, "upper": 8.0},
    "DRS":      {"lower": 0.0, "upper": 14.0}
  },
  "redbull": {
    "Speed":    {"lower": 0.0, "upper": 340.0},
    ...
  },
  "combined": {
    ...
  }
}
```

Stored at `data/processed/thresholds.json`.
Loaded at relay startup by `AnomalyFilter`.

---

## Anomaly Detection Results

### Anomaly Categories Identified

From forensic analysis of 1,814,537 Mercedes frames:

**Physical anomalies (REJECT level):**
These represent data quality issues in the
raw FastF1 dataset — not security events:
Speed > 400 km/h:    0 occurrences
RPM > 16000:         0 occurrences
nGear > 8:           0 occurrences
Throttle > 100:      0 occurrences
Real F1 data is clean — physical limits are
never exceeded in the source data.

**Statistical anomalies (FLAG level):**
Values beyond 3 standard deviations:
Speed anomalies:     Pit lane entries/exits
Safety car restarts
Crash events
RPM anomalies:       Engine failures
Gear change hesitation
Power unit modes
Throttle anomalies:  Wheel spin events
Sensor glitches
Brake testing
### Anomaly Count by Circuit

Anomaly rates vary significantly by circuit
characteristics:
High anomaly circuits:
Monaco         ← Low speed, frequent braking
Singapore      ← Street circuit, walls
Baku           ← Mixed speed, long straight
Low anomaly circuits:
Monza          ← High speed, smooth flow
Silverstone    ← Fast corners, consistent
Bahrain        ← Technical but predictable
---

## Visualisations

Five visualisations generated by
`forensic/visualise_telemetry.py` and saved
to `architecture/diagrams/`:

### 1. Speed Distribution (`speed_distribution.png`)

Histogram of Speed values across all Mercedes
sessions. Shows bimodal distribution — peak at
0-50 km/h (pit lane) and 250-320 km/h (race pace).
Long tail at 320-345 km/h (DRS straight).

**Security relevance:** Establishes the valid
speed range for anomaly filter thresholds.
Values outside 3σ from race pace peak are flagged.

### 2. Throttle vs Speed (`throttle_vs_speed.png`)

Scatter plot of Throttle position vs Speed.
Shows characteristic F1 pattern — high throttle
at high speed (straights), zero throttle at
low speed (braking zones), mixed at corners.

**Security relevance:** Correlation pattern
allows detection of physically implausible
combinations — e.g., 100% throttle at 0 km/h
for more than a brief period is suspicious.

### 3. Channel Statistics (`channel_statistics.png`)

Box plots of all six telemetry channels with
mean, quartiles, and outlier points marked.
Visualises the statistical distribution used
to compute anomaly thresholds.

**Security relevance:** Shows the 1.5×IQR
outlier boundary used as an alternative to
3σ threshold for non-normal distributions
(Brake is binary — not normally distributed).

### 4. Anomaly Counts (`anomaly_counts.png`)

Bar chart of anomaly frequency per channel per
circuit. Shows that Speed anomalies are most
common (pit lane transitions) and Throttle
anomalies correlate with street circuits.

**Security relevance:** Baseline anomaly rate
per circuit establishes what "normal unusual"
looks like — a sudden spike in anomalies above
the circuit baseline is a security signal.

### 5. DRS Usage (`drs_usage.png`)

DRS state encoding distribution and usage by
circuit. Monaco has near-zero DRS usage (no
detection zones), Monza has highest DRS usage
(two long straights).

**Security relevance:** DRS values outside
the circuit-specific expected range are
suspicious — DRS state 14 on a Monaco sector
with no DRS zone would be anomalous.

---

## Running the Forensic Pipeline

### Prerequisites

```bash
# Activate virtual environment
f1env\Scripts\activate.bat

# Install dependencies
pip install fastf1 pandas matplotlib --break-system-packages
```

### Step 1 — Fetch Telemetry

```bash
python forensic/fetch_telemetry.py
# Downloads all 56 CSV files to data/raw/
# Takes 10-30 minutes depending on FastF1 cache
```

### Step 2 — Compute Baselines

```bash
python forensic/forensic_analysis.py
# Reads data/raw/
# Produces data/processed/mercedes_baseline.csv
#           data/processed/redbull_baseline.csv
#           data/processed/forensic_summary.json
```

### Step 3 — Calibrate Thresholds

```bash
python forensic/calibrate_thresholds.py
# Reads baselines
# Produces data/processed/thresholds.json
```

### Step 4 — Generate Visualisations

```bash
python forensic/visualise_telemetry.py
# Reads baselines
# Produces architecture/diagrams/*.png
```

### Step 5 — Verify Thresholds Loaded

```bash
python relay-node/src/anomaly_filters.py
# Should print:
#   [AnomalyFilter] Thresholds loaded for: ['mercedes', 'redbull']
```

---

## Forensic Files — Gitignore Status

The following files are gitignored due to size:
data/raw/.csv              ← 56 files, ~25MB each
data/processed/_baseline.csv ← 380-413MB each
data/processed/thresholds.json ← Regenerated from baselines
data/anomalies/*.csv        ← Anomaly detection output
**To regenerate after fresh clone:**
```bash
python forensic/fetch_telemetry.py
python forensic/forensic_analysis.py
python forensic/calibrate_thresholds.py
```

This takes approximately 15-45 minutes depending
on FastF1 cache state and internet connection.

---

## Forensic Findings Relevant to Security

### Finding 1 — Negative Speed is Legitimate

Discovery: Real F1 telemetry contains Speed = -0.04
to -0.06 km/h. Setting physical minimum to 0 would
produce false positives in the anomaly filter.

**Impact:** Physical limit set to -5.0 km/h.
Documented in `relay-node/src/anomaly_filters.py`
PHYSICAL_LIMITS.

### Finding 2 — DRS is Not Boolean

Discovery: FastF1 DRS channel encodes state as
integer 0-14, not a simple open/closed boolean.

**Impact:** PHYSICAL_LIMITS DRS max set to 14.
DRS threshold calibrated against observed values,
not assumed 0/1 range.

### Finding 3 — Session Affects Distribution

Discovery: Qualifying sessions have different
speed distributions than Race sessions — Q1/Q2/Q3
have outlap/inlap low-speed phases that Race
does not.

**Impact:** `SensorSimulator` allows session
selection. Thresholds should ideally be
session-specific in production.

### Finding 4 — São Paulo Sprint Data

Discovery: São Paulo 2025 had both a Sprint
Qualifying and Sprint Race session, contributing
two additional CSV files with distinct
distribution characteristics.

**Impact:** Sprint sessions included in baseline
computation. `SensorSimulator` correctly handles
Sprint session type.

---

## See Also

- `forensic/fetch_telemetry.py` — Data acquisition
- `forensic/forensic_analysis.py` — Baseline computation
- `forensic/calibrate_thresholds.py` — Threshold derivation
- `forensic/visualise_telemetry.py` — Plot generation
- `relay-node/src/anomaly_filters.py` — Runtime detection
- `docs/FIA_DATA_PRIVACY_MODEL.md` — Data privacy handling
- `architecture/diagrams/` — Generated visualisations