# Forensic Analysis — PitCrypt-F1

**Document:** `FORENSIC_ANALYSIS.md`  
**Version:** 1.1  
**Project:** PitCrypt-F1  
**Status:** Prototype analysis methodology — results require reproducible verification  
**Last reviewed:** 24 October 2026

---

## 1. Overview

This document describes the forensic telemetry analysis workflow used by PitCrypt-F1 to explore telemetry distributions, calculate statistical baselines, calibrate anomaly-detection thresholds, and generate visualisations for security assessment.

The project uses the FastF1 Python library to retrieve Formula 1 timing and telemetry data. The analysis is intended to provide context for telemetry validation and anomaly detection; it is not a formal forensic certification or evidence that the dataset represents every car, session, or operating condition.

Statistical anomalies are not necessarily security incidents. Unusual values can arise from pit-lane movement, braking, safety-car periods, session transitions, sensor behaviour, or data-processing artefacts. A security conclusion requires additional context and corroborating evidence.

Dataset counts, summary statistics, generated plots, and threshold outputs in this document should be treated as reported results until they can be reproduced from the current repository, source data, and configuration.

## 2. Data sources

### 2.1 FastF1

FastF1 is a Python library that provides access to Formula 1 timing and telemetry data through supported data sources.

Example session-loading code:

```python
import fastf1

session = fastf1.get_session(2025, "Bahrain", "R")
session.load(telemetry=True, laps=True)
```

The exact data available depends on the session, the library version, the underlying data source, and the fields exposed by the loaded objects.

The resulting data should be described as telemetry retrieved through FastF1, rather than as a separately certified or independently verified forensic evidence source.

### 2.2 Reported dataset coverage

The original project notes report analysis of Mercedes-AMG Petronas and Red Bull Racing data from 13 circuits:

- Abu Dhabi
- Australia
- Bahrain
- Baku
- Japan
- Monaco
- Monza
- Netherlands
- Qatar
- Saudi Arabia
- Silverstone
- Singapore
- São Paulo

The reported session categories include Race (`R`), Qualifying (`Q`), and Sprint (`S`). The exact meaning and availability of session identifiers must be checked against the acquisition script and generated files.

Previously recorded row counts were:

| Dataset | Reported rows | Verification status |
|---|---:|---|
| Mercedes | 1,814,537 | Reproduce from the current dataset before treating as a verified result |
| Red Bull | Approximately 1,566,769 | Reported subset; exact coverage and row count require verification |

These counts can change if sessions, channels, filtering rules, FastF1 versions, or data-loading behaviour change. A reproducible report should record the acquisition date, library version, included sessions, file names, and row counts.

### 2.3 Channels

The original analysis describes the following channels:

| Channel | Interpretation | Important consideration |
|---|---|---|
| `Speed` | Speed in km/h | Small negative values may occur in source data; inspect context before classifying them as errors. |
| `RPM` | Engine speed | Values depend on data availability and operating conditions. |
| `Throttle` | Throttle percentage | Check expected scale and source representation. |
| `Brake` | Brake indicator or channel value | The documented binary interpretation must be confirmed for each dataset. |
| `nGear` | Gear value | Validate against the source encoding and expected range. |
| `DRS` | DRS state encoding | Do not assume it is a Boolean channel; the source may encode multiple states. |

Current project telemetry may also include `X`, `Y`, and `Distance`. Include those channels in a baseline only when the analysis code explicitly loads and processes them.

### 2.4 Data-quality observations

The original notes report the following observations:

- No rows were dropped for missing values in the examined datasets.
- UTF-8 handling was considered for the São Paulo circuit name.
- Speed values around -0.04 to -0.06 km/h were observed.
- DRS values were treated as an integer state encoding rather than a Boolean value.

These observations are useful hypotheses for repeatable data-quality checks, not universal properties of all FastF1 datasets. Re-run missing-value, encoding, range, and channel-type checks after downloading or regenerating the data.

A data-quality report should record:

- Rows loaded and rows excluded.
- Missing values by channel.
- Duplicate timestamps or samples, where applicable.
- Non-finite values.
- Observed minimum and maximum values.
- Channel types and units.
- Source session and driver identifiers.
- Any cleaning, interpolation, or transformation applied.

Do not claim that no rows were dropped unless the current execution output supports that statement.

## 3. Forensic analysis pipeline

The intended workflow is:

```text
FastF1 data source
        |
        v
forensic/fetch_telemetry.py
        |
        v
Raw telemetry files
        |
        v
forensic/forensic_analysis.py
        |
        +--> Baseline statistics
        +--> Forensic summary
        |
        v
forensic/calibrate_thresholds.py
        |
        v
Threshold configuration
        |
        v
forensic/visualise_telemetry.py
        |
        v
Generated plots
        |
        v
relay-node/src/anomaly_filters.py
        |
        v
Runtime anomaly decisions
```

This is the intended data flow described by the project documentation. Confirm each input/output path and the runtime loading behaviour against the current source before treating the entire workflow as an integrated pipeline.

In particular, producing a threshold JSON file does not establish that the relay loads it, interprets it correctly, or applies every generated threshold to incoming telemetry.

## 4. Statistical baseline computation

### 4.1 Purpose

Baselines summarise the observed distribution of telemetry values. They can help identify unusual observations and inform threshold calibration.

The analysis should distinguish baseline generation from runtime detection. A descriptive statistical summary does not automatically define an appropriate security boundary.

### 4.2 Reported statistics

For each supported channel and selected grouping, the original methodology computes:

- Mean
- Standard deviation
- Minimum and maximum
- 1st and 5th percentiles
- 95th and 99th percentiles

Example:

```python
channels = [
    "Speed", "RPM", "Throttle",
    "Brake", "nGear", "DRS"
]

for channel in channels:
    baseline[channel] = {
        "mean": df[channel].mean(),
        "std": df[channel].std(),
        "min": df[channel].min(),
        "max": df[channel].max(),
        "p01": df[channel].quantile(0.01),
        "p05": df[channel].quantile(0.05),
        "p95": df[channel].quantile(0.95),
        "p99": df[channel].quantile(0.99),
    }
```

This snippet illustrates the intended calculations. Confirm the actual grouping keys, missing-value treatment, standard-deviation convention, and output schema against `forensic_analysis.py`.

The project notes describe baselines by team, circuit, and session combination. They also describe a global baseline for some anomaly detection. Those are distinct choices and should not be conflated.

### 4.3 Grouping and distribution shifts

Telemetry distributions vary with:

- Circuit layout and surface characteristics.
- Race, qualifying, and sprint sessions.
- Pit-lane entry and exit.
- Outlaps, inlaps, and other non-representative periods.
- Weather and track conditions.
- Driver behaviour and car setup.
- Data availability and sampling behaviour.

A global baseline can be useful for broad exploratory analysis, but it may flag normal values from a particular context. Where sufficient data exists, evaluate separate baselines by channel, team, circuit, session type, and relevant operating state.

Do not treat a team-specific statistical difference as evidence of malicious behaviour.

## 5. Z-score anomaly analysis

### 5.1 Formula

For a value \(x\), mean \(\mu\), and standard deviation \(\sigma\), the absolute Z-score is:

\[
z = \frac{|x-\mu|}{\sigma}
\]

A common exploratory threshold is \(z > 3\). The calculation must handle zero or non-finite standard deviations and missing or non-numeric values explicitly.

Example:

```python
if std > 0:
    z_score = abs(value - mean) / std
else:
    # Define an explicit policy for constant or invalid baselines.
    z_score = None
```

### 5.2 Interpretation

Under a normal distribution, observations beyond three standard deviations are uncommon. However, motorsport telemetry is not guaranteed to follow a normal distribution.

Some channels are bounded, discrete, or multimodal. `Brake` may be binary in a particular dataset, while `DRS` represents discrete states. A global Z-score can therefore be misleading.

A three-standard-deviation threshold should be treated as an exploratory statistical rule, not as a universal probability guarantee or a security detector.

A value flagged by this method should be reviewed alongside:

- The channel and unit.
- The relevant circuit and session.
- Adjacent telemetry samples.
- Vehicle state and operating context.
- Source-data quality.
- The result of independent validation checks.

### 5.3 Baseline statistics

The original document reported the following Mercedes summary values:

| Channel | Reported mean | Reported standard deviation | Reported minimum | Reported maximum | Reported P95 |
|---|---:|---:|---:|---:|---:|
| Speed (km/h) | 187.3 | 89.2 | -0.06 | 345.1 | 308.4 |
| RPM | 9,842.1 | 2,891.4 | 0 | 13,812 | 13,204 |
| Throttle (%) | 58.7 | 43.8 | 0 | 100 | 100 |
| Brake | 0.14 | 0.35 | 0 | 1 | 1 |
| `nGear` | 5.2 | 1.8 | 0 | 8 | 8 |
| DRS | 2.1 | 4.8 | 0 | 14 | 12 |

**Verification note:** These are previously reported values, not independently reproduced results in this document. Recalculate them from the current dataset before citing them as measured project results. The exact values depend on data coverage, filtering, and the statistical method used.

Reproducible results should be accompanied by a generated summary, script version or commit, and enough configuration detail to reproduce the same dataset.

## 6. Threshold calibration

### 6.1 Purpose

Threshold calibration converts baseline observations and domain constraints into parameters used by the runtime anomaly filter.

The project documentation describes two categories:

1. Statistical bounds derived from the baseline.
2. Hard range checks intended to identify values outside configured limits.

These categories should have different meanings in the implementation and in the resulting audit events.

### 6.2 Statistical bounds

The original methodology describes:

```python
lower = max(physical_min, mean - 3 * std)
upper = min(physical_max, mean + 3 * std)
```

This is an illustrative rule. Confirm that the current calibration code uses this exact calculation and that the variables are valid for the relevant channel.

A statistical bound indicates that a value is unusual relative to the chosen baseline. It does not necessarily indicate that the value is physically impossible.

### 6.3 Candidate physical limits

The original configuration notes include:

```python
PHYSICAL_LIMITS = {
    "Speed":    {"min": -5.0, "max": 400},
    "RPM":      {"min": 0,    "max": 16000},
    "Throttle": {"min": 0,    "max": 100},
    "Brake":    {"min": 0,    "max": 1},
    "nGear":    {"min": 0,    "max": 8},
    "DRS":      {"min": 0,    "max": 14},
}
```

Treat these as project-configured candidate limits, not independently established engineering or FIA limits. Confirm that the current `AnomalyFilter` uses these values and that the units and channel encodings match the input.

The binary interpretation of `Brake`, valid gear values, and the accepted DRS range should be verified against the actual source data and simulator schema.

### 6.4 Negative speed

The original analysis notes observed small negative speed values, around -0.04 to -0.06 km/h, and proposes a lower threshold of -5 km/h to avoid rejecting such samples.

This is a project-specific tolerance, not proof that every negative speed value is valid. Investigate values outside the normal observed range and examine their context before classifying them.

### 6.5 Decision semantics

The original design distinguishes:

- **REJECT:** A value violates a configured hard limit.
- **FLAG:** A value falls outside a statistical bound but is not rejected solely for that reason.

Verify the actual runtime implementation before claiming these semantics are enforced. The filter's code, configuration loading, and caller behaviour determine whether a flagged packet is forwarded, annotated, or rejected.

The system should make rejection and flagging reasons explicit in its results and logs.

## 7. Threshold output and runtime integration

The original documentation describes a JSON threshold file containing team-specific channel bounds and a combined set of bounds.

An illustrative shape is:

```json
{
  "mercedes": {
    "Speed": {"lower": 0.0, "upper": 345.0},
    "RPM": {"lower": 0.0, "upper": 13500.0},
    "Throttle": {"lower": 0.0, "upper": 100.0},
    "Brake": {"lower": 0.0, "upper": 1.0},
    "nGear": {"lower": 0.0, "upper": 8.0},
    "DRS": {"lower": 0.0, "upper": 14.0}
  },
  "redbull": {
    "Speed": {"lower": 0.0, "upper": 340.0}
  },
  "combined": {}
}
```

This is an abbreviated example, not a verified current output file. Regenerate the actual file and inspect its schema before using it as a reference.

Verify all of the following:

- The calibration script writes to the documented location.
- The runtime filter reads from that location.
- Team names and channel names match between producer, calibration, and runtime code.
- Missing or malformed thresholds cause a clear, safe outcome.
- Default thresholds are documented if the file is absent.
- Reload behaviour is defined if the file changes while the relay is running.
- The runtime decision actually uses the loaded values.

Do not assume that calibration and runtime detection are integrated merely because both components exist in the repository.

## 8. Anomaly results and interpretation

### 8.1 Physical-range violations

The original notes report zero occurrences of the following values in the examined Mercedes dataset:

- Speed above 400 km/h.
- RPM above 16,000.
- Gear above 8.
- Throttle above 100%.

These counts require reproduction from the current dataset and should specify the exact filters, included sessions, and handling of missing or non-finite values.

Even if no such values occur in the source dataset, this does not prove that the detector can identify all malformed or adversarial telemetry.

### 8.2 Statistical anomalies

The original analysis associates unusual speed, RPM, throttle, and braking observations with events such as pit-lane transitions, safety-car restarts, engine behaviour, wheel spin, and sensor glitches.

These are plausible investigation hypotheses, not verified causal findings. A statistical outlier does not establish that a crash, engine failure, sensor fault, or security incident occurred.

Where causal interpretation matters, correlate the observation with session context, adjacent samples, available timing data, and other evidence.

### 8.3 Circuit-level anomaly rates

Circuit-specific distributions can differ substantially. For example, low-speed street circuits may exhibit different speed and braking patterns from circuits with long straights.

However, circuit rankings such as “high anomaly” and “low anomaly” must be based on computed rates and a documented denominator. They should not be treated as established findings without regenerated counts and plots.

For meaningful comparisons, report at least:

- Total samples per circuit.
- Number of flagged samples per channel.
- Flag rate and rejection rate.
- Session types included.
- Missing or excluded observations.
- Threshold configuration and baseline version.

A spike in anomaly flags may indicate a changed operating condition, a configuration mismatch, a data-quality problem, or an attack. It is a signal for investigation, not a conclusion.

## 9. Visualisations

The original pipeline describes five visualisations. Their existence and current output should be checked against `forensic/visualise_telemetry.py` and the generated files.

### 9.1 Speed distribution

**Intended purpose:** Show the distribution of speed samples and highlight possible multimodal behaviour, including low-speed and racing-speed periods.

**Security relevance:** Helps assess the suitability of global speed bounds and identify distribution shifts.

**Limitation:** A histogram does not establish which samples are valid or malicious. Session context and data quality remain important.

### 9.2 Throttle versus speed

**Intended purpose:** Explore the relationship between throttle and speed.

**Security relevance:** May help identify observations that deserve review when they are inconsistent with expected patterns.

**Limitation:** A simple scatter plot does not account for every legitimate vehicle state, transient, gear, braking event, or sensor behaviour. Correlation should not be used as a hard rejection rule without a validated model.

### 9.3 Channel statistics

**Intended purpose:** Compare distributions across channels using descriptive plots such as box plots.

**Security relevance:** Helps identify spread, skew, outliers, and differences between channels.

**Limitation:** Box-plot outliers, including points beyond conventional 1.5×IQR whiskers, are statistical indicators. They are not automatically security incidents or physically impossible values.

### 9.4 Anomaly counts

**Intended purpose:** Compare flag or rejection counts by channel, circuit, or session.

**Security relevance:** Helps monitor distribution changes and investigate unexpected increases in flags.

**Limitation:** Counts must be normalised by the number of samples and interpreted against the relevant context. A larger dataset may naturally produce more flags even if the underlying rate is unchanged.

### 9.5 DRS state distribution

**Intended purpose:** Inspect DRS state values and compare observed distributions across circuits or sessions.

**Security relevance:** Can help identify unexpected encodings or values that warrant investigation.

**Limitation:** Circuit-specific rules must be supported by an accurate mapping of the session, track layout, applicable DRS configuration, and telemetry semantics. A DRS state should not be rejected solely because a general circuit assumption suggests it is unusual.

## 10. Running the forensic workflow

Commands below reflect the project paths described in the original documentation. Verify them against the current repository before relying on them.

### 10.1 Install dependencies

Activate the appropriate project virtual environment and install the dependencies declared by the repository.

For example:

```bash
python -m pip install fastf1 pandas matplotlib
```

Prefer a project-managed dependency file and virtual environment over global installation. Avoid adding `--break-system-packages` to ordinary setup instructions.

### 10.2 Fetch telemetry

```bash
python forensic/fetch_telemetry.py
```

The original notes describe downloading raw CSV files into `data/raw/`. Confirm the actual filenames, session coverage, and output directory from the script.

### 10.3 Compute baselines

```bash
python forensic/forensic_analysis.py
```

The original notes describe outputs under `data/processed/`, including baseline files and a forensic summary. Confirm the exact names and schemas from the current implementation.

### 10.4 Calibrate thresholds

```bash
python forensic/calibrate_thresholds.py
```

Inspect the generated threshold file and verify that the values and grouping keys are correct.

### 10.5 Generate visualisations

```bash
python forensic/visualise_telemetry.py
```

Confirm the output paths and inspect the generated images rather than assuming the script completed successfully.

### 10.6 Verify runtime integration

Inspect and test:

```bash
python relay-node/src/anomaly_filters.py
```

This command may exercise or display the filter's loading behaviour, depending on the module implementation. It does not, by itself, prove that a running relay uses the generated thresholds.

For integration verification, run the intended relay test or simulation with known input packets and confirm the observed decision for values inside and outside configured bounds.

## 11. Data storage and reproducibility

The original project notes state that raw telemetry, processed baselines, threshold files, and anomaly outputs may be excluded from version control because of their size or regeneration strategy.

Check the current `.gitignore` and repository state before relying on that description.

A reproducible analysis should record:

- Source and session identifiers.
- Data retrieval date.
- FastF1 and Python versions.
- Analysis code revision.
- Channel list and units.
- Data-cleaning rules.
- Baseline grouping method.
- Threshold configuration.
- Row counts and missing-value summaries.
- Output file names and generation results.

If large datasets are not stored in the repository, provide clear regeneration instructions and retain a small, non-sensitive test fixture for automated tests.

Do not include credentials, private keys, or other secrets in data archives or reproducibility artifacts.

## 12. Forensic interpretation and evidence limitations

PitCrypt-F1's forensic analysis is exploratory telemetry analysis. It should not be confused with a complete digital-forensics process or a legally defensible chain of custody.

Statistical baselines and visualisations do not independently prove:

- Who generated a packet.
- Whether a telemetry value is truthful.
- Whether a system was compromised.
- Whether a driver or team violated a regulation.
- Whether evidence has remained unchanged since acquisition.

Those conclusions require appropriate provenance, authenticated records, validated tools, context, and corroborating evidence.

Where data is used in a security investigation, preserve the source files, record their origin and acquisition time, document transformations, and maintain hashes or other integrity records where appropriate. A hash supports later integrity checking only when the reference hash and its provenance are adequately protected.

## 13. Findings and follow-up work

The original project notes identify several useful engineering observations:

1. **Small negative speed values:** Investigate source context before choosing lower bounds; avoid arbitrary rejection of legitimate samples.
2. **DRS encoding:** Preserve the actual source representation rather than assuming a Boolean channel.
3. **Session-dependent distributions:** Evaluate whether separate baselines are appropriate for race, qualifying, and sprint sessions.
4. **Sprint coverage:** Confirm which sprint-related sessions were actually fetched and included in each baseline.
5. **Threshold integration:** Test that calibrated values reach the active runtime filter and produce the intended decisions.

Recommended next steps:

- Reproduce and version the reported statistics.
- Add automated tests for missing values, non-finite values, boundary conditions, and unexpected channel encodings.
- Evaluate false-positive and false-negative behaviour using labelled or deliberately constructed test cases.
- Separate statistical flags from hard validation failures in reports.
- Add per-circuit and per-session evaluation where the dataset supports it.
- Record threshold provenance so runtime decisions can be traced to the configuration that produced them.

## 14. Related documents and code

- `forensic/fetch_telemetry.py` — Data acquisition, if present.
- `forensic/forensic_analysis.py` — Baseline computation, if present.
- `forensic/calibrate_thresholds.py` — Threshold derivation, if present.
- `forensic/visualise_telemetry.py` — Plot generation, if present.
- `relay-node/src/anomaly_filters.py` — Runtime anomaly filtering.
- `docs/FIA_DATA_PRIVACY_MODEL.md` — Data privacy model.
- `docs/THREAT_MODEL.md` — Threat analysis.
- `architecture/diagrams/` — Generated visualisations, if present.

Update this document when the analysis pipeline, source coverage, channel definitions, calibration logic, or runtime integration changes. Keep reported results separate from unverified observations and regenerate numerical claims when the underlying data or code changes.
