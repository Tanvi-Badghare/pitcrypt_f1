import os
import sys
import json
import time
import logging
from datetime import datetime, timezone

# ── Path setup ───────────────────────────────────────────────────
ROOT    = os.path.abspath(os.path.dirname(__file__) + '/..')
IAM_SRC = os.path.join(ROOT, 'iam-module', 'src')

sys.path.insert(0, IAM_SRC)

from identity_store import IdentityStore
from policy_loader  import PolicyLoader
from rbac_engine    import RBACEngine, AccessDecision
from access_auditor import AccessAuditor

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s — %(levelname)s — %(message)s"
)

"""
iam_breach_sim.py

Simulates IAM breach and privilege escalation attempts
against PitCrypt-F1 zero-trust access control.

Attack vectors tested:
    1. Unknown node access      — unregistered node attempts access
    2. Cross-team data access   — Mercedes reads Red Bull telemetry
    3. Car → Validator bypass   — car contacts validator directly
    4. Relay impersonation      — car pretends to be relay
    5. Privilege escalation     — car attempts validator actions
    6. Audit log tampering      — relay attempts to modify audit log
    7. Consecutive denial storm — repeated denied requests (DoS probe)

Defence mechanisms verified:
    - Zero-trust default deny for unknown nodes
    - Role-based policy enforcement
    - Explicit deny rules override allow rules
    - Consecutive denial alerting

Results saved to:
    simulations/results/iam_breach_log.json
"""

RESULTS_DIR = os.path.join(ROOT, 'simulations', 'results')
os.makedirs(RESULTS_DIR, exist_ok=True)


def build_iam():
    """Build IAM engine with auditor."""
    store  = IdentityStore()
    loader = PolicyLoader()
    engine = RBACEngine(
        identity_store=store,
        policy_loader=loader,
        enforcement='strict',
    )
    auditor = AccessAuditor(
        node_id='iam_sim',
        log_to_file=False,
    )
    return engine, auditor


def record(
    auditor: AccessAuditor,
    decision: AccessDecision,
) -> None:
    """Record decision to auditor."""
    auditor.record_from_decision(decision)


# ── Attack simulations ────────────────────────────────────────────

def sim_1_unknown_node(
    engine: RBACEngine,
    auditor: AccessAuditor,
) -> dict:
    """
    Attack: Unregistered node attempts to read telemetry.
    Defence: Zero-trust default deny — node not registered.
    """
    print("\n[Attack 1] Unknown Node Access Attempt")

    attempts = [
        ('unknown_attacker',  'telemetry.read',    'all_telemetry'),
        ('rouge_car_99',      'network.transmit',  'validator_node'),
        ('mystery_node',      'audit.read',        'audit_log'),
        ('fake_relay',        'telemetry.decrypt', 'car_packets'),
    ]

    results = []
    for node_id, action, resource in attempts:
        d = engine.check(node_id, action, resource)
        record(auditor, d)
        results.append({
            'node_id':  node_id,
            'action':   action,
            'resource': resource,
            'allowed':  d.allowed,
            'reason':   d.reason,
        })
        status = '✅ BLOCKED' if not d.allowed else '❌ ALLOWED'
        print(
            f"  {status} — {node_id} "
            f"→ {action} on {resource}"
        )

    all_blocked = all(not r['allowed'] for r in results)
    print(
        f"  Result: "
        f"{'✅ ALL BLOCKED' if all_blocked else '❌ SOME PASSED'}"
    )

    return {
        'attack':     'unknown_node_access',
        'attempts':   len(attempts),
        'blocked':    sum(1 for r in results if not r['allowed']),
        'all_blocked': all_blocked,
        'details':    results,
    }


def sim_2_cross_team_access(
    engine: RBACEngine,
    auditor: AccessAuditor,
) -> dict:
    """
    Attack: Mercedes car tries to read Red Bull telemetry.
    Defence: Explicit deny rule in car_node_policy.
    """
    print("\n[Attack 2] Cross-Team Data Access")

    attempts = [
        ('mercedes_car', 'telemetry.read', 'other_team_telemetry'),
        ('redbull_car',  'telemetry.read', 'other_team_telemetry'),
        ('mercedes_car', 'key.read',       'other_node_keys'),
        ('redbull_car',  'key.read',       'other_node_keys'),
    ]

    results = []
    for node_id, action, resource in attempts:
        d = engine.check(node_id, action, resource)
        record(auditor, d)
        results.append({
            'node_id':  node_id,
            'action':   action,
            'resource': resource,
            'allowed':  d.allowed,
            'reason':   d.reason,
        })
        status = '✅ BLOCKED' if not d.allowed else '❌ ALLOWED'
        print(
            f"  {status} — {node_id} "
            f"→ {action} on {resource}"
        )

    all_blocked = all(not r['allowed'] for r in results)
    print(
        f"  Result: "
        f"{'✅ ALL BLOCKED' if all_blocked else '❌ SOME PASSED'}"
    )

    return {
        'attack':      'cross_team_access',
        'attempts':    len(attempts),
        'blocked':     sum(1 for r in results if not r['allowed']),
        'all_blocked': all_blocked,
        'details':     results,
    }


def sim_3_car_validator_bypass(
    engine: RBACEngine,
    auditor: AccessAuditor,
) -> dict:
    """
    Attack: Car node tries to contact validator directly,
            bypassing relay entirely.
    Defence: Explicit deny — car cannot transmit to validator.
    """
    print("\n[Attack 3] Car → Validator Direct Bypass")

    attempts = [
        ('mercedes_car', 'network.transmit', 'validator_node'),
        ('redbull_car',  'network.transmit', 'validator_node'),
        ('mercedes_car', 'signature.verify', 'all_packets'),
        ('mercedes_car', 'audit.write',      'audit_log'),
    ]

    results = []
    for node_id, action, resource in attempts:
        d = engine.check(node_id, action, resource)
        record(auditor, d)
        results.append({
            'node_id':  node_id,
            'action':   action,
            'resource': resource,
            'allowed':  d.allowed,
            'reason':   d.reason,
        })
        status = '✅ BLOCKED' if not d.allowed else '❌ ALLOWED'
        print(
            f"  {status} — {node_id} "
            f"→ {action} on {resource}"
        )

    all_blocked = all(not r['allowed'] for r in results)
    print(
        f"  Result: "
        f"{'✅ ALL BLOCKED' if all_blocked else '❌ SOME PASSED'}"
    )

    return {
        'attack':      'car_validator_bypass',
        'attempts':    len(attempts),
        'blocked':     sum(1 for r in results if not r['allowed']),
        'all_blocked': all_blocked,
        'details':     results,
    }


def sim_4_relay_impersonation(
    engine: RBACEngine,
    auditor: AccessAuditor,
) -> dict:
    """
    Attack: Car node attempts actions only relay can do.
    Defence: Policy denies relay-specific actions to car role.
    """
    print("\n[Attack 4] Relay Impersonation by Car Node")

    attempts = [
        ('mercedes_car', 'telemetry.reencrypt', 'validator_packets'),
        ('mercedes_car', 'telemetry.forward',   'validator_node'),
        ('mercedes_car', 'anomaly.filter',       'telemetry_values'),
        ('mercedes_car', 'integrity.check',      'packet_sequence'),
    ]

    results = []
    for node_id, action, resource in attempts:
        d = engine.check(node_id, action, resource)
        record(auditor, d)
        results.append({
            'node_id':  node_id,
            'action':   action,
            'resource': resource,
            'allowed':  d.allowed,
            'reason':   d.reason,
        })
        status = '✅ BLOCKED' if not d.allowed else '❌ ALLOWED'
        print(
            f"  {status} — {node_id} "
            f"→ {action} on {resource}"
        )

    all_blocked = all(not r['allowed'] for r in results)
    print(
        f"  Result: "
        f"{'✅ ALL BLOCKED' if all_blocked else '❌ SOME PASSED'}"
    )

    return {
        'attack':      'relay_impersonation',
        'attempts':    len(attempts),
        'blocked':     sum(1 for r in results if not r['allowed']),
        'all_blocked': all_blocked,
        'details':     results,
    }


def sim_5_privilege_escalation(
    engine: RBACEngine,
    auditor: AccessAuditor,
) -> dict:
    """
    Attack: Car and relay nodes attempt validator actions.
    Defence: Role-based policy — only fia_validator role
             can perform verification and audit actions.
    """
    print("\n[Attack 5] Privilege Escalation Attempts")

    attempts = [
        # Car trying validator actions
        ('mercedes_car', 'signature.verify', 'all_packets'),
        ('mercedes_car', 'zkp.verify',       'all_packets'),
        ('mercedes_car', 'packet.accept',    'verified_packets'),
        ('mercedes_car', 'packet.reject',    'invalid_packets'),
        # Relay trying validator actions
        ('relay_01',     'signature.verify', 'all_packets'),
        ('relay_01',     'zkp.verify',       'all_packets'),
        ('relay_01',     'audit.write',      'audit_log'),
        ('relay_01',     'node.register',    'car_nodes'),
    ]

    results = []
    for node_id, action, resource in attempts:
        d = engine.check(node_id, action, resource)
        record(auditor, d)
        results.append({
            'node_id':  node_id,
            'action':   action,
            'resource': resource,
            'allowed':  d.allowed,
            'reason':   d.reason,
        })
        status = '✅ BLOCKED' if not d.allowed else '❌ ALLOWED'
        print(
            f"  {status} — {node_id} "
            f"→ {action} on {resource}"
        )

    all_blocked = all(not r['allowed'] for r in results)
    print(
        f"  Result: "
        f"{'✅ ALL BLOCKED' if all_blocked else '❌ SOME PASSED'}"
    )

    return {
        'attack':      'privilege_escalation',
        'attempts':    len(attempts),
        'blocked':     sum(1 for r in results if not r['allowed']),
        'all_blocked': all_blocked,
        'details':     results,
    }


def sim_6_audit_log_tampering(
    engine: RBACEngine,
    auditor: AccessAuditor,
) -> dict:
    """
    Attack: Relay attempts to read or modify audit log.
    Defence: Relay policy explicitly denies audit access.
             Only fia_validator can write/read audit log.
    """
    print("\n[Attack 6] Audit Log Tampering Attempt")

    attempts = [
        ('relay_01',     'audit.read',   'audit_log'),
        ('relay_01',     'audit.write',  'audit_log'),
        ('relay_01',     'audit.export', 'audit_log'),
        ('mercedes_car', 'audit.read',   'audit_log'),
        ('mercedes_car', 'audit.write',  'audit_log'),
        ('redbull_car',  'audit.read',   'audit_log'),
    ]

    results = []
    for node_id, action, resource in attempts:
        d = engine.check(node_id, action, resource)
        record(auditor, d)
        results.append({
            'node_id':  node_id,
            'action':   action,
            'resource': resource,
            'allowed':  d.allowed,
            'reason':   d.reason,
        })
        status = '✅ BLOCKED' if not d.allowed else '❌ ALLOWED'
        print(
            f"  {status} — {node_id} "
            f"→ {action} on {resource}"
        )

    all_blocked = all(not r['allowed'] for r in results)
    print(
        f"  Result: "
        f"{'✅ ALL BLOCKED' if all_blocked else '❌ SOME PASSED'}"
    )

    return {
        'attack':      'audit_log_tampering',
        'attempts':    len(attempts),
        'blocked':     sum(1 for r in results if not r['allowed']),
        'all_blocked': all_blocked,
        'details':     results,
    }


def sim_7_denial_storm(
    engine: RBACEngine,
    auditor: AccessAuditor,
) -> dict:
    """
    Attack: Repeated denied requests from unknown node —
            probing the system to find allowed actions.
    Defence: AccessAuditor detects consecutive denials
             and triggers alert after threshold (3).
    """
    print("\n[Attack 7] Consecutive Denial Storm (DoS Probe)")

    probe_actions = [
        'telemetry.read',
        'telemetry.write',
        'audit.read',
        'key.read',
        'network.transmit',
        'signature.forge',
        'packet.inject',
        'session.hijack',
    ]

    results  = []
    node_id  = 'probing_attacker'
    resource = 'any'

    print(f"  Probing node: {node_id}")
    for action in probe_actions:
        d = engine.check(node_id, action, resource)
        record(auditor, d)
        results.append({
            'node_id':  node_id,
            'action':   action,
            'resource': resource,
            'allowed':  d.allowed,
            'reason':   d.reason,
        })

    all_denied  = all(not r['allowed'] for r in results)
    alert_fired = auditor.alert_count > 0

    print(
        f"  All {len(probe_actions)} probes denied: "
        f"{'✅' if all_denied else '❌'}"
    )
    print(
        f"  Alert triggered: "
        f"{'✅ YES' if alert_fired else '❌ NO'}"
    )
    print(
        f"  Total alerts: {auditor.alert_count}"
    )
    print(
        f"  Result: "
        f"{'✅ DETECTED' if alert_fired else '⚠️  No alert'}"
    )

    return {
        'attack':       'denial_storm',
        'probes':       len(probe_actions),
        'all_denied':   all_denied,
        'alert_fired':  alert_fired,
        'alert_count':  auditor.alert_count,
        'details':      results,
    }


# ── Main ──────────────────────────────────────────────────────────

def main():
    print("\n" + "="*60)
    print("  PitCrypt-F1 — IAM Breach Simulation")
    print("  Testing zero-trust access control enforcement")
    print("="*60)

    engine, auditor = build_iam()
    results = []
    start   = time.time()

    results.append(sim_1_unknown_node(engine, auditor))
    results.append(sim_2_cross_team_access(engine, auditor))
    results.append(sim_3_car_validator_bypass(engine, auditor))
    results.append(sim_4_relay_impersonation(engine, auditor))
    results.append(sim_5_privilege_escalation(engine, auditor))
    results.append(sim_6_audit_log_tampering(engine, auditor))
    results.append(sim_7_denial_storm(engine, auditor))

    elapsed = time.time() - start

    # ── Summary ──────────────────────────────────────────────────
    print("\n" + "="*60)
    print("  Simulation Summary")
    print("="*60)

    total    = len(results)
    defended = sum(
        1 for r in results
        if r.get('all_blocked') or r.get('alert_fired')
    )

    for r in results:
        status  = '✅' if (
            r.get('all_blocked') or r.get('alert_fired')
        ) else '❌'
        blocked = r.get('blocked', r.get('probes', 0))
        total_a = r.get('attempts', r.get('probes', 0))
        print(
            f"  {status} {r['attack']:<30} "
            f"blocked={blocked}/{total_a}"
        )

    aud_summary = auditor.summary()
    print(f"\n  Attacks simulated:  {total}")
    print(f"  Fully defended:     {defended}/{total}")
    print(f"  Total IAM checks:   {aud_summary['total']}")
    print(f"  Total blocked:      {aud_summary['denied']}")
    print(f"  Alerts triggered:   {aud_summary['alerts']}")
    print(f"  Elapsed:            {elapsed:.2f}s")

    # ── Save JSON ─────────────────────────────────────────────────
    output = {
        'simulation':   'iam_breach',
        'timestamp':    datetime.now(timezone.utc).isoformat(),
        'total':        total,
        'defended':     defended,
        'elapsed_s':    round(elapsed, 2),
        'audit_summary': aud_summary,
        'results':      results,
    }

    path = os.path.join(RESULTS_DIR, 'iam_breach_log.json')
    with open(path, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"\n  Results saved → {path}")
    print(f"\n✅ IAM breach simulation complete.")

    return output


if __name__ == '__main__':
    main()