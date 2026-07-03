"""
scoring.py: heuristic risk scoring for decoded IOCTLs.

Severity is derived from the IOCTL transfer method and access mode (the fields
that map to real high-severity driver bug classes) and bumped when the handling
function is known to reach a dangerous sink (see signatures.DANGEROUS_SINKS and the
call-chain tracer).
"""

from __future__ import annotations

from typing import Dict, List, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from DriverBuddyReloaded.reporting import Reporter

from DriverBuddyReloaded import config, signatures as sig

try:
    import ida_funcs
    import idc
    import idautils
    from DriverBuddyReloaded.callchain import transitive_callees
    from DriverBuddyReloaded.reporting import Finding
except Exception:  # pragma: no cover - only when imported outside IDA without stubs
    ida_funcs = None
    idc = None
    idautils = None
    transitive_callees = None
    Finding = None


def _inline_reach(case_ranges, opcode_findings):
    """Per-case attribution for a monolithic dispatcher whose case does its work
    inline (no callee handler to attribute to).  Scans the case's own address
    span(s) for dangerous-sink call sites and inline privileged opcodes and returns
    (sink_severity, {sink_names}, opcode_severity) found *within those spans*, so a
    benign case is not tarred with sinks that only sibling cases reach.

    *case_ranges* is a list of [lo, hi) spans: a single IOCTL can map to several
    case bodies (e.g. a `goto`-shared port-I/O handler), and the attribution is the
    union of them all.
    """
    sink_sev = 0
    sink_names = set()
    opc_sev = 0
    for lo, hi in case_ranges:
        for f in opcode_findings:
            if f.ea and lo <= f.ea < hi:
                opc_sev = max(opc_sev, f.severity)
        if idc is None:
            continue
        try:
            ea = lo
            while ea != idc.BADADDR and ea < hi:
                if idc.print_insn_mnem(ea) == "call":
                    name = (idc.print_operand(ea, 0) or "").split(":")[-1]
                    if name.startswith("__imp_"):
                        name = name[len("__imp_"):]
                    if name in sig.DANGEROUS_SINKS:
                        sink_sev = max(sink_sev, sig.DANGEROUS_SINKS[name])
                        sink_names.add(name)
                nxt = idc.next_head(ea, hi)
                if nxt <= ea:
                    break
                ea = nxt
        except Exception:
            pass
    return sink_sev, sink_names, opc_sev


def _points_to_severity(points):
    if points >= 5:
        return config.SEV_HIGH
    if points >= 3:
        return config.SEV_MEDIUM
    if points >= 1:
        return config.SEV_LOW
    return config.SEV_INFO


def score_ioctl(decoded: Dict[str, object]) -> Tuple[int, List[str]]:
    """
    Compute (severity, reasons) for a decoded IOCTL dict (see ioctl_decoder.decode).
    METHOD_NEITHER + FILE_ANY_ACCESS is the canonical arbitrary-r/w shape and scores
    highest; CRITICAL is reserved for handlers that additionally reach a sink.
    """
    reasons = []
    points = 0
    method = decoded.get("method_name")
    access = decoded.get("access_name")
    m = config.METHOD_RISK.get(method, 0)
    if m:
        points += m
        reasons.append("{} (+{})".format(method, m))
    a = config.ACCESS_RISK.get(access, 0)
    if a:
        points += a
        reasons.append("{} (+{})".format(access, a))
    return _points_to_severity(points), reasons


def score(rep: Reporter) -> None:
    """
    Assign severities to every IOCTL finding in `rep`, in place, and record the
    contributing reasons under data["risk_reasons"]. Uses any call-chain findings
    to bump handlers that reach a dangerous sink.
    :param rep: Reporter instance
    """

    ioctls = rep.by_category("ioctl")
    if not ioctls:
        return

    # Highest sink severity reached per function, gathered from call-chain findings.
    sink_by_func = {}
    for f in rep.by_category("callchain"):
        if f.func:
            prev_sev, prev_names = sink_by_func.get(f.func, (0, set()))
            sink_name = f.data.get("sink", "") if f.data else ""
            sink_by_func[f.func] = (
                max(prev_sev, f.severity),
                prev_names | ({sink_name} if sink_name else set()),
            )

    # Privileged inline primitives (wrmsr/rdmsr, port I/O, mov cr*) are opcode
    # findings, not callable sinks, so the call-chain tracer never sees them.
    # Map the function that contains each to its severity so an IOCTL whose
    # handler transitively reaches it (e.g. ALSysIO64's writemsr_wrapper) is
    # scored on that primitive rather than dropping to LOW.
    opcode_sev_by_func = {}
    if ida_funcs is not None:
        for f in rep.by_category("opcode"):
            if not f.ea:
                continue
            fn = ida_funcs.get_func(f.ea)
            if fn:
                opcode_sev_by_func[fn.start_ea] = max(
                    opcode_sev_by_func.get(fn.start_ea, 0), f.severity)
    _opcode_reach_cache = {}

    def _opcode_reach_sev(handler_ea):
        if not opcode_sev_by_func or transitive_callees is None:
            return 0
        if handler_ea in _opcode_reach_cache:
            return _opcode_reach_cache[handler_ea]
        # Reach at least as deep as handler bodies are expanded for the heuristic
        # checks (HANDLER_SEED_DEPTH) so an opcode emitted anywhere in the handler
        # subtree is attributable, regardless of how CALLCHAIN_MAX_DEPTH is tuned.
        # Defaults to CALLCHAIN_MAX_DEPTH (6 >= 4), so unchanged at shipped values.
        reach = transitive_callees(
            {handler_ea}, max(config.CALLCHAIN_MAX_DEPTH, config.HANDLER_SEED_DEPTH))
        best = max((sev for fea, sev in opcode_sev_by_func.items() if fea in reach),
                   default=0)
        _opcode_reach_cache[handler_ea] = best
        return best

    opcode_findings = rep.by_category("opcode")

    for f in ioctls:
        sev, reasons = score_ioctl(f.data)
        method_neither = f.data.get("method_name") == "METHOD_NEITHER"
        handler = f.data.get("handler_name")
        handler_ea = f.data.get("handler_ea")
        case_range = f.data.get("case_range")

        if handler is not None:
            # Precise per-case attribution: this IOCTL routes to a resolved handler.
            attribution = "handler"
            entry = sink_by_func.get(handler)
            if entry and entry[0]:
                sink_sev, sink_names = entry
                sinks_sorted = sorted(sink_names)
                reasons.extend("-> {}".format(s) for s in sinks_sorted)
                f.data["sinks"] = sinks_sorted
                f.detail += " | sinks: " + ", ".join(sinks_sorted)
                sev = max(sev, sink_sev)
                if method_neither:  # raw user pointer straight into a sink: worst case
                    sev = config.SEV_CRITICAL
            if handler_ea:
                opc_sev = _opcode_reach_sev(handler_ea)
                if opc_sev:
                    sev = max(sev, opc_sev)
                    reasons.append("-> privileged opcode/instruction")
        elif case_range:
            # Per-case inline attribution: attribute only sinks/opcodes that live
            # inside this switch case's own body, not the whole dispatcher's union.
            attribution = "case-inline"
            sink_sev, sink_names, opc_sev = _inline_reach(case_range, opcode_findings)
            if sink_sev:
                sinks_sorted = sorted(sink_names)
                reasons.extend("-> {}".format(s) for s in sinks_sorted)
                f.data["sinks"] = sinks_sorted
                f.detail += " | sinks (in-case): " + ", ".join(sinks_sorted)
                sev = max(sev, sink_sev)
                if method_neither:  # the sink is in THIS case: precise, so worst case
                    sev = config.SEV_CRITICAL
            if opc_sev:
                sev = max(sev, opc_sev)
                reasons.append("-> privileged opcode/instruction (in-case)")
        else:
            # No per-case information (if-chain dispatcher, or immediate recovery):
            # fall back to the dispatcher-wide sink union, but CAP the bump at HIGH
            # and do NOT force CRITICAL -- the evidence is not attributable to this
            # specific IOCTL, so it must not inflate every code to CRITICAL.
            attribution = "dispatcher-wide"
            entry = sink_by_func.get(f.func)
            if entry and entry[0]:
                sink_sev, sink_names = entry
                sinks_sorted = sorted(sink_names)
                reasons.extend("-> {}".format(s) for s in sinks_sorted)
                f.data["sinks"] = sinks_sorted
                f.detail += " | sinks (dispatcher-wide): " + ", ".join(sinks_sorted)
                sev = max(sev, min(sink_sev, config.SEV_HIGH))

        f.data["sink_attribution"] = attribution
        f.severity = config.clamp_severity(sev)
        f.data["risk_reasons"] = reasons

    high = sum(1 for f in ioctls if f.severity >= config.SEV_HIGH)
    rep.info("[>] Risk scoring: {} IOCTL(s) scored, {} High/Critical".format(len(ioctls), high))

    # FN-2: a driver whose whole purpose is arbitrary MSR / physical-memory access
    # (e.g. BS_RVSIO64) can carry a HIGH/CRITICAL inline primitive that no IOCTL was
    # scored against, because the dispatcher-to-primitive path was not established.
    # Surface a driver-level finding so the driver is not left looking benign.
    if Finding is not None:
        prim = [f for f in opcode_findings if f.severity >= config.SEV_HIGH]
        if prim and max((f.severity for f in ioctls), default=0) < config.SEV_HIGH:
            worst = max(prim, key=lambda f: f.severity)
            rep.add(Finding(
                category="heuristic",
                title="Privileged primitive present; IOCTL linkage unconfirmed",
                ea=worst.ea,
                func=worst.func,
                severity=config.SEV_HIGH,
                detail="Driver contains a privileged inline primitive ({}) not linked "
                       "to any scored IOCTL handler; review whether it is reachable "
                       "from the dispatch surface.".format(worst.title)))
