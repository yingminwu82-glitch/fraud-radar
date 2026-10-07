from collections import defaultdict

from app.schemas.risk import NormalizedSignal


def aggregate_signals(signals: list[NormalizedSignal]):
    """Group duplicate factor detections; use maximum severity so duplicates do not inflate risk."""
    grouped = defaultdict(list)
    for signal in signals:
        if not signal.missing:
            grouped[signal.category].append(signal)
    result = {}
    for category, items in grouped.items():
        representative = max(items, key=lambda item: item.risk_score * item.confidence)
        result[category] = {
            "risk_score": max(item.risk_score for item in items),
            "providers": sorted({item.provider for item in items}),
            "factors": sorted({item.factor for item in items}),
            "raw_signal": ", ".join(f"{item.factor}={item.value}" for item in items),
            "agreement": len({item.provider for item in items}),
            "confidence": representative.confidence,
        }
    return result
