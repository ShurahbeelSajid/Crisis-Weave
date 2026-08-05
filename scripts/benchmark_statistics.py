"""Dependency-free, deterministic event-cluster uncertainty estimates."""

from __future__ import annotations

import math
import random
import statistics
from collections.abc import Mapping
from typing import Any

JsonObject = dict[str, Any]


class BootstrapError(ValueError):
    """Raised when an event-level bootstrap input is invalid."""


def _validated_samples(samples: int) -> int:
    invalid_type = isinstance(samples, bool) or not isinstance(samples, int)
    if invalid_type or not 1_000 <= samples <= 1_000_000:
        raise BootstrapError("bootstrap samples must be an integer between 1,000 and 1,000,000")
    return samples


def _percentile(ordered: list[float], probability: float) -> float:
    return ordered[max(0, math.ceil(probability * len(ordered)) - 1)]


def event_bootstrap_confidence_intervals(
    per_event: Mapping[str, Mapping[str, float | int | None]],
    *,
    samples: int = 10_000,
    seed: int = 24_051,
) -> JsonObject:
    """Bootstrap whole disasters and report event-macro percentile intervals."""

    _validated_samples(samples)
    if len(per_event) < 2:
        raise BootstrapError("event bootstrap requires at least two events")
    event_ids = sorted(per_event)
    metric_names = sorted({name for metrics in per_event.values() for name in metrics})
    rng = random.Random(seed)  # nosec B311  # noqa: S311 -- deterministic bootstrap
    intervals: JsonObject = {}
    for metric in metric_names:
        available = [
            float(value)
            for event_id in event_ids
            if isinstance((value := per_event[event_id].get(metric)), (int, float))
        ]
        if len(available) < 2:
            intervals[metric] = None
            continue
        draws: list[float] = []
        for _ in range(samples):
            sampled = [
                per_event[event_ids[rng.randrange(len(event_ids))]].get(metric) for _ in event_ids
            ]
            numeric = [float(value) for value in sampled if isinstance(value, (int, float))]
            if numeric:
                draws.append(statistics.fmean(numeric))
        draws.sort()
        intervals[metric] = {
            "estimate_event_macro_mean": round(statistics.fmean(available), 6),
            "ci95_low": round(_percentile(draws, 0.025), 6),
            "ci95_high": round(_percentile(draws, 0.975), 6),
            "contributing_events": len(available),
        }
    return {
        "method": "event_cluster_percentile_bootstrap",
        "samples": samples,
        "seed": seed,
        "event_count": len(event_ids),
        "intervals": intervals,
    }


def paired_event_delta_confidence_intervals(
    candidate: Mapping[str, Mapping[str, float | int | None]],
    baseline: Mapping[str, Mapping[str, float | int | None]],
    *,
    samples: int = 10_000,
    seed: int = 24_051,
) -> JsonObject:
    """Paired event bootstrap for candidate-minus-baseline ablation effects."""

    _validated_samples(samples)
    if set(candidate) != set(baseline) or len(candidate) < 2:
        raise BootstrapError("paired bootstrap requires the same two or more event IDs")
    event_ids = sorted(candidate)
    metrics = sorted(
        {name for values in candidate.values() for name in values}
        & {name for values in baseline.values() for name in values}
    )
    rng = random.Random(seed)  # nosec B311  # noqa: S311 -- deterministic bootstrap
    intervals: JsonObject = {}
    for metric in metrics:
        deltas = {
            event_id: float(candidate_value) - float(baseline_value)
            for event_id in event_ids
            if isinstance((candidate_value := candidate[event_id].get(metric)), (int, float))
            and isinstance((baseline_value := baseline[event_id].get(metric)), (int, float))
        }
        if len(deltas) < 2:
            intervals[metric] = None
            continue
        paired_ids = sorted(deltas)
        draws = sorted(
            statistics.fmean(deltas[paired_ids[rng.randrange(len(paired_ids))]] for _ in paired_ids)
            for _ in range(samples)
        )
        intervals[metric] = {
            "estimate_event_macro_delta": round(statistics.fmean(deltas.values()), 6),
            "ci95_low": round(_percentile(draws, 0.025), 6),
            "ci95_high": round(_percentile(draws, 0.975), 6),
            "paired_events": len(deltas),
        }
    return {
        "method": "paired_event_cluster_percentile_bootstrap",
        "samples": samples,
        "seed": seed,
        "event_count": len(event_ids),
        "intervals": intervals,
    }
