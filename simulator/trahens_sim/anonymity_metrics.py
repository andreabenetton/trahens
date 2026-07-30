"""Entropy-based anonymity metrics for classifier confusion matrices.

These metrics complement accuracy. They treat the true route label as the
secret and the classifier output as one observable. The result is conditional
entropy for this declared observer, not a system-wide anonymity theorem.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from math import log2
from typing import Sequence


@dataclass(frozen=True)
class AnonymityMetrics:
    classes: int
    samples: int
    prior_entropy_bits: float
    conditional_entropy_bits: float
    information_leakage_bits: float
    normalized_anonymity: float
    effective_anonymity_set: float
    bayes_vulnerability: float
    min_entropy_bits: float
    effective_min_anonymity_set: float

    def to_dict(self) -> dict[str, int | float]:
        return asdict(self)


def _entropy(probabilities: Sequence[float]) -> float:
    return -sum(value * log2(value) for value in probabilities if value > 0.0)


def confusion_anonymity_metrics(confusion: Sequence[Sequence[int]]) -> AnonymityMetrics:
    if not confusion or any(len(row) != len(confusion) for row in confusion):
        raise ValueError("confusion matrix must be non-empty and square")
    if any(value < 0 for row in confusion for value in row):
        raise ValueError("confusion counts cannot be negative")
    classes = len(confusion)
    samples = sum(sum(row) for row in confusion)
    if samples == 0:
        raise ValueError("confusion matrix must contain observations")

    actual_totals = [sum(row) for row in confusion]
    prior = [value / samples for value in actual_totals]
    prior_entropy = _entropy(prior)

    conditional_entropy = 0.0
    vulnerability = 0.0
    for predicted in range(classes):
        column = [confusion[actual][predicted] for actual in range(classes)]
        column_total = sum(column)
        if column_total == 0:
            continue
        observation_probability = column_total / samples
        posterior = [value / column_total for value in column]
        conditional_entropy += observation_probability * _entropy(posterior)
        vulnerability += observation_probability * max(posterior)

    leakage = max(0.0, prior_entropy - conditional_entropy)
    max_entropy = log2(classes)
    normalized = conditional_entropy / max_entropy if max_entropy else 1.0
    effective = 2.0**conditional_entropy
    min_entropy = -log2(vulnerability)
    return AnonymityMetrics(
        classes=classes,
        samples=samples,
        prior_entropy_bits=prior_entropy,
        conditional_entropy_bits=conditional_entropy,
        information_leakage_bits=leakage,
        normalized_anonymity=normalized,
        effective_anonymity_set=effective,
        bayes_vulnerability=vulnerability,
        min_entropy_bits=min_entropy,
        effective_min_anonymity_set=1.0 / vulnerability,
    )
