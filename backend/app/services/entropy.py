"""
Shannon entropy calculation service.

Shannon entropy measures the randomness / information density of data.
High entropy (>7.5 on the 0-8 scale for byte data) is a strong indicator
of encrypted, compressed, or packed content – all common in malware
that tries to evade signature-based detection.

Formula:  H = -Σ p(x) * log2( p(x) )   for each byte value x ∈ [0, 255]
"""

from __future__ import annotations

import math
import logging
from collections import Counter

logger = logging.getLogger(__name__)


def calculate_entropy(file_bytes: bytes) -> float:
    """
    Calculate the Shannon entropy of a byte sequence.

    Returns a float in [0.0 , 8.0].
    - 0.0  → completely uniform (e.g., all null bytes)
    - ~4.5 → typical English text
    - ~7.0 → compressed / structured binary
    - >7.5 → likely encrypted or packed (suspicious)
    """
    if not file_bytes:
        return 0.0

    length = len(file_bytes)
    freq = Counter(file_bytes)

    entropy = 0.0
    for count in freq.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    entropy = round(entropy, 4)
    logger.info("Entropy calculated: %.4f (length=%d bytes)", entropy, length)
    return entropy
