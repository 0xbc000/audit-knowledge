"""
Smart Contract Auditor - Custom Slither Detectors

This package contains custom Slither detectors for:
- MEV vulnerabilities
- L2-specific risks
- Emerging protocol patterns (Restaking, Intent, Points)
- Admin security (L2 focus, based on real exploits)
- Cryptographic primitives (BN254/BLS, ZK proofs)
- FCFS/Tiering systems (ranking, boundaries)

Usage:
    slither . --detector-path /path/to/slither-detectors

Author: Smart Contract Auditor (ClawdEva)
Version: 1.2.0
"""

from .mev_risks import DETECTORS as MEV_DETECTORS
from .l2_specific import DETECTORS as L2_DETECTORS
from .emerging_protocols import DETECTORS as EMERGING_DETECTORS
from .admin_security import DETECTORS as ADMIN_DETECTORS
from .cryptographic_primitives import DETECTORS as CRYPTO_DETECTORS
from .fcfs_tiering import DETECTORS as FCFS_DETECTORS

# Combine all detectors for easy registration
ALL_DETECTORS = (
    MEV_DETECTORS + 
    L2_DETECTORS + 
    EMERGING_DETECTORS + 
    ADMIN_DETECTORS +
    CRYPTO_DETECTORS +
    FCFS_DETECTORS
)

__version__ = "1.2.0"
__all__ = [
    "MEV_DETECTORS",
    "L2_DETECTORS", 
    "EMERGING_DETECTORS",
    "ADMIN_DETECTORS",
    "CRYPTO_DETECTORS",
    "FCFS_DETECTORS",
    "ALL_DETECTORS",
]
