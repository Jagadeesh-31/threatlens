"""
run_pipeline.py — Wrapper script allowing pipeline execution from src/ directory.
"""

import sys
from pathlib import Path

# Add project root to path and delegate to main run_pipeline.py
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from run_pipeline import main

if __name__ == "__main__":
    main()
