import sys
import os

# Make the project root importable so that samples can be reached via
# importlib without package-level __init__.py files.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
