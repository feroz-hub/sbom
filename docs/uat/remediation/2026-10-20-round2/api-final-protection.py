"""Recheck Round 1 serialization/authorization after the final boundary correction."""
import importlib.util,json
from pathlib import Path
out=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('checks',out/'live-round1-protection.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);m.PHASE='round1-final';m.main()
