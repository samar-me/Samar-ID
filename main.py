import os
import sys
import importlib.util

samar_id_dir = os.path.join(os.path.dirname(__file__), "core", "samar-id")
if samar_id_dir not in sys.path:
    sys.path.insert(0, samar_id_dir)

target_path = os.path.join(samar_id_dir, "main.py")
spec = importlib.util.spec_from_file_location("samar_id_main", target_path)
module = importlib.util.module_from_spec(spec)
sys.modules["samar_id_main"] = module
spec.loader.exec_module(module)

app = module.app
