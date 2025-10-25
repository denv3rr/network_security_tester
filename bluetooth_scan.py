# bluetooth_scan.py
# Placeholder; discovery needs platform-specific libs (e.g., bleak/pybluez).

import logging

def scan_bluetooth(output_queue=None, stop_flag=None, **kwargs):
    try:
        if stop_flag and getattr(stop_flag, "is_set", lambda: False)():
            return {"status": "stopped"}
        msg = "Bluetooth device scan — not implemented."
        logging.info(msg)
        if output_queue: output_queue.put(msg)
        return {"status": "ok", "note": "not implemented"}
    except Exception as e:
        logging.error(f"bluetooth scan error: {e}")
        if output_queue: output_queue.put(f"bluetooth scan error: {e}")
        return {"error": str(e)}
