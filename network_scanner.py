# network_scanner.py
# Network metadata/summary; tolerant to extra kwargs and supports stop_flag.

import logging
import platform
import socket

def run_network_metadata_scan(output_queue=None, stop_flag=None, **kwargs):
    """
    Prints basic hostname/IP info and OS; extend here for richer metadata later.
    """
    try:
        if stop_flag and getattr(stop_flag, "is_set", lambda: False)():
            return {"status": "stopped"}

        hostname = socket.gethostname()
        try:
            ip = socket.gethostbyname(hostname)
        except Exception:
            ip = "Unknown"

        os_name = platform.platform()
        msg = f"Host: {hostname} | IP: {ip} | OS: {os_name}"
        logging.info(msg)
        if output_queue: output_queue.put(msg)
        return {"hostname": hostname, "ip": ip, "os": os_name}
    except Exception as e:
        logging.error(f"network metadata error: {e}")
        if output_queue: output_queue.put(f"network metadata error: {e}")
        return {"error": str(e)}
