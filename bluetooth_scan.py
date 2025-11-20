# bluetooth_scan.py
# Asynchronous Bluetooth Low Energy (BLE) scanner using Bleak.
# Wrapped in a synchronous function for compatibility with the threaded orchestrator.

import asyncio
import logging
import platform

try:
    from bleak import BleakScanner
    BLEAK_AVAILABLE = True
except ImportError:
    BLEAK_AVAILABLE = False

def _async_scan_wrapper(duration=5.0):
    """Helper to run async bleak scan in a sync context."""
    async def perform():
        # We must ask for advertisement data to get RSSI in newer Bleak versions
        devices = await BleakScanner.discover(timeout=duration, return_adv=True)
        return devices
    
    try:
        # Check for existing loop
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            future = asyncio.run_coroutine_threadsafe(perform(), loop)
            return future.result()
        else:
            return asyncio.run(perform())
    except Exception as e:
        logging.error(f"Async scan loop error: {e}")
        return {}

def scan_bluetooth(output_queue=None, stop_flag=None, **kwargs):
    """
    Scans for BLE devices.
    """
    if not BLEAK_AVAILABLE:
        msg = "Module 'bleak' not found. Install with: pip install bleak"
        logging.error(msg)
        if output_queue: output_queue.put(msg)
        return {"error": "missing_dependency", "note": msg}

    if stop_flag and getattr(stop_flag, "is_set", lambda: False)():
        return {"status": "stopped"}

    logging.info("Starting Bluetooth scan (5s)...")
    if output_queue: output_queue.put("Scanning Bluetooth devices (5s)...")

    try:
        # Run the scan - returns dict: { "address": (device, adv_data) }
        found_devices = _async_scan_wrapper(duration=5.0)
        
        results = []
        
        # Handle both old and new bleak return types just in case, but target new dict format
        if isinstance(found_devices, dict):
            for key, val in found_devices.items():
                # val is tuple (device, advertisement_data)
                d, adv = val
                
                name = d.name or adv.local_name or "Unknown"
                address = d.address
                rssi = adv.rssi
                
                results.append({
                    "name": name,
                    "address": address,
                    "rssi": rssi,
                    "metadata": adv.service_data
                })
                
                log_line = f"  [BLE] {name} ({address}) Signal: {rssi}dBm"
                logging.info(log_line)
                if output_queue: output_queue.put(log_line)
        
        elif isinstance(found_devices, list):
            # Fallback for older bleak versions returning list of devices
            for d in found_devices:
                name = d.name or "Unknown"
                address = d.address
                # old bleak attached rssi to device, new one doesn't. handle safely.
                rssi = getattr(d, "rssi", "?")
                
                results.append({
                    "name": name,
                    "address": address,
                    "rssi": rssi,
                    "metadata": d.metadata
                })
                
                log_line = f"  [BLE] {name} ({address}) Signal: {rssi}dBm"
                logging.info(log_line)
                if output_queue: output_queue.put(log_line)

        summary = f"Bluetooth scan finished. Found {len(results)} devices."
        if output_queue: output_queue.put(summary)
        
        return {"devices": results, "count": len(results)}

    except Exception as e:
        logging.error(f"Bluetooth scan error: {e}")
        if output_queue: output_queue.put(f"Bluetooth scan error: {e}")
        return {"error": str(e)}