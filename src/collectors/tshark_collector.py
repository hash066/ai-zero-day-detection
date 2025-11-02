"""
TShark-based network packet collector.

Supports both live capture from network interfaces and offline pcap file parsing.
Yields normalized packet dictionaries with timestamp and common network fields.
"""

import subprocess
import shlex
import json
import threading
import queue
import logging
import re
import platform
from typing import Generator, Optional, Dict, Any, List
from pathlib import Path

logger = logging.getLogger(__name__)


class TsharkCollector:
    """
    Resilient tshark-based network packet collector.
    
    Modes:
     - Live capture: captures from network interface using tshark
     - Offline: reads and parses pcap/pcapng files
    
    Yields packet dictionaries with:
     - ts: float epoch timestamp
     - src_ip, dst_ip, src_port, dst_port
     - protocol: highest-level protocol detected
     - raw_bytes: packet length in bytes
     - tshark: full tshark JSON object for advanced field extraction
    """
    
    def __init__(
        self,
        interface: Optional[str] = None,
        pcap_file: Optional[str] = None,
        display_filter: Optional[str] = None,
        tshark_path: str = "tshark",
        capture_filter: Optional[str] = None,
        buffer_size: int = 1000
    ):
        """
        Initialize TsharkCollector.
        
        Args:
            interface: Network interface name for live capture (e.g., 'eth0', 'Wi-Fi')
                      On Windows, can be interface name or number (will auto-resolve)
            pcap_file: Path to pcap file for offline analysis
            display_filter: Wireshark display filter (e.g., 'tcp.port == 80')
            tshark_path: Path to tshark executable
            capture_filter: BPF capture filter for live mode (e.g., 'port 443')
            buffer_size: Queue buffer size for live capture
        """
        if not (interface or pcap_file):
            raise ValueError("Provide either interface (live) or pcap_file (offline).")
        
        self.interface = interface
        self.pcap_file = pcap_file
        self.display_filter = display_filter
        self.capture_filter = capture_filter
        self.tshark_path = tshark_path
        self.buffer_size = buffer_size
        self._proc = None
        self._stop_event = threading.Event()
        self._reader_thread = None
        
        # Resolve interface name to number on Windows
        if self.interface and platform.system() == "Windows":
            self.interface = self._resolve_interface_on_windows(self.interface)
    
    def _resolve_interface_on_windows(self, interface_input: str) -> str:
        """
        Resolve interface name to interface number on Windows.
        
        On Windows, tshark requires interface numbers or full device paths.
        This method converts friendly names like 'Wi-Fi' to interface numbers.
        
        Args:
            interface_input: Interface name or number
            
        Returns:
            Interface identifier that tshark can use
        """
        # If already a number, return as-is
        if interface_input.isdigit():
            return interface_input
            
        try:
            # Run tshark -D to list interfaces
            result = subprocess.run(
                [self.tshark_path, "-D"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                logger.warning(f"Failed to list interfaces: {result.stderr}")
                return interface_input
            
            # Parse output: "1. \Device\NPF_... (Wi-Fi)"
            # Match pattern: <number>. ... (<name>)
            pattern = re.compile(r'^\s*(\d+)\.\s+.*?\(([^)]+)\)', re.MULTILINE)
            
            for match in pattern.finditer(result.stdout):
                interface_num = match.group(1)
                interface_name = match.group(2)
                
                # Case-insensitive match
                if interface_name.lower() == interface_input.lower():
                    logger.info(f"Resolved interface '{interface_input}' to number {interface_num}")
                    return interface_num
            
            logger.warning(f"Could not resolve interface '{interface_input}', using as-is")
            return interface_input
            
        except Exception as e:
            logger.warning(f"Error resolving interface name: {e}, using as-is")
            return interface_input
        
    def _build_cmd(self) -> List[str]:
        """Build tshark command based on mode and filters."""
        if self.pcap_file:
            # Offline mode: read from file, output as JSON array
            cmd = f'{self.tshark_path} -r "{self.pcap_file}" -T json'
            if self.display_filter:
                cmd += f' -Y "{self.display_filter}"'
        else:
            # Live mode: capture from interface, use EK format for line-by-line JSON
            cmd = f'{self.tshark_path} -i {shlex.quote(str(self.interface))} -l -T ek'
            if self.capture_filter:
                cmd += f' -f "{self.capture_filter}"'
            if self.display_filter:
                cmd += f' -Y "{self.display_filter}"'
        
        return shlex.split(cmd)
    
    @staticmethod
    def _extract_common_fields(tshark_obj: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract common network fields from tshark JSON output.
        
        Handles both standard JSON and EK format variations.
        """
        result = {
            "ts": None,
            "src_ip": None,
            "dst_ip": None,
            "src_port": None,
            "dst_port": None,
            "protocol": None,
            "raw_bytes": None,
            "ttl": None,
            "tcp_flags": {},
            "ip_version": None
        }
        
        # Extract layers from different tshark output formats
        layers = {}
        if isinstance(tshark_obj, dict):
            # EK format: {"_source": {"layers": {...}}}
            if "_source" in tshark_obj and "layers" in tshark_obj["_source"]:
                layers = tshark_obj["_source"]["layers"]
            # Standard JSON format: {"_source": {...layers...}}
            elif "_source" in tshark_obj:
                layers = tshark_obj["_source"]
            # Direct layers format
            elif "layers" in tshark_obj:
                layers = tshark_obj["layers"]
            else:
                layers = tshark_obj
        
        if not layers:
            return result
        
        # Helper to safely extract nested values
        def get_field(layer_name: str, field_name: str, default=None):
            """Extract field from layer, handling lists and nested dicts."""
            layer = layers.get(layer_name, {})
            if not isinstance(layer, dict):
                return default
            
            # Try both formats:
            # 1. EK format: "frame_frame_time_epoch"
            # 2. Standard JSON format: "frame.time_epoch"
            ek_key = f"{layer_name}_{field_name.replace('.', '_')}"
            std_key = field_name
            
            value = layer.get(ek_key) or layer.get(std_key)
            if value is None:
                return default
            
            # Handle tshark's tendency to wrap values in lists
            if isinstance(value, list) and len(value) > 0:
                return value[0]
            return value
        
        # Extract timestamp from frame layer
        # Try to parse as Unix timestamp (milliseconds or seconds)
        # First try top-level timestamp field (EK format)
        frame_time = tshark_obj.get("timestamp")
        if not frame_time:
            frame_time = get_field("frame", "frame.time_epoch")
        
        # Normalize list-like values to a single scalar element
        if isinstance(frame_time, list) and frame_time:
            frame_time = frame_time[0]
        
        if frame_time is not None:
            try:
                # Accept numeric types and numeric strings, coerce to float
                if isinstance(frame_time, (int, float)):
                    ts = float(frame_time)
                elif isinstance(frame_time, str):
                    ts = float(frame_time)
                else:
                    # Fallback: try to coerce via string representation
                    ts = float(str(frame_time))
                # If timestamp is in milliseconds (> 10 billion), convert to seconds
                if ts > 10_000_000_000:
                    ts = ts / 1000.0
                result["ts"] = ts
            except (ValueError, TypeError):
                # Try parsing as ISO format string
                try:
                    from datetime import datetime
                    if isinstance(frame_time, str):
                        dt = datetime.fromisoformat(frame_time.replace('Z', '+00:00'))
                        result["ts"] = dt.timestamp()
                except Exception:
                    logger.debug(f"Failed to parse timestamp: {frame_time}")
        
        # Extract packet length
        frame_len = get_field("frame", "frame.len")
        if frame_len:
            try:
                result["raw_bytes"] = int(frame_len)
            except (ValueError, TypeError):
                pass
        
        # Extract IP layer fields
        ip_layer = layers.get("ip", {})
        if isinstance(ip_layer, dict):
            result["src_ip"] = get_field("ip", "ip.src")
            result["dst_ip"] = get_field("ip", "ip.dst")
            result["ttl"] = get_field("ip", "ip.ttl")
            result["ip_version"] = 4
        
        # Check for IPv6
        ipv6_layer = layers.get("ipv6", {})
        if isinstance(ipv6_layer, dict):
            result["src_ip"] = result["src_ip"] or get_field("ipv6", "ipv6.src")
            result["dst_ip"] = result["dst_ip"] or get_field("ipv6", "ipv6.dst")
            result["ttl"] = get_field("ipv6", "ipv6.hlim")
            result["ip_version"] = 6
        
        # Extract transport layer ports
        tcp_layer = layers.get("tcp", {})
        if isinstance(tcp_layer, dict):
            result["src_port"] = get_field("tcp", "tcp.srcport")
            result["dst_port"] = get_field("tcp", "tcp.dstport")
            result["protocol"] = "TCP"
            
            # Extract TCP flags
            flags = get_field("tcp", "tcp.flags")
            if flags:
                try:
                    flags_int = int(flags, 16) if isinstance(flags, str) else int(flags)
                    result["tcp_flags"] = {
                        "fin": bool(flags_int & 0x01),
                        "syn": bool(flags_int & 0x02),
                        "rst": bool(flags_int & 0x04),
                        "psh": bool(flags_int & 0x08),
                        "ack": bool(flags_int & 0x10),
                        "urg": bool(flags_int & 0x20),
                        "ece": bool(flags_int & 0x40),
                        "cwr": bool(flags_int & 0x80)
                    }
                except (ValueError, TypeError):
                    pass
        
        udp_layer = layers.get("udp", {})
        if isinstance(udp_layer, dict):
            result["src_port"] = result["src_port"] or get_field("udp", "udp.srcport")
            result["dst_port"] = result["dst_port"] or get_field("udp", "udp.dstport")
            result["protocol"] = result["protocol"] or "UDP"
        
        # Detect application layer protocols (ordered by specificity)
        protocol_checks = [
            ("http", "HTTP"),
            ("https", "HTTPS"),
            ("tls", "TLS"),
            ("dns", "DNS"),
            ("dhcp", "DHCP"),
            ("smtp", "SMTP"),
            ("ssh", "SSH"),
            ("telnet", "Telnet"),
            ("ftp", "FTP"),
            ("mqtt", "MQTT"),
            ("coap", "CoAP"),
            ("arp", "ARP"),
            ("icmp", "ICMP"),
            ("icmpv6", "ICMPv6"),
            ("igmp", "IGMP")
        ]
        
        for layer_key, proto_name in protocol_checks:
            if layer_key in layers:
                result["protocol"] = proto_name
                break
        
        # Convert port numbers to integers
        if result["src_port"]:
            try:
                result["src_port"] = int(result["src_port"])
            except (ValueError, TypeError):
                result["src_port"] = None
        
        if result["dst_port"]:
            try:
                result["dst_port"] = int(result["dst_port"])
            except (ValueError, TypeError):
                result["dst_port"] = None
        
        return result
    
    def stream_packets(self) -> Generator[Dict[str, Any], None, None]:
        """
        Stream packets as normalized dictionaries.
        
        Yields:
            Dict containing: ts, src_ip, dst_ip, src_port, dst_port, protocol,
            raw_bytes, tcp_flags, and full tshark JSON object
        """
        cmd = self._build_cmd()
        
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
        except FileNotFoundError as e:
            raise RuntimeError(
                f"tshark not found at '{self.tshark_path}'. "
                "Install Wireshark or set correct path."
            ) from e
        except Exception as e:
            raise RuntimeError(f"Failed to start tshark: {e}") from e
        
        logger.info(f"Started tshark collector: {' '.join(cmd)}")
        
        if self.pcap_file:
            # Offline mode: read entire JSON array
            yield from self._stream_offline()
        else:
            # Live mode: stream line-by-line JSON
            yield from self._stream_live()
    
    def _stream_offline(self) -> Generator[Dict[str, Any], None, None]:
        """Stream packets from pcap file."""
        try:
            raw_output = self._proc.stdout.read()
            self._proc.stdout.close()
            
            if not raw_output.strip():
                logger.warning(f"No output from tshark for file: {self.pcap_file}")
                return
            
            try:
                packets = json.loads(raw_output)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse tshark JSON output: {e}")
                return
            
            if not isinstance(packets, list):
                packets = [packets]
            
            for pkt in packets:
                if self._stop_event.is_set():
                    break
                
                common_fields = self._extract_common_fields(pkt)
                yield {**common_fields, "tshark": pkt}
            
            logger.info(f"Finished processing {len(packets)} packets from {self.pcap_file}")
        
        finally:
            self._proc.wait(timeout=2)
    
    def _stream_live(self) -> Generator[Dict[str, Any], None, None]:
        """Stream packets from live capture."""
        packet_queue = queue.Queue(maxsize=self.buffer_size)
        
        def reader_thread():
            """Background thread to read tshark output."""
            try:
                for line in self._proc.stdout:
                    if self._stop_event.is_set():
                        break
                    
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Skip EK index lines ({"index": {...}})
                    if line.startswith('{"index":'):
                        continue
                    
                    try:
                        packet_queue.put(line, timeout=1)
                    except queue.Full:
                        logger.warning("Packet queue full, dropping packet")
            except Exception as e:
                logger.error(f"Reader thread error: {e}")
            finally:
                packet_queue.put(None)  # Signal EOF
        
        self._reader_thread = threading.Thread(target=reader_thread, daemon=True)
        self._reader_thread.start()
        
        packet_count = 0
        try:
            while True:
                try:
                    line = packet_queue.get(timeout=0.5)
                except queue.Empty:
                    if self._stop_event.is_set():
                        break
                    continue
                
                if line is None:  # EOF signal
                    break
                
                try:
                    pkt = json.loads(line)
                    common_fields = self._extract_common_fields(pkt)
                    packet_count += 1
                    yield {**common_fields, "tshark": pkt}
                except json.JSONDecodeError as e:
                    logger.debug(f"Failed to parse JSON line: {e}")
                    continue
                
                if self._stop_event.is_set():
                    break
        
        finally:
            logger.info(f"Live capture stopped. Processed {packet_count} packets")
            self.stop()
    
    def stop(self):
        """Gracefully stop the collector."""
        logger.info("Stopping tshark collector...")
        self._stop_event.set()
        
        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                logger.warning("tshark did not terminate, killing process")
                self._proc.kill()
                self._proc.wait()
            except Exception as e:
                logger.error(f"Error stopping tshark: {e}")
            finally:
                self._proc = None
        
        if self._reader_thread and self._reader_thread.is_alive():
            self._reader_thread.join(timeout=1)
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()
        return False


def list_interfaces() -> List[str]:
    """
    List available network interfaces using tshark.
    
    Returns:
        List of interface names
    """
    try:
        result = subprocess.run(
            ["tshark", "-D"],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        interfaces = []
        for line in result.stdout.strip().split('\n'):
            # Format: "1. eth0 (Ethernet)"
            if line and '.' in line:
                parts = line.split('.', 1)
                if len(parts) > 1:
                    # Extract interface name
                    iface = parts[1].strip().split()[0]
                    interfaces.append(iface)
        
        return interfaces
    
    except Exception as e:
        logger.error(f"Failed to list interfaces: {e}")
        return []


if __name__ == "__main__":
    # Example usage
    import sys
    
    logging.basicConfig(level=logging.INFO)
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  Live capture: python tshark_collector.py --interface <iface>")
        print("  Offline: python tshark_collector.py --pcap <file.pcap>")
        print("\nAvailable interfaces:")
        for iface in list_interfaces():
            print(f"  - {iface}")
        sys.exit(1)
    
    if sys.argv[1] == "--interface":
        collector = TsharkCollector(interface=sys.argv[2])
    elif sys.argv[1] == "--pcap":
        collector = TsharkCollector(pcap_file=sys.argv[2])
    else:
        print("Unknown option")
        sys.exit(1)
    
    try:
        count = 0
        for packet in collector.stream_packets():
            print(f"Packet {count}: {packet['ts']:.6f} | "
                  f"{packet['src_ip']}:{packet['src_port']} -> "
                  f"{packet['dst_ip']}:{packet['dst_port']} | "
                  f"{packet['protocol']}")
            count += 1
            if count >= 10:  # Show first 10 packets
                break
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        collector.stop()