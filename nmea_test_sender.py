#!/usr/bin/env python3
"""
nmea_test_sender.py  -  Broadcast fake NMEA0183 sentences over UDP.

Tests the Network Analyser NMEA Scope page by sending 7 sentence types
on both UDP port 2000 and port 10110 (IEC 61162-1 standard).

Usage:
    python nmea_test_sender.py                          # broadcast default
    python nmea_test_sender.py --host 192.168.1.255     # subnet broadcast
    python nmea_test_sender.py --interval 0.5           # 2 Hz
    python nmea_test_sender.py --ports 10110            # single port
"""

import socket
import time
import datetime
import math
import argparse

DEFAULT_PORTS     = [2000, 10110]
DEFAULT_BROADCAST = "255.255.255.255"


# ---------------------------------------------------------------------------
# NMEA helpers
# ---------------------------------------------------------------------------

def checksum(body: str) -> str:
    """XOR of every character between $ and * (exclusive)."""
    result = 0
    for c in body:
        result ^= ord(c)
    return f"{result:02X}"


def sentence(*fields) -> bytes:
    """Build a complete NMEA sentence: $fields*CS\r\n as ASCII bytes."""
    body = ",".join(str(f) for f in fields)
    return f"${body}*{checksum(body)}\r\n".encode("ascii")


# ---------------------------------------------------------------------------
# Sentence generators
# ---------------------------------------------------------------------------

def _latlon(lat: float, lon: float):
    """Return (lat_str, lat_hem, lon_str, lon_hem) in NMEA ddmm.mmmm format."""
    lat_d = int(abs(lat)); lat_m = (abs(lat) - lat_d) * 60
    lon_d = int(abs(lon)); lon_m = (abs(lon) - lon_d) * 60
    return (
        f"{lat_d:02d}{lat_m:07.4f}", "N" if lat >= 0 else "S",
        f"{lon_d:03d}{lon_m:07.4f}", "E" if lon >= 0 else "W",
    )


def make_sentences(t: datetime.datetime, lat: float, lon: float,
                   speed_kn: float, heading: float,
                   depth_m: float, wind_angle: float, wind_speed_kn: float) -> list:
    ts = t.strftime("%H%M%S.00")
    ds = t.strftime("%d%m%y")
    la, lah, lo, loh = _latlon(lat, lon)

    return [
        # GPRMC  - Recommended Minimum Navigation Info
        sentence("GPRMC", ts, "A", la, lah, lo, loh,
                 f"{speed_kn:.1f}", f"{heading:.1f}", ds, "000.0", "W"),

        # GPGGA  - GPS Fix Data
        sentence("GPGGA", ts, la, lah, lo, loh,
                 "1", "08", "1.0", "2.3", "M", "46.9", "M", "", ""),

        # GPGLL  - Geographic Position
        sentence("GPGLL", la, lah, lo, loh, ts, "A"),

        # GPVTG  - Course / Speed Over Ground
        sentence("GPVTG", f"{heading:.1f}", "T", "", "M",
                 f"{speed_kn:.1f}", "N", f"{speed_kn * 1.852:.1f}", "K"),

        # IIMWV  - Wind Speed and Angle (relative)
        sentence("IIMWV", f"{wind_angle:.1f}", "R", f"{wind_speed_kn:.1f}", "N", "A"),

        # SDDBT  - Depth Below Transducer
        sentence("SDDBT", f"{depth_m * 3.28084:.1f}", "f",
                 f"{depth_m:.1f}", "M", f"{depth_m / 1.8288:.1f}", "F"),

        # HCHDG  - Compass Heading
        sentence("HCHDG", f"{heading:.1f}", "", "", "0.0", "W"),
    ]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Broadcast NMEA0183 UDP sentences to test the Network Analyser NMEA Scope."
    )
    parser.add_argument("--host",     default=DEFAULT_BROADCAST,
                        help=f"Destination IP (default: {DEFAULT_BROADCAST})")
    parser.add_argument("--ports",    nargs="+", type=int, default=DEFAULT_PORTS,
                        help=f"UDP ports (default: {DEFAULT_PORTS})")
    parser.add_argument("--interval", type=float, default=1.0,
                        help="Seconds between bursts (default: 1.0)")
    parser.add_argument("--lat",      type=float, default=50.5074,
                        help="Starting latitude  (default: 50.5074)")
    parser.add_argument("--lon",      type=float, default=-0.1278,
                        help="Starting longitude (default: -0.1278)")
    parser.add_argument("--bind",     default="",
                        help="Local IP to bind to (force a specific network interface, e.g. 192.168.0.10)")
    parser.add_argument("--bad",      action="store_true",
                        help="Occasionally inject sentences with a corrupt checksum (tests BAD display)")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if args.bind:
        sock.bind((args.bind, 0))

    print("NMEA0183 UDP Test Sender")
    print(f"  Destination : {args.host}")
    print(f"  Ports       : {args.ports}")
    print(f"  Bind        : {args.bind if args.bind else '(any interface)'}")
    print(f"  Interval    : {args.interval}s")
    print(f"  Position    : {args.lat:.4f}, {args.lon:.4f}")
    print(f"  Bad-CS test : {'ON' if args.bad else 'OFF'}")
    print(f"\nSentences per burst: 7 types  ({', '.join(['GPRMC','GPGGA','GPGLL','GPVTG','IIMWV','SDDBT','HCHDG'])})")
    print("Press Ctrl+C to stop.\n")

    tick = 0
    total_sent = 0
    start = time.time()

    try:
        while True:
            now      = datetime.datetime.utcnow()
            heading  = (tick * 2)        % 360
            wind_ang = (tick * 3 + 45)   % 360
            wind_spd = 8.0  + 4.0  * math.sin(math.radians(tick * 5))
            speed    = 5.0  + 2.0  * math.sin(math.radians(tick * 7))
            depth    = 10.0 + 3.0  * math.sin(math.radians(tick * 11))

            sentences = make_sentences(now, args.lat, args.lon,
                                       speed, heading, depth, wind_ang, wind_spd)

            # Optionally corrupt one sentence every 10 bursts to test BAD display
            if args.bad and tick % 10 == 0:
                bad = sentences[0].decode("ascii").replace("*", "*XX", 1).encode("ascii")
                sentences[0] = bad

            for port in args.ports:
                for s in sentences:
                    sock.sendto(s, (args.host, port))

            total_sent += len(sentences) * len(args.ports)
            elapsed = time.time() - start

            print(
                f"\r  [{now.strftime('%H:%M:%S')}]"
                f"  hdg={heading:5.1f}°  spd={speed:.1f}kn  dep={depth:.1f}m"
                f"  wind={wind_ang:.0f}°/{wind_spd:.1f}kn"
                f"  |  {total_sent} datagrams  {elapsed:.0f}s",
                end="", flush=True,
            )

            tick += 1
            time.sleep(args.interval)

    except KeyboardInterrupt:
        print(f"\n\nStopped after {time.time() - start:.1f}s, {total_sent} datagrams sent.")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
