"""Frigate NVR: camera names for camera IPs.

Frigate's API (8971) has its own auth off: nftables on the NVR only lets the
Kubernetes range in, which is where this runs. Read-only, GET /api/config.

Cameras usually read from go2rtc (rtsp://REDACTED_IP:8554/<stream>); the stream's
own source URL holds the camera's address. Only that address is kept: the URLs
carry credentials.
"""
from __future__ import annotations

import logging
import os
import re

import requests
from pydantic import BaseModel, ValidationError

from model import Collected, is_usable_ip, verify_ssl

log = logging.getLogger("frigate")
HOST_RE = re.compile(r"//(?:[^/@]*@)?(\d{1,3}(?:\.\d{1,3}){3})")
LOCAL = ("REDACTED_IP", "localhost")


class FfmpegInputRaw(BaseModel):
    path: str = ""


class FfmpegRaw(BaseModel):
    inputs: list[FfmpegInputRaw] = []


class CameraRaw(BaseModel):
    enabled: bool = True
    ffmpeg: FfmpegRaw = FfmpegRaw()


def camera_ips(cfg: dict) -> dict[str, str]:
    """Frigate config -> {camera ip: camera name}."""
    streams = {name: [m.group(1) for u in (urls if isinstance(urls, list) else [urls]) for m in [HOST_RE.search(str(u))] if m]
               for name, urls in ((cfg.get("go2rtc") or {}).get("streams") or {}).items()}
    out: dict[str, str] = {}
    for name, raw in (cfg.get("cameras") or {}).items():
        try:
            cam = CameraRaw.model_validate(raw)
        except ValidationError as e:
            log.warning("skipping malformed camera %r: %s", name, e)
            continue
        if not cam.enabled:
            continue
        ips: list[str] = []
        for inp in cam.ffmpeg.inputs:
            path = inp.path
            m = HOST_RE.search(path) or re.search(r"//(localhost)", path)
            if m and m.group(1) in LOCAL:                     # via go2rtc: the stream's source
                ips += streams.get(path.rstrip("/").rsplit("/", 1)[-1].split("?")[0], [])
            elif m:
                ips.append(m.group(1))
        for ip in ips:
            if is_usable_ip(ip) and ip not in LOCAL:
                out.setdefault(ip, name)
                break                                           # the main stream's camera
    return out


def collect(c: Collected) -> None:
    url = os.environ.get("FRIGATE_URL", "https://REDACTED_IP:8971").rstrip("/")
    r = requests.get(f"{url}/api/config", timeout=30, verify=verify_ssl("FRIGATE"))
    if r.status_code != 200:
        raise RuntimeError(f"Frigate: {r.status_code} {r.text[:200]}")
    c.cameras = camera_ips(r.json())
