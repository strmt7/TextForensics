from __future__ import annotations

import asyncio
import csv
import io
import json
import os
import uuid
from collections import OrderedDict
from contextlib import suppress
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from ..config import Settings, ensure_bind_allowed, validate_text_input
from ..detectors import list_detector_health, list_detector_metadata
from ..report import build_forensic_bundle
from ..version import get_version

