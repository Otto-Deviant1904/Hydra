from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect

from hydra.distribution.chunk import ChunkManager
from hydra.distribution.worker_manager import WorkerManager

logger = logging.getLogger(__name__)


async def ws_handler(websocket: WebSocket) -> None:
    await websocket.accept()
    worker_id = ""
    try:
        data = await websocket.receive_text()
        msg = json.loads(data)
        if msg.get("type") != "register":
            await websocket.send_json({"error": "first message must be register"})
            await websocket.close()
            return

        worker_id = msg.get("worker_id", "")
        hostname = msg.get("hostname", "unknown")
        devices = msg.get("devices", [])
        app = websocket.app
        wm: WorkerManager = app.state.worker_manager
        cm: ChunkManager = app.state.chunk_manager

        wm.register(worker_id, hostname, devices)
        await websocket.send_json({"type": "registered", "worker_id": worker_id})

        while True:
            data = await websocket.receive_text()
            msg = json.loads(data)

            match msg.get("type"):
                case "heartbeat":
                    wm.heartbeat(worker_id)
                    pending = cm.pending_count()
                    await websocket.send_json({
                        "type": "heartbeat_ack",
                        "pending_chunks": pending,
                    })
                    if pending > 0:
                        chunk = cm.get_pending()[0]
                        if cm.mark_assigned(chunk.id, worker_id):
                            wm.assign_chunk(worker_id, chunk.id)
                            await websocket.send_json({
                                "type": "chunk_assigned",
                                "chunk": _chunk_to_dict(chunk),
                            })

                case "chunk_result":
                    chunk_id = msg.get("chunk_id", "")
                    cracked = msg.get("cracked", {})
                    speed = msg.get("speed", 0.0)
                    completed = cm.complete_chunk(chunk_id, cracked, speed)
                    if completed:
                        wm.complete_chunk(worker_id, len(cracked), speed)
                        logger.info(
                            "Chunk %s done: %d cracked @ %.0f H/s",
                            chunk_id, len(cracked), speed,
                        )
                    await websocket.send_json({
                        "type": "chunk_ack",
                        "chunk_id": chunk_id,
                    })

                case "ready":
                    wm.heartbeat(worker_id)
                    chunk = _maybe_assign(worker_id, wm, cm)
                    await websocket.send_json({
                        "type": "ready_ack",
                        "chunk": _chunk_to_dict(chunk) if chunk else None,
                    })

    except WebSocketDisconnect:
        logger.info("Worker disconnected: %s", worker_id or "unknown")
    except Exception:
        logger.exception("WebSocket error for worker: %s", worker_id)
    finally:
        if worker_id:
            websocket.app.state.worker_manager.unregister(worker_id)


def _chunk_to_dict(chunk: Any) -> dict[str, Any]:
    if chunk is None:
        return None
    return {
        "id": chunk.id,
        "session_id": chunk.session_id,
        "phase_name": chunk.phase_name,
        "hashes": chunk.hashes,
        "hash_type": chunk.hash_type,
        "index": chunk.index,
        "total_chunks": chunk.total_chunks,
    }


def _maybe_assign(worker_id: str, wm: WorkerManager, cm: ChunkManager) -> Any:
    pending = cm.get_pending()
    if not pending:
        return None
    chunk = pending[0]
    if cm.mark_assigned(chunk.id, worker_id):
        wm.assign_chunk(worker_id, chunk.id)
        return chunk
    return None
