import asyncio
import json

import websockets

from live_bridge import (
    LivePacketBridge,
    TCPFlowTracker,
    TCP_ACK,
    TCP_FIN,
    TCP_RST,
)


def test_elephant_flow_qualification_ignores_mice_flows():
    tracker = TCPFlowTracker(idle_timeout_sec=15.0, min_packets_to_lock=6, min_bytes_to_lock=4096)

    # Short 3-packet HTTPS "mouse" flow must NOT steal the lock
    seq = 1000
    for i in range(3):
        tracker.process_fields("10.0.0.5", "142.250.1.1", 51000, 443, 1200, TCP_ACK, seq, 1, now=1.0 + i * 0.05)
        seq += 1200
    assert tracker.target_flow is None

    # Sustained flow reaching 6 packets & >= 4096 bytes locks cleanly
    seq = 5000
    for i in range(6):
        tracker.process_fields("10.0.0.5", "140.82.113.26", 52000, 443, 1000, TCP_ACK, seq, 1, now=2.0 + i * 0.05)
        seq += 1000
    assert tracker.target_flow == ("10.0.0.5", "140.82.113.26", 52000, 443)


def test_idle_timeout_and_pin_hold_mode():
    tracker = TCPFlowTracker(idle_timeout_sec=15.0, min_packets_to_lock=4, min_bytes_to_lock=2048)

    seq = 1000
    for i in range(4):
        tracker.process_fields("10.0.0.5", "1.1.1.1", 55000, 443, 1000, TCP_ACK, seq, 1, now=10.0 + i * 0.01)
        seq += 1000
    assert tracker.target_flow == ("10.0.0.5", "1.1.1.1", 55000, 443)

    # Pin the flow: must stay locked even after 30s idle AND even on FIN
    tracker.set_pinned(True)
    tracker.process_fields("10.0.0.5", "9.9.9.9", 56000, 443, 1400, TCP_ACK, 100, 1, now=45.0)
    assert tracker.target_flow == ("10.0.0.5", "1.1.1.1", 55000, 443)

    tracker.process_fields("10.0.0.5", "1.1.1.1", 55000, 443, 0, TCP_FIN | TCP_ACK, seq, 1, now=46.0)
    assert tracker.target_flow == ("10.0.0.5", "1.1.1.1", 55000, 443)

    # Unpin: idle > 15s now unlocks immediately
    tracker.set_pinned(False)
    tracker.process_fields("10.0.0.5", "9.9.9.9", 56000, 443, 1400, TCP_ACK, 100, 1, now=70.0)
    assert tracker.target_flow is None


def test_graceful_fin_rst_unlocks_unpinned_flow():
    tracker = TCPFlowTracker(idle_timeout_sec=15.0, min_packets_to_lock=3, min_bytes_to_lock=1500)

    seq = 100
    for i in range(3):
        tracker.process_fields("10.0.0.5", "8.8.8.8", 40000, 443, 600, TCP_ACK, seq, 1, now=1.0 + i * 0.01)
        seq += 600
    assert tracker.target_flow is not None

    # FIN unlocks immediately
    tracker.process_fields("10.0.0.5", "8.8.8.8", 40000, 443, 0, TCP_FIN | TCP_ACK, seq, 1, now=1.5)
    assert tracker.target_flow is None

    # Lock again and verify RST unlocks immediately
    seq = 100
    for i in range(3):
        tracker.process_fields("10.0.0.5", "8.8.4.4", 40001, 443, 600, TCP_ACK, seq, 1, now=2.0 + i * 0.01)
        seq += 600
    assert tracker.target_flow is not None
    tracker.process_fields("8.8.4.4", "10.0.0.5", 443, 40001, 0, TCP_RST, 1, seq, now=2.2)
    assert tracker.target_flow is None


def test_websocket_batched_broadcast_and_pin_control():
    async def _run():
        bridge = LivePacketBridge(batch_interval=0.02)
        broadcaster = asyncio.create_task(bridge.broadcast_loop())
        srv = await websockets.serve(bridge.handle_client, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]

        try:
            async with websockets.connect(f"ws://127.0.0.1:{port}") as ws:
                hello = json.loads(await asyncio.wait_for(ws.recv(), timeout=2.0))
                assert hello["type"] == "bridge_info"
                assert hello["pinned"] is False

                # Send pin_flow command from client and verify batched flow_update arrives
                await ws.send(json.dumps({"type": "pin_flow", "pinned": True}))
                batch = json.loads(await asyncio.wait_for(ws.recv(), timeout=2.0))
                assert batch["type"] == "batch"
                assert batch["flow_update"]["pinned"] is True
                assert bridge.flow_tracker.pinned is True
        finally:
            bridge.stop_event.set()
            broadcaster.cancel()
            await asyncio.gather(broadcaster, return_exceptions=True)
            srv.close()
            await asyncio.wait_for(srv.wait_closed(), timeout=2.0)

    asyncio.run(_run())
