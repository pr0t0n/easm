"""Minimal, real SOCKS5 (RFC 1928) server: implements only the greeting and
CONNECT handshake for real -- proxychains4 (inside kali_runner) genuinely
completes this handshake over the network, which is the "real traffic" this
phase proves. What happens after the handshake is a stub: no real relay into
a customer network exists yet (there is none in dev), so a canned payload is
sent back and the connection is closed, standing in for the real Rust
agent's future relay behavior.
"""
from __future__ import annotations

import asyncio
import logging
import struct

logger = logging.getLogger("bas_agent_stub.socks5")

_SOCKS_VERSION = 0x05
_CMD_CONNECT = 0x01
_ATYP_IPV4 = 0x01
_ATYP_DOMAIN = 0x03
_ATYP_IPV6 = 0x04
_REP_SUCCEEDED = 0x00
_REP_GENERAL_FAILURE = 0x01

# Stands in for "the target service answered" -- deliberately generic and
# clearly fake, never a crafted real-looking service banner.
_STUB_RESPONSE_PAYLOAD = b"BAS-STUB-SIMULATED-RESPONSE\r\n"


async def _read_exact(reader: asyncio.StreamReader, n: int) -> bytes:
    data = await reader.readexactly(n)
    return data


async def handle_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername")
    try:
        # ── Greeting ──
        header = await _read_exact(reader, 2)
        version, nmethods = header[0], header[1]
        if version != _SOCKS_VERSION:
            logger.warning("bas_agent_stub: rejected non-SOCKS5 client peer=%s version=%s", peer, version)
            return
        await _read_exact(reader, nmethods)  # methods offered, ignored -- we always pick "no auth"
        writer.write(bytes([_SOCKS_VERSION, 0x00]))
        await writer.drain()

        # ── CONNECT request: VER, CMD, RSV, ATYP (4 bytes), then the address ──
        req_header = await _read_exact(reader, 4)
        cmd, atyp = req_header[1], req_header[3]
        if atyp == _ATYP_IPV4:
            addr_bytes = await _read_exact(reader, 4)
            dest_addr = ".".join(str(b) for b in addr_bytes)
        elif atyp == _ATYP_DOMAIN:
            length = (await _read_exact(reader, 1))[0]
            dest_addr = (await _read_exact(reader, length)).decode("ascii", errors="replace")
        elif atyp == _ATYP_IPV6:
            addr_bytes = await _read_exact(reader, 16)
            dest_addr = addr_bytes.hex()
        else:
            writer.write(bytes([_SOCKS_VERSION, _REP_GENERAL_FAILURE, 0x00, _ATYP_IPV4, 0, 0, 0, 0, 0, 0]))
            await writer.drain()
            return
        dest_port = struct.unpack("!H", await _read_exact(reader, 2))[0]

        if cmd != _CMD_CONNECT:
            writer.write(bytes([_SOCKS_VERSION, 0x07, 0x00, _ATYP_IPV4, 0, 0, 0, 0, 0, 0]))  # command not supported
            await writer.drain()
            return

        logger.info(
            "bas_agent_stub: REAL SOCKS5 CONNECT received peer=%s requested_destination=%s:%s",
            peer, dest_addr, dest_port,
        )

        # Reply "succeeded" as if we connected to dest_addr:dest_port -- bind
        # address/port are meaningless here (0.0.0.0:0), never a real socket.
        writer.write(bytes([_SOCKS_VERSION, _REP_SUCCEEDED, 0x00, _ATYP_IPV4, 0, 0, 0, 0, 0, 0]))
        await writer.drain()

        # Give the tool a moment to send its first bytes (e.g. an SMB
        # negotiate request), then reply with the stub payload regardless of
        # content -- there is nothing real behind this tunnel endpoint yet.
        try:
            await asyncio.wait_for(reader.read(4096), timeout=2.0)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            pass
        writer.write(_STUB_RESPONSE_PAYLOAD)
        await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionResetError):
        logger.info("bas_agent_stub: connection closed early peer=%s", peer)
    except Exception:  # noqa: BLE001
        logger.exception("bas_agent_stub: handshake error peer=%s", peer)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass


async def serve(host: str, port: int) -> None:
    server = await asyncio.start_server(handle_connection, host, port)
    logger.info("bas_agent_stub: SOCKS5 tunnel stub listening on %s:%s", host, port)
    async with server:
        await server.serve_forever()
