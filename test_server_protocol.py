import os
import socket
import struct
import subprocess
import time

from lab_admin import get_true_vector

RESPONSE = b"REQUEST_PROCESSED"
PORT = 19099
FLAG_LENGTH = 42


def build_frame(badge_id, vector, opcode=1):
    return struct.pack("!BI8s", opcode, badge_id, vector)


def start_server(binary):
    env = dict(os.environ)
    env["TAPTRACE_QUIET"] = "1"
    env["TAPTRACE_PORT"] = str(PORT)
    proc = subprocess.Popen(
        [f"./{binary}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )
    for _ in range(50):
        try:
            sock = socket.create_connection(("127.0.0.1", PORT), timeout=0.2)
            sock.close()
            return proc
        except OSError:
            time.sleep(0.1)
    proc.terminate()
    raise RuntimeError("le serveur ne repond pas sur le port de test")


def stop_server(proc):
    proc.terminate()
    proc.wait(timeout=5)


def test_response_always_identical_and_17_bytes():
    proc = start_server("taptrace_server")
    try:
        sock = socket.create_connection(("127.0.0.1", PORT))
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        vectors = [
            bytes([0x00] * 8),
            bytes([0xFF] * 8),
            bytes(range(8)),
            bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
        ]
        for vector in vectors:
            sock.sendall(build_frame(1, vector))
            resp = sock.recv(64)
            assert len(resp) == 17, f"response doit faire 17 octets, obtenu {len(resp)}"
            assert resp == RESPONSE, f"response doit toujours etre {RESPONSE!r}, obtenu {resp!r}"
        sock.close()
        print("[+] test_response_always_identical_and_17_bytes OK")
    finally:
        stop_server(proc)


def test_partial_send_reassembled():
    proc = start_server("taptrace_server")
    try:
        sock = socket.create_connection(("127.0.0.1", PORT))
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        frame = build_frame(1, bytes([0x00] * 8))
        sock.sendall(frame[:6])
        time.sleep(0.05)
        sock.sendall(frame[6:])
        resp = sock.recv(64)
        assert resp == RESPONSE, "le serveur doit reassembler une request envoyee en plusieurs morceaux"
        sock.close()
        print("[+] test_partial_send_reassembled OK")
    finally:
        stop_server(proc)


def test_truncated_close_does_not_crash_server():
    proc = start_server("taptrace_server")
    try:
        sock = socket.create_connection(("127.0.0.1", PORT))
        frame = build_frame(1, bytes([0x00] * 8))
        sock.sendall(frame[:6])
        sock.close()
        time.sleep(0.2)
        assert proc.poll() is None, "le serveur ne doit pas crasher sur une fermeture au milieu d'une frame"

        sock2 = socket.create_connection(("127.0.0.1", PORT))
        sock2.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock2.sendall(build_frame(1, bytes([0x00] * 8)))
        resp = sock2.recv(64)
        assert resp == RESPONSE, "le serveur doit rester utilisable apres une fermeture tronquee anterieure"
        sock2.close()
        print("[+] test_truncated_close_does_not_crash_server OK")
    finally:
        stop_server(proc)


def test_hardened_response_also_fixed():
    proc = start_server("taptrace_server_hardened")
    try:
        sock = socket.create_connection(("127.0.0.1", PORT))
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        for vector in [bytes([0x00] * 8), bytes([0xFF] * 8)]:
            sock.sendall(build_frame(1, vector))
            resp = sock.recv(64)
            assert len(resp) == 17 and resp == RESPONSE
        sock.close()
        print("[+] test_hardened_response_also_fixed OK")
    finally:
        stop_server(proc)


def test_flag_denied_on_wrong_vector():
    proc = start_server("taptrace_server")
    try:
        sock = socket.create_connection(("127.0.0.1", PORT))
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.sendall(build_frame(1, bytes([0x00] * 8), opcode=2))
        resp = sock.recv(64)
        assert len(resp) == FLAG_LENGTH, f"reponse flag doit faire {FLAG_LENGTH} octets, obtenu {len(resp)}"
        assert not resp.startswith(b"TAPTRACE{"), "un vecteur faux ne doit jamais donner le flag"
        sock.close()
        print("[+] test_flag_denied_on_wrong_vector OK")
    finally:
        stop_server(proc)


def test_flag_granted_on_true_vector():
    proc = start_server("taptrace_server")
    try:
        true_vector = get_true_vector(1)
        sock = socket.create_connection(("127.0.0.1", PORT))
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.sendall(build_frame(1, true_vector, opcode=2))
        resp = sock.recv(64)
        assert resp.startswith(b"TAPTRACE{") and resp.endswith(b"}"), \
            f"le vrai vecteur doit donner un flag bien forme, obtenu {resp!r}"
        assert len(resp) == FLAG_LENGTH
        sock.close()
        print("[+] test_flag_granted_on_true_vector OK")
    finally:
        stop_server(proc)


def test_flag_does_not_affect_enroll_response():
    proc = start_server("taptrace_server")
    try:
        sock = socket.create_connection(("127.0.0.1", PORT))
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.sendall(build_frame(1, bytes([0x00] * 8), opcode=2))
        sock.recv(64)
        sock.sendall(build_frame(1, bytes([0x00] * 8), opcode=1))
        resp = sock.recv(64)
        assert resp == RESPONSE, "la soumission du flag ne doit pas perturber le canal d'enrollment"
        sock.close()
        print("[+] test_flag_does_not_affect_enroll_response OK")
    finally:
        stop_server(proc)


def main():
    test_response_always_identical_and_17_bytes()
    test_partial_send_reassembled()
    test_truncated_close_does_not_crash_server()
    test_hardened_response_also_fixed()
    test_flag_denied_on_wrong_vector()
    test_flag_granted_on_true_vector()
    test_flag_does_not_affect_enroll_response()
    print("[+] tous les tests de protocole reseau ont reussi")


if __name__ == "__main__":
    main()
