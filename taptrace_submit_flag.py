import argparse
import socket
import struct

OPCODE_SUBMIT_FLAG = 2
FLAG_LENGTH = 42


def build_frame(badge_id, vector):
    return struct.pack("!BI8s", OPCODE_SUBMIT_FLAG, badge_id, vector)


def recv_exact(sock, length):
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("connexion fermee avant reception complete")
        data += chunk
    return data


def main():
    parser = argparse.ArgumentParser(
        description="TAPTRACE soumission du flag, sur le canal public (aucun acces admin)"
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--badge-id", type=int, default=1)
    parser.add_argument("recovered", nargs=8, help="8 octets recuperes en hexadecimal, ex: b1 27 78 ...")
    args = parser.parse_args()

    vector = bytes(int(b, 16) for b in args.recovered)

    sock = socket.create_connection((args.host, args.port))
    sock.sendall(build_frame(args.badge_id, vector))
    resp = recv_exact(sock, FLAG_LENGTH)
    sock.close()

    text = resp.decode("ascii", errors="replace")
    if text.startswith("TAPTRACE{"):
        print(f"Flag obtenu : {text}")
    else:
        print("Acces refuse : le vecteur soumis est incorrect.")


if __name__ == "__main__":
    main()
