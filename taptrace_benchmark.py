import argparse
import socket
import random
import struct
import time
import numpy as np

from lab_admin import get_true_vector

WARMUP = 100
RESPONSE = b"REQUEST_PROCESSED"


def build_frame(badge_id, vector):
    return struct.pack("!BI8s", 1, badge_id, vector)


def recv_exact(sock, length):
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("connexion fermee avant reception complete")
        data += chunk
    return data


def send_and_measure(sock, frame):
    start = time.perf_counter_ns()
    sock.sendall(frame)
    resp = recv_exact(sock, len(RESPONSE))
    end = time.perf_counter_ns()
    if resp != RESPONSE:
        raise ValueError(f"response inattendue: {resp!r}")
    return end - start


def build_prefix_frames(badge_id, true_vector):
    frames = []
    for prefix_length in range(9):
        vector_list = list(true_vector[:prefix_length])
        if prefix_length < 8:
            wrong = (true_vector[prefix_length] + 1) % 256
            vector_list.append(wrong)
            vector_list += [0x00] * (8 - len(vector_list))
        frames.append(bytes(vector_list))
    return [build_frame(badge_id, v) for v in frames]


def collect(host, port, frames, seed, rounds):
    sock = socket.create_connection((host, port))
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    for i in range(WARMUP):
        send_and_measure(sock, frames[i % len(frames)])

    n = len(frames)
    temps = np.empty((rounds, n), dtype=np.float64)
    rng = random.Random(seed)
    total_requests = WARMUP
    for t in range(rounds):
        order = list(range(n))
        rng.shuffle(order)
        for prefix_length in order:
            temps[t, prefix_length] = send_and_measure(sock, frames[prefix_length])
            total_requests += 1

    sock.close()
    return temps, total_requests


def main():
    parser = argparse.ArgumentParser(
        description="TAPTRACE benchmark de laboratoire : mesure le temps de reponse en "
        "fonction de la longueur de prefixe correct, en utilisant le vrai secret via "
        "le canal admin. Ce n'est PAS l'attaque : ca ne devine rien, ca construit "
        "directement des vecteurs a longueur de prefixe controlee pour caracteriser "
        "le signal temporel sous-jacent."
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--badge-id", type=int, default=1)
    parser.add_argument("--rounds", type=int, default=3000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--admin-socket", default=None)
    args = parser.parse_args()

    kwargs = {}
    if args.admin_socket:
        kwargs["admin_socket"] = args.admin_socket
    true_vector = get_true_vector(args.badge_id, **kwargs)

    frames = build_prefix_frames(args.badge_id, true_vector)
    temps, total_requests = collect(args.host, args.port, frames, args.seed, args.rounds)

    round_medians = np.median(temps, axis=1, keepdims=True)
    centered = temps - round_medians

    print("TAPTRACE benchmark (laboratoire uniquement, utilise le canal admin)")
    print(f"badge_id: {args.badge_id}, rounds: {args.rounds}, requests: {total_requests}")
    print()
    print("prefix_length  mediane_brute_ns  mediane_centree_ns")
    for prefix_length in range(9):
        raw_median = float(np.median(temps[:, prefix_length]))
        centered_median = float(np.median(centered[:, prefix_length]))
        print(f"{prefix_length:>16}  {raw_median:>16.1f}  {centered_median:>18.1f}")


if __name__ == "__main__":
    main()
