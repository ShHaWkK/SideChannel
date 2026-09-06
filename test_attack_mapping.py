import random
import numpy as np

WARMUP = 100


def rank_by(scores):
    return sorted(range(256), key=lambda c: scores[c], reverse=True)


def simulate_collection(seed, rounds, time_function):
    rng = random.Random(seed)
    temps = np.empty((rounds, 256), dtype=np.float64)
    for t in range(rounds):
        order = list(range(256))
        rng.shuffle(order)
        for candidate in order:
            temps[t, candidate] = time_function(candidate)
    return temps


def centered_score(temps):
    round_medians = np.median(temps, axis=1, keepdims=True)
    centered = temps - round_medians
    return np.median(centered, axis=0)


def test_strictly_increasing_order_base_plus_candidate():
    def time_function(candidate):
        return 1000.0 + candidate

    temps = simulate_collection(seed=1, rounds=20, time_function=time_function)
    score = centered_score(temps)
    ranking = rank_by(score)
    assert ranking[0] == 255, f"attendu rank1=255, obtenu {ranking[0]}"
    assert ranking[-1] == 0, f"attendu dernier=0, obtenu {ranking[-1]}"
    for expected_candidate, candidate in zip(range(255, -1, -1), ranking):
        assert expected_candidate == candidate, f"ordre casse a {candidate}, attendu {expected_candidate}"
    print("[+] test_strictly_increasing_order_base_plus_candidate OK")


def test_single_peak_at_0x42():
    def time_function(candidate):
        base = 1000.0
        if candidate == 0x42:
            return base + 100.0
        return base

    temps = simulate_collection(seed=2, rounds=50, time_function=time_function)
    score = centered_score(temps)
    ranking = rank_by(score)
    assert ranking[0] == 0x42, f"attendu rank1=0x42, obtenu {ranking[0]:02x}"
    print("[+] test_single_peak_at_0x42 OK")


def test_column_matches_shuffled_index():
    rng = random.Random(3)
    rounds = 10
    temps = np.empty((rounds, 256), dtype=np.float64)
    recorded = []
    for t in range(rounds):
        order = list(range(256))
        rng.shuffle(order)
        for candidate in order:
            value = 1000.0 + candidate
            temps[t, candidate] = value
            recorded.append((t, candidate, value))

    for t, candidate, value in recorded:
        assert temps[t, candidate] == value, "colonne decalee par rapport au candidat mesure"
    for t in range(rounds):
        for c in range(256):
            assert temps[t, c] == 1000.0 + c, f"tour {t} candidat {c} valeur inattendue {temps[t, c]}"
    print("[+] test_column_matches_shuffled_index OK")


def test_each_round_covers_all_candidates_once():
    rng = random.Random(4)
    rounds = 30
    seen_count = np.zeros(256, dtype=int)
    for _ in range(rounds):
        order = list(range(256))
        rng.shuffle(order)
        assert sorted(order) == list(range(256)), "un tour ne contient pas exactement 0x00 a 0xff"
        assert len(set(order)) == 256, "un tour contient un doublon"
        for candidate in order:
            seen_count[candidate] += 1
    assert all(seen_count == rounds), "un candidat n'est pas mesure exactement une fois par tour"
    print("[+] test_each_round_covers_all_candidates_once OK")


def test_frame_matches_known_prefix():
    from taptrace_attack import build_frame

    badge_id = 1
    known_prefix = [0xAB, 0xCD]
    candidate = 0x42
    neutral_suffix_length = 5
    vector_list = list(known_prefix) + [candidate]
    vector_list += [0x00] * (8 - len(vector_list))
    assert len(vector_list) == 8, "access_vector doit faire exactement 8 octets"
    assert vector_list[0] == 0xAB and vector_list[1] == 0xCD, "prefixe connu mal place"
    assert vector_list[2] == candidate, "candidat pas a l'offset attendu"
    assert vector_list[3:] == [0x00] * neutral_suffix_length, "suffixe neutre mal dimensionne"

    frame = build_frame(badge_id, bytes(vector_list))
    assert len(frame) == 13, f"frame doit faire 13 octets, obtenu {len(frame)}"
    assert frame[0] == 1, "opcode incorrect"
    assert frame[5:13] == bytes(vector_list), "access_vector mal serialise dans la frame"
    print("[+] test_frame_matches_known_prefix OK")


def main():
    test_each_round_covers_all_candidates_once()
    test_column_matches_shuffled_index()
    test_strictly_increasing_order_base_plus_candidate()
    test_single_peak_at_0x42()
    test_frame_matches_known_prefix()
    print("[+] tous les tests de mapping ont reussi")


if __name__ == "__main__":
    main()
