import argparse

from lab_admin import ADMIN_SOCKET, get_true_vector


def main():
    parser = argparse.ArgumentParser(description="TAPTRACE verification laboratoire (canal admin)")
    parser.add_argument("--badge-id", type=int, default=1)
    parser.add_argument("--admin-socket", default=ADMIN_SOCKET)
    parser.add_argument("recovered", nargs=8, help="8 octets recuperes en hexadecimal, ex: b1 27 78 ...")
    args = parser.parse_args()

    recovered = [int(b, 16) for b in args.recovered]
    true_vector = get_true_vector(args.badge_id, args.admin_socket)

    all_ok = True
    for i in range(8):
        ok = recovered[i] == true_vector[i]
        all_ok = all_ok and ok
        print(f"byte{i} : {'SUCCES' if ok else 'ECHEC'}")

    print("ATTACK SUCCESS" if all_ok else "ATTACK FAILURE")


if __name__ == "__main__":
    main()
