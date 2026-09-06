import socket
import struct

ADMIN_SOCKET = "/tmp/taptrace/admin.sock"


def get_true_vector(badge_id, admin_socket=ADMIN_SOCKET):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(admin_socket)
    s.sendall(struct.pack("!BI", 1, badge_id))
    resp = s.recv(64)
    s.close()
    return resp[1:9]
