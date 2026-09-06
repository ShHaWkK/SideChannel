CC = gcc
CFLAGS = -Wall -Wextra -O0
SRC = src
LEVEL ?= 1

COMMON_SRC = $(SRC)/badge.c $(SRC)/policy.c $(SRC)/enrollment.c
COMMON_DEFS = -DTAPTRACE_BADGE_NO_MAIN -DTAPTRACE_POLICY_NO_MAIN -DTAPTRACE_ENROLLMENT_NO_MAIN

.PHONY: all test run run-hardened attack benchmark demo demo-hardened hint clean

all: taptrace_badge_test taptrace_policy_test taptrace_enrollment_test taptrace_server taptrace_server_hardened

taptrace_badge_test: $(SRC)/badge.c
	$(CC) $(CFLAGS) $(SRC)/badge.c -o taptrace_badge_test

taptrace_policy_test: $(SRC)/badge.c $(SRC)/policy.c
	$(CC) $(CFLAGS) -DTAPTRACE_BADGE_NO_MAIN $(SRC)/badge.c $(SRC)/policy.c -o taptrace_policy_test

taptrace_enrollment_test: $(COMMON_SRC)
	$(CC) $(CFLAGS) -DTAPTRACE_BADGE_NO_MAIN -DTAPTRACE_POLICY_NO_MAIN $(SRC)/badge.c $(SRC)/policy.c $(SRC)/enrollment.c -o taptrace_enrollment_test

taptrace_server: $(COMMON_SRC) $(SRC)/server.c
	$(CC) $(CFLAGS) $(COMMON_DEFS) $(COMMON_SRC) $(SRC)/server.c -o taptrace_server

taptrace_server_hardened: $(COMMON_SRC) $(SRC)/server_hardened.c
	$(CC) $(CFLAGS) $(COMMON_DEFS) $(COMMON_SRC) $(SRC)/server_hardened.c -o taptrace_server_hardened

test: taptrace_badge_test taptrace_policy_test taptrace_enrollment_test taptrace_server taptrace_server_hardened
	./taptrace_badge_test
	./taptrace_policy_test
	./taptrace_enrollment_test
	python3 test_attack_mapping.py
	python3 test_server_protocol.py

run: taptrace_server
	./taptrace_server

run-hardened: taptrace_server_hardened
	./taptrace_server_hardened

demo: taptrace_server
	./demo.sh vulnerable

demo-hardened: taptrace_server_hardened
	./demo.sh hardened

attack: taptrace_attack.py
	python3 taptrace_attack.py

benchmark: taptrace_benchmark.py
	python3 taptrace_benchmark.py

hint: taptrace_hints.py
	python3 taptrace_hints.py --level $(LEVEL)

clean:
	rm -f taptrace_badge_test taptrace_policy_test taptrace_enrollment_test taptrace_server taptrace_server_hardened
