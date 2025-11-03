# main.py
from test.test_classical_handshake import main as main_classical
from test.test_pqc_handshake import main as main_pqc


def main():
    """
    Runs both the classical and PQC handshake benchmarks.
    """
    print("=============================================")
    print("=== STARTING CLASSICAL HANDSHAKE BENCHMARK ===")
    print("=============================================")
    main_classical()

    print("\n\n==========================================")
    print("=== STARTING PQC HANDSHAKE BENCHMARK ===")
    print("==========================================")
    main_pqc()


if __name__ == "__main__":
    main()
