# main.py
"""
Hlavní spouštěcí skript projektu.

Tento skript importuje a spouští srovnávací benchmarky definované
v souboru `test/test_tls.py`.
"""

from test import test_tls

if __name__ == "__main__":
    print("Spouštím srovnávací testy z 'test/test_tls.py'...")
    test_tls.main()
    print("\nVšechny testy byly dokončeny.")
