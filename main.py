from test import test_my_tls, test_classic_tls, test_oqs_tls, test_kem, test_dsa

if __name__ == "__main__":
    print("Spouštím srovnávací testy z 'test/test_tls.py'...")
    test_kem.main()
    test_dsa.main()
    test_my_tls.main()
    test_classic_tls.main()
    test_oqs_tls.main()
    print("\nVšechny testy byly dokončeny.")
