#include <iostream>
#include <string>
#include "crypto.h"

int main() {
    std::ios_base::sync_with_stdio(false);
    std::cin.tie(NULL);

    std::string command;

    while (std::cin >> command) {
        if (command == "setup_params") {
            std::cin >> global_group.p >> global_group.g >> global_group.q;

        } else if (command == "rsa_encrypt") {
            Int N, e, m;
            std::cin >> N >> e >> m;
            std::cout << rsa_encrypt(N, e, m) << "\n";

        } else if (command == "rsa_decrypt") {
            Int N, d, c;
            std::cin >> N >> d >> c;
            std::cout << rsa_decrypt(N, d, c) << "\n";

        } else if (command == "dh_key_exchange") {
            Int public_key_A;
            std::cin >> public_key_A;
            Int k_b = 0, shared_key = 0;
            diffie_hellman(public_key_A, k_b, shared_key);
            std::cout << k_b << "\n" << shared_key << "\n";

        } else if (command == "elgamal_encrypt") {
            Int pk, m;
            std::cin >> pk >> m;
            Int c1 = 0, c2 = 0;
            elgamal_encrypt(pk, m, c1, c2);
            std::cout << c1 << "\n" << c2 << "\n";

        } else if (command == "elgamal_decrypt") {
            Int sk, c1, c2;
            std::cin >> sk >> c1 >> c2;
            std::cout << elgamal_decrypt(sk, c1, c2) << "\n";
        }
    }

    return 0;
}