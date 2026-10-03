#ifndef CRYPTO_H
#define CRYPTO_H

#include <iostream>
#include <random>

using Int = unsigned long long;

struct GroupParams {
    Int p;
    Int g;
    Int q;
};

inline GroupParams global_group = {0, 0, 0};

inline Int mod_exp(Int base, Int exp, Int mod) {
    if (mod == 1) return 0;
    
    Int result = 1;
    base %= mod;

    while (exp > 0) {
        if (exp % 2 == 1) {
            result = (__int128(result) * base) % mod;
        }
        base = (__int128(base) * base) % mod;
        exp /= 2;
    }
    
    return result;
}

inline Int mod_inverse(Int a, Int mod) {
    long long m0 = static_cast<long long>(mod);
    long long y = 0, x = 1;
    long long a_signed = static_cast<long long>(a % mod);

    if (mod == 1) return 0;

    long long r0 = m0;
    long long r1 = a_signed;

    while (r1 > 0) {
        long long q = r0 / r1;
        
        long long temp_r = r0 - q * r1;
        r0 = r1;
        r1 = temp_r;

        long long temp_x = y - q * x;
        y = x;
        x = temp_x;
    }

    if (r0 != 1) return 0;

    if (y < 0) {
        y += m0;
    }

    return static_cast<Int>(y);
}

// My 5 functions
inline Int rsa_encrypt(Int N, Int e, Int m) {
    return mod_exp(m, e, N);
}

inline Int rsa_decrypt(Int N, Int d, Int c) {
    return mod_exp(c, d, N);
}

inline void diffie_hellman(Int public_key_A, Int &k_b, Int &shared_key) {

    Int upper_bound = (global_group.q > 1) ? (global_group.q - 1) : (global_group.p - 2);

    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<Int> dist(1, upper_bound);

    k_b = dist(gen);

    shared_key = mod_exp(public_key_A, k_b, global_group.p);
}

inline void elgamal_encrypt(Int pk, Int m, Int &c1, Int &c2) {

    Int upper_bound = (global_group.q > 1) ? (global_group.q - 1) : (global_group.p - 2);

    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<Int> dist(1, upper_bound);

    Int y = dist(gen);

    c1 = mod_exp(global_group.g, y, global_group.p);

    Int s = mod_exp(pk, y, global_group.p);

    c2 = (__int128(m % global_group.p) * s) % global_group.p;
}

inline Int elgamal_decrypt(Int sk, Int c1, Int c2) {

    Int s = mod_exp(c1, sk, global_group.p);

    Int s_inv = mod_inverse(s, global_group.p);

    Int m = (__int128(c2 % global_group.p) * s_inv) % global_group.p;

    return m;
}

#endif // CRYPTO_H
