#include "include/openssl/evp.h"
#include "include/openssl/sha.h"
#include "include/openssl/params.h"
#include "include/openssl/core_names.h"
#include <stdio.h>
#include <string.h>

static int do_kmac(const unsigned char *in, size_t in_len,
                   const unsigned char *key, size_t key_len,
                   const unsigned char *custom, size_t custom_len,
                   int xof_enabled, unsigned char *out, int out_len)
{
    EVP_MAC_CTX *ctx = NULL;
    EVP_MAC *mac = NULL;
    OSSL_PARAM params[4], *p;
    int ret = 0;
    size_t l = 0;

    mac = EVP_MAC_fetch(NULL, "KMAC-128", NULL);
    if (mac == NULL)
        goto err;
    ctx = EVP_MAC_CTX_new(mac);
    /* The mac can be freed after it is used by EVP_MAC_CTX_new */
    EVP_MAC_free(mac);
    if (ctx == NULL)
        goto err;

    /*
     * Setup parameters required before calling EVP_MAC_init()
     * The parameters OSSL_MAC_PARAM_XOF and OSSL_MAC_PARAM_SIZE may also be
     * used at this point.
     */
    p = params;
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY,
                                             (void *)key, key_len);
    if (custom != NULL && custom_len != 0)
      *p++ = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_CUSTOM,
                                               (void *)custom, custom_len);
    *p = OSSL_PARAM_construct_end();
    if (!EVP_MAC_CTX_set_params(ctx, params))
        goto err;

    if (!EVP_MAC_init(ctx, key, key_len, params))
        goto err;

    /*
     * Note: the following optional parameters can be set any time
     * before EVP_MAC_final().
     */
    p = params;
    *p++ = OSSL_PARAM_construct_int(OSSL_MAC_PARAM_XOF, &xof_enabled);
    *p++ = OSSL_PARAM_construct_int(OSSL_MAC_PARAM_SIZE, &out_len);
    *p = OSSL_PARAM_construct_end();
    if (!EVP_MAC_CTX_set_params(ctx, params))
        goto err;

    /* The update may be called multiple times here for streamed input */
    if (!EVP_MAC_update(ctx, in, in_len))
        goto err;
    if (!EVP_MAC_final(ctx, out, &l, out_len))
        goto err;
    ret = 1;
err:
    EVP_MAC_CTX_free(ctx);
    return ret;
}

void print_sha3_hash(const unsigned char *message, size_t message_len) {
    EVP_MD_CTX *mdctx;
    unsigned char hash[SHA256_DIGEST_LENGTH];  // SHA3-256 produces a 32-byte hash
    unsigned int hash_len;

    mdctx = EVP_MD_CTX_new();
    if(mdctx == NULL) {
        printf("Failed to create context\n");
        return;
    }

    if(1 != EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL)) {
        printf("Failed to initialize digest\n");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    if(1 != EVP_DigestUpdate(mdctx, message, message_len)) {
        printf("Failed to update digest\n");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    if(1 != EVP_DigestFinal_ex(mdctx, hash, &hash_len)) {
        printf("Failed to finalize digest\n");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    EVP_MD_CTX_free(mdctx);

    printf("SHA3-256 Hash: ");
    for(unsigned int i = 0; i < hash_len; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}


int main1(void) {
    // Define 3 different keys with varying lengths
    const unsigned char key1[] = "0123456789abcdef";    // 16-byte key (128 bits)
    const unsigned char key2[] = "abcdef0123456789abcdef0123456789"; // 32-byte key (256 bits)
    const unsigned char key3[] = "01234567";            // 8-byte key (64 bits)
    
    // Define 3 different messages with varying lengths
    const unsigned char input1[] = "hello, world";       // 12 bytes
    const unsigned char input2[] = "OpenSSL KMAC Example"; // 21 bytes
    
    unsigned char mac[64];  // Adjust size if needed
    int out_len = sizeof(mac);
    int xof_enabled = 0;

    // MAC for key1 and input1
    if (do_kmac(input1, strlen((const char*)input1), key1, sizeof(key1)-1, NULL, 0, xof_enabled, mac, out_len)) {
        printf("MAC for input1 with key1: ");
        for (int i = 0; i < out_len; i++)
            printf("%02x", mac[i]);
        printf("\n");
    } else {
        printf("KMAC computation failed for input1 with key1.\n");
    }

    // MAC for key2 and input2
    if (do_kmac(input2, strlen((const char*)input2), key2, sizeof(key2)-1, NULL, 0, xof_enabled, mac, out_len)) {
        printf("MAC for input2 with key2: ");
        for (int i = 0; i < out_len; i++)
            printf("%02x", mac[i]);
        printf("\n");
    } else {
        printf("KMAC computation failed for input2 with key2.\n");
    }

    return 0;
}


int main2(void) {
    const unsigned char message[] = "hello, world";
    print_sha3_hash(message, strlen((const char *)message));

    const unsigned char message2[] = "goodbye world!";
    print_sha3_hash(message2, strlen((const char *)message2));
    return 0;
}

int main(void) {
    main1();
    main2();
    printf("www\n");
}

/*
./Configure no-tests no-engine no-docs no-aria no-bf no-blake2 no-camellia no-cast no-chacha no-cmac no-des no-dh no-dsa no-ecdh no-ecdsa no-idea no-md4 no-mdc2 no-ocb no-poly1305 no-rc2 no-rc4 no-rmd160 no-scrypt no-seed no-siphash no-siv no-sm2 no-sm3 no-sm4 no-whirlpool no-doc no-quic

make build_generated && make libcrypto.a

gcc ./main.c ./libcrypto.a -Wl,--unresolved-symbols=ignore-all && ./a.out
OR
gcc ./main.c ./libcrypto.a -I/home/rabbitsthecat/openssl/include && ./a.out
*/

