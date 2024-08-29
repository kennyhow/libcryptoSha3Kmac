#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
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
    const unsigned char key[] = "0123456789abcdef";  // 128-bit key
    const unsigned char input[] = "hello, world";
    unsigned char mac[32];  // Adjust size if needed
    int out_len = sizeof(mac);
    int xof_enabled = 0;

    if (do_kmac(input, strlen((const char*)input), key, sizeof(key)-1, NULL, 0, xof_enabled, mac, out_len)) {
        printf("MAC: ");
        for (int i = 0; i < out_len; i++)
            printf("%02x", mac[i]);
        printf("\n");
    } else {
        printf("KMAC computation failed.\n");
    }

    return 0;
}

int main2(void) {
    const unsigned char message[] = "hello, world";
    print_sha3_hash(message, strlen((const char *)message));
    return 0;
}

int main(void) {
    main1();
    main2();
}

/*
./Configure no-tests no-engine no-docs no-aria no-bf no-blake2 no-camellia no-cast no-chacha no-cmac no-des no-dh no-dsa no-ecdh no-ecdsa no-idea no-md4 no-mdc2 no-ocb no-poly1305 no-rc2 no-rc4 no-rmd160 no-scrypt no-seed no-siphash no-siv no-sm2 no-sm3 no-sm4 no-whirlpool
*/

// gcc ./main.c ./libcrypto.a -Wl,--unresolved-symbols=ignore-all && ./a.out