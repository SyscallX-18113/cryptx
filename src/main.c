#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <unistd.h>

#define ENCRYPT "encrypt"
#define DECRYPT "decrypt"

int encrypt_2 = 0;
int decrypt_2 = 0;


void banner()
{
    printf("\n");

    printf("                         CRYPTX  \n");
    printf("_________________________________________________________________________");
    printf("\n");
    printf("    CryptX is a lightweight command line encryption tool \n\n");
    printf("Usage Encryption: cryptx encrypt \"string\" \"encryption key\"\n");
    printf("Usage Decryption: cryptx decrypt \"encrypted_string\" \"encryption key\"\n\n");
    
    printf("         Github: https://github.com/SyscallX-18113/cryptx \n\n");
    printf("                  Developed By: Syscallx-18113\n\n");
    printf("                             v1.0.0");
}


int hex_to_bytes(const char *hex, unsigned char *output, int max_size)
{
    int len = strlen(hex);

    if (len % 2 != 0 || len / 2 > max_size)
        return -1;

    for (int i = 0; i < len; i += 2)
    {
        unsigned int byte;

        if (sscanf(hex + i, "%2x", &byte) != 1)
            return -1;

        output[i / 2] = (unsigned char)byte;
    }

    return len / 2;
}


int decrypt(const unsigned char *encrypted, int encrypted_len, const char *key, unsigned char *decrypted)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL)
        return -1;

    int len = 0;
    int decrypted_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(),
                           NULL, (const unsigned char *)key,
                           NULL) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptUpdate(ctx, decrypted, &len,
                          encrypted, encrypted_len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    decrypted_len = len;

    if (EVP_DecryptFinal_ex(ctx, decrypted + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    decrypted_len += len;
    decrypted[decrypted_len] = '\0';

    EVP_CIPHER_CTX_free(ctx);
    return decrypted_len;
}


int main(int argc, char *argv[])
{

    for (int i = 1; i < argc; i++)
    {

        if (strcmp(argv[i], ENCRYPT) == 0)
            encrypt_2 = 1;

        else if (strcmp(argv[i], DECRYPT) == 0)
            decrypt_2 = 1;
    }

    banner();

    if (encrypt_2 == 0 && decrypt_2 == 0)
    {
        return 0;
    }

    sleep(2);

    if (encrypt_2 == 1)
    {
        printf("\nStarting Encryption Engine...\n\n");

        char *text = argv[2];
        char *key = argv[3];

        size_t encrypted_size = strlen(text) + EVP_MAX_BLOCK_LENGTH;
        unsigned char *encrypted = malloc(encrypted_size);

        if (encrypted == NULL)
        {
            fprintf(stderr, "Memory Allocation Failed.\n");
            return 1;
        }

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

        int len, encrypted_len;

        EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, (unsigned char *)key, NULL);

        EVP_EncryptUpdate(ctx, encrypted, &len, (unsigned char *)text, strlen(text));
        encrypted_len = len;

        EVP_EncryptFinal_ex(ctx, encrypted + len, &len);
        encrypted_len += len;

        printf("Encrypted Bytes: ");
        for (int i = 0; i < encrypted_len; i++)
            printf("%02x", encrypted[i]);

        printf("\n");

        EVP_CIPHER_CTX_free(ctx);
        free(encrypted);
    }

    else
    {
        printf("\nStarting Decryption Engine...\n\n");
        sleep(2);

        const char *encrypted_hex = argv[2];
        const char *key = argv[3];

        size_t encrypted_size = strlen(encrypted_hex) / 2 + 1;

        size_t decrypted_size = encrypted_size + EVP_MAX_BLOCK_LENGTH + 1;

        unsigned char *encrypted = malloc(encrypted_size);
        unsigned char *decrypted = malloc(decrypted_size);

        if (encrypted == NULL || decrypted == NULL)
        {
            fprintf(stderr, "Memory Allocation Failed.\n");
            free(encrypted);
            free(decrypted);
            return 1;
        }

        int encrypted_len = hex_to_bytes(encrypted_hex, encrypted, encrypted_size);

        if (encrypted_len < 0)
        {
            fprintf(stderr, "Invalid Hexadecimal Ciphertext.\n");
            free(encrypted);
            free(decrypted);
            return 1;
        }

        int result = decrypt(encrypted, encrypted_len, key, decrypted);

        if (result >= 0)
            printf("Decrypted Text: %s\n", decrypted);
        else
            printf("Decryption Failed!\n");

        free(encrypted);
        free(decrypted);
    }

    return 0;
}
