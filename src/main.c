
#define _POSIX_C_SOURCE 200809L
#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#define VERSION "1.5.0"
#define SALT_LEN 16
#define NONCE_LEN 12
#define TAG_LEN 16
#define KEY_LEN 32
#define HEADER_LEN 36
#define CHUNK_SIZE 65536
#define PBKDF2_ITERATIONS 600000

static const unsigned char MAGIC[8] = {
    'C', 'R', 'Y', 'P', 'E', 'N', 'C', '1'
};

static void banner()
{
    printf("                         CRYPTX  \n");
    printf("_________________________________________________________________________");
    printf("\n");
    printf("    CryptX is a lightweight command line encryption tool \n\n");
    printf("\n");
    printf("  Text Encryption:   cryptx encrypt \"string\" \"encryption key\"\n");
    printf("  Text Decryption:   cryptx decrypt \"encrypted_string\" \"encryption key\"\n\n");
    printf("  File encryption:   cryptx encrypt-file file \"encryption key\"\n");
    printf("  File decryption:   cryptx decrypt-file file.crypenc \"encryption key\"\n");
    printf("\n");

    printf("         Github: https://github.com/SyscallX-18113/cryptx \n\n");
    printf("                  Developed By: Syscallx-18113\n\n");
    printf("                             v1.5.0\n");

}

static int derive_key(const char *passphrase, const unsigned char *salt, unsigned char *key)
{
    if (passphrase == NULL || passphrase[0] == '\0') 
    {
        fprintf(stderr, "Passphrase cannot be empty.\n");
        return 0;
    }

    if (PKCS5_PBKDF2_HMAC(passphrase, (int)strlen(passphrase), salt, SALT_LEN, PBKDF2_ITERATIONS, EVP_sha256(), KEY_LEN, key) != 1) 
    {
        fprintf(stderr, "Key derivation failed.\n");
        return 0;
    }

    return 1;
}

static void make_header(unsigned char *header, const unsigned char *salt, const unsigned char *nonce)
{
    memcpy(header, MAGIC, 8);
    memcpy(header + 8, salt, SALT_LEN);
    memcpy(header + 24, nonce, NONCE_LEN);
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static char *to_hex(const unsigned char *data, size_t len)
{
    static const char digits[] = "0123456789abcdef";

    if (len > (SIZE_MAX - 1) / 2)
        return NULL;

    char *hex = malloc(len * 2 + 1);
    if (!hex)
        return NULL;

    for (size_t i = 0; i < len; i++) {
        hex[i * 2] = digits[data[i] >> 4];
        hex[i * 2 + 1] = digits[data[i] & 0x0f];
    }

    hex[len * 2] = '\0';
    return hex;
}

static unsigned char *from_hex(const char *hex, size_t *out_len)
{
    size_t len = strlen(hex);

    if (len % 2 != 0) {
        fprintf(stderr, "Invalid hexadecimal input.\n");
        return NULL;
    }

    unsigned char *data = malloc(len / 2 ? len / 2 : 1);
    if (!data)
        return NULL;

    for (size_t i = 0; i < len; i += 2) {
        int high = hex_value(hex[i]);
        int low = hex_value(hex[i + 1]);

        if (high < 0 || low < 0) {
            fprintf(stderr, "Input contains non-hexadecimal characters.\n");
            free(data);
            return NULL;
        }

        data[i / 2] = (unsigned char)((high << 4) | low);
    }

    *out_len = len / 2;
    return data;
}

static int encrypt_text(const char *text, const char *passphrase)
{
    int ok = 0;
    int out1 = 0, out2 = 0;
    size_t text_len = strlen(text);

    if (text_len > INT_MAX) {
        fprintf(stderr, "Text is too large.\n");
        return 0;
    }

    if (text_len > SIZE_MAX - HEADER_LEN - TAG_LEN - EVP_MAX_BLOCK_LENGTH) {
        fprintf(stderr, "Input is too large.\n");
        return 0;
    }

    size_t capacity = HEADER_LEN + text_len + EVP_MAX_BLOCK_LENGTH + TAG_LEN;

    unsigned char *container = malloc(capacity);
    unsigned char key[KEY_LEN] = {0};
    unsigned char *salt = NULL;
    unsigned char *nonce = NULL;
    unsigned char *ciphertext = NULL;
    unsigned char *tag = NULL;
    EVP_CIPHER_CTX *ctx = NULL;

    if (!container) {
        fprintf(stderr, "Memory allocation failed.\n");
        goto cleanup;
    }

    salt = container + 8;
    nonce = container + 24;
    ciphertext = container + HEADER_LEN;

    if (RAND_bytes(salt, SALT_LEN) != 1 || RAND_bytes(nonce, NONCE_LEN) != 1) {
        fprintf(stderr, "Secure random generation failed.\n");
        goto cleanup;
    }

    memcpy(container, MAGIC, 8);

    if (!derive_key(passphrase, salt, key))
        goto cleanup;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto cleanup;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1 || EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1 || EVP_EncryptUpdate(ctx, ciphertext, &out1, (const unsigned char *)text, (int)text_len) != 1 || EVP_EncryptFinal_ex(ctx, ciphertext + out1, &out2) != 1) {
        fprintf(stderr, "Text encryption failed.\n");
        goto cleanup;
    }

    tag = ciphertext + out1 + out2;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1)
        goto cleanup;

    size_t total_len = HEADER_LEN + (size_t)out1 + (size_t)out2 + TAG_LEN;


    char *hex = to_hex(container, total_len);
    if (!hex) {
        fprintf(stderr, "Could not encode ciphertext.\n");
        goto cleanup;
    }

    printf("%s\n", hex);
    free(hex);
    ok = 1;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    if (container) {
        OPENSSL_cleanse(container, capacity);
        free(container);
    }
    OPENSSL_cleanse(key, sizeof(key));
    return ok;
}

static int decrypt_text(const char *hex, const char *passphrase)
{
    int ok = 0;
    int out1 = 0, out2 = 0;

    size_t container_len = 0;
    unsigned char key[KEY_LEN] = {0};
    EVP_CIPHER_CTX *ctx = NULL;

    unsigned char *container = from_hex(hex, &container_len);
    if (!container)
        return 0;


    if (container_len < HEADER_LEN + TAG_LEN || memcmp(container, MAGIC, 8) != 0)
     {
        fprintf(stderr, "Invalid CryptX ciphertext.\n");
        goto cleanup;
    }

    size_t cipher_len = container_len - HEADER_LEN - TAG_LEN;
    if (cipher_len > INT_MAX) 
    {
        fprintf(stderr, "Ciphertext is too large.\n");
        goto cleanup;
    }

    unsigned char *salt = container + 8;
    unsigned char *nonce = container + 24;

    unsigned char *ciphertext = container + HEADER_LEN;
    unsigned char *tag = container + container_len - TAG_LEN;

    unsigned char *plaintext = malloc(cipher_len + 1);
    if (!plaintext) 
    {
        fprintf(stderr, "Memory allocation failed.\n");
        goto cleanup;
    }

    if (!derive_key(passphrase, salt, key)) 
    {
        free(plaintext);
        goto cleanup;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto plaintext_cleanup;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1 || EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1 || EVP_DecryptUpdate(ctx, plaintext, &out1, ciphertext, (int)cipher_len) != 1 || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag) != 1 || EVP_DecryptFinal_ex(ctx, plaintext + out1, &out2) != 1) {
        fprintf(stderr, "Error: Decryption failed. Wrong passphrase or modified data.\n");
        goto plaintext_cleanup;
    }

    plaintext[out1 + out2] = '\0';
    printf("%s\n", (char *)plaintext);
    ok = 1;

plaintext_cleanup:
    OPENSSL_cleanse(plaintext, cipher_len + 1);
    free(plaintext);

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(container, container_len);
    free(container);
    return ok;
}

static FILE *open_temp_file(const char *destination, char **temp_path, int *temp_fd)
{
    
    size_t len = strlen(destination);

    if (len == 0 || len > SIZE_MAX - 16)
        return NULL;

    *temp_path = malloc(len + 16);
    if (!*temp_path)
        return NULL;

    snprintf(*temp_path, len + 16, "%s.tmp.XXXXXX", destination);

    *temp_fd = mkstemp(*temp_path);
    if (*temp_fd < 0) {
        free(*temp_path);
        *temp_path = NULL;
        return NULL;
    }

    FILE *fp = fdopen(*temp_fd, "wb");
    if (!fp) {
        close(*temp_fd);
        unlink(*temp_path);
        free(*temp_path);
        *temp_path = NULL;
        return NULL;
    }

    return fp;
}


static int publish_temp(FILE *fp, char *temp_path, const char *destination, int *temp_fd)
{
    int close_ok = (fclose(fp) == 0);
    *temp_fd = -1;

    if (!close_ok) {
        fprintf(stderr, "Could not finish writing output file.\n");
        unlink(temp_path);
        free(temp_path);
        return 0;
    }

    if (link(temp_path, destination) != 0) {
        if (errno == EEXIST)
            fprintf(stderr, "Destination already exists: %s\n", destination);
        else
            perror("error creating destination");
        unlink(temp_path);
        free(temp_path);
        return 0;
    }

    unlink(temp_path);
    free(temp_path);
    return 1;
}

static int encrypt_file(const char *input_path, const char *passphrase)
{
    int ok = 0;
    int temp_fd = -1;
    FILE *in = NULL, *out = NULL;
    char *destination = NULL, *temp_path = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char key[KEY_LEN] = {0};
    unsigned char salt[SALT_LEN], nonce[NONCE_LEN];
    unsigned char header[HEADER_LEN], tag[TAG_LEN];
    unsigned char inbuf[CHUNK_SIZE], outbuf[CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH];

    size_t path_len = strlen(input_path);
    if (path_len > SIZE_MAX - 9) {
        fprintf(stderr, "File Path is too long.\n");
        return 0;
    }

    destination = malloc(path_len + 9);
    if (!destination)
        goto cleanup;

    snprintf(destination, path_len + 9, "%s.crypenc", input_path);

    in = fopen(input_path, "rb");
    if (!in) {
        perror("Error opening input file");
        goto cleanup;
    }

    if (RAND_bytes(salt, sizeof(salt)) != 1 ||
        RAND_bytes(nonce, sizeof(nonce)) != 1) {
        fprintf(stderr, "Secure random generation failed.\n");
        goto cleanup;
    }

    make_header(header, salt, nonce);
    if (!derive_key(passphrase, salt, key))
        goto cleanup;

    out = open_temp_file(destination, &temp_path, &temp_fd);
    if (!out) {
        perror("Error creating temporary output");
        goto cleanup;
    }

    if (fwrite(header, 1, HEADER_LEN, out) != HEADER_LEN)
        goto cleanup;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto cleanup;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1 || EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        fprintf(stderr, "File encryption initialization failed.\n");
        goto cleanup;
    }

    for (;;) {
        size_t n = fread(inbuf, 1, sizeof(inbuf), in);

        if (n > 0) {
            int produced = 0;
            if (EVP_EncryptUpdate(ctx, outbuf, &produced, inbuf, (int)n) != 1 || fwrite(outbuf, 1, (size_t)produced, out) != (size_t)produced) {
                fprintf(stderr, "File encryption/write failed.\n");
                goto cleanup;
            }
        }


        if (n < sizeof(inbuf)) {
            if (ferror(in)) {
                perror("Error reading input file");
                goto cleanup;
            }
            break;
        }
    }

    {
        int produced = 0;
        if (EVP_EncryptFinal_ex(ctx, outbuf, &produced) != 1 || fwrite(outbuf, 1, (size_t)produced, out) != (size_t)produced || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1 || fwrite(tag, 1, TAG_LEN, out) != TAG_LEN) {
            fprintf(stderr, "Could not finalize encrypted file.\n");
            goto cleanup;
        }
    }


    if (fclose(in) != 0) {
        in = NULL;
        perror("Error closing input file");
        goto cleanup;
    }
    in = NULL;

    if (!publish_temp(out, temp_path, destination, &temp_fd)) {
        out = NULL;
        temp_path = NULL;
        goto cleanup;
    }

    out = NULL;
    temp_path = NULL;
    printf("Encrypted successfully: %s\n", destination);
    ok = 1;

cleanup:
    if (in)
        fclose(in);
    if (out)
        fclose(out);
    if (temp_path) {
        unlink(temp_path);
        free(temp_path);
    }
    if (temp_fd >= 0)
        close(temp_fd);

    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(inbuf, sizeof(inbuf));
    OPENSSL_cleanse(outbuf, sizeof(outbuf));
    free(destination);
    return ok;
}

static int decrypt_file(const char *input_path, const char *passphrase)
{
    int ok = 0;
    int temp_fd = -1;
    FILE *in = NULL, *out = NULL;

    char *destination = NULL, *temp_path = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char key[KEY_LEN] = {0};

    unsigned char header[HEADER_LEN], tag[TAG_LEN];
    unsigned char inbuf[CHUNK_SIZE], outbuf[CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH];

    size_t path_len = strlen(input_path);
    const char *suffix = ".crypenc";
    size_t suffix_len = strlen(suffix);

    if (path_len <= suffix_len ||
        strcmp(input_path + path_len - suffix_len, suffix) != 0) {
        fprintf(stderr, "Input file must end in .crypenc\n");
        return 0;
    }

    size_t dest_len = path_len - suffix_len;
    destination = malloc(dest_len + 1);
    if (!destination)
        goto cleanup;

    memcpy(destination, input_path, dest_len);
    destination[dest_len] = '\0';

    if (dest_len == 0) 
    {
        fprintf(stderr, "Invalid destination filename.\n");
        goto cleanup;
    }

    in = fopen(input_path, "rb");
    if (!in) {
        perror("Error opening encrypted file");
        goto cleanup;
    }

    if (fseeko(in, 0, SEEK_END) != 0)
        goto cleanup;

    off_t file_size = ftello(in);
    if (file_size < (off_t)(HEADER_LEN + TAG_LEN)) 
    {
        fprintf(stderr, "Encrypted file is too small or invalid.\n");
        goto cleanup;
    }

    if (fseeko(in, 0, SEEK_SET) != 0 ||
        fread(header, 1, HEADER_LEN, in) != HEADER_LEN ||
        memcmp(header, MAGIC, 8) != 0) {
        fprintf(stderr, "Invalid CryptX file format.\n");
        goto cleanup;
    }

    if (fseeko(in, file_size - TAG_LEN, SEEK_SET) != 0 ||
        fread(tag, 1, TAG_LEN, in) != TAG_LEN ||
        fseeko(in, HEADER_LEN, SEEK_SET) != 0) {
        fprintf(stderr, "Could not read encrypted file.\n");
        goto cleanup;
    }

    uint64_t remaining = (uint64_t)file_size - HEADER_LEN - TAG_LEN;

    if (!derive_key(passphrase, header + 8, key))
        goto cleanup;

    out = open_temp_file(destination, &temp_path, &temp_fd);
    if (!out) {
        perror("Error creating temporary output");
        goto cleanup;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto cleanup;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1 || EVP_DecryptInit_ex(ctx, NULL, NULL, key, header + 24) != 1) {
        fprintf(stderr, "File decryption initialization failed.\n");
        goto cleanup;
    }

    while (remaining > 0) {
        size_t want = remaining > sizeof(inbuf) ?
                      sizeof(inbuf) : (size_t)remaining;
        size_t n = fread(inbuf, 1, want, in);

        if (n != want) {
            fprintf(stderr, "Unexpected end of encrypted file.\n");
            goto cleanup;
        }

        int produced = 0;
        if (EVP_DecryptUpdate(ctx, outbuf, &produced,
                              inbuf, (int)n) != 1 ||
            fwrite(outbuf, 1, (size_t)produced, out) != (size_t)produced) {
            fprintf(stderr, "File decryption/write failed.\n");
            goto cleanup;
        }

        remaining -= n;
    }

    {
        int produced = 0;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag) != 1 ||
            EVP_DecryptFinal_ex(ctx, outbuf, &produced) != 1) {
            fprintf(stderr, "Authentication failed. Wrong passphrase or modified file.\n");
            goto cleanup;
        }

        if (fwrite(outbuf, 1, (size_t)produced, out) != (size_t)produced) {
            fprintf(stderr, "Could not finish writing plaintext.\n");
            goto cleanup;
        }
    }

    if (fclose(in) != 0) {
        in = NULL;
        perror("Error closing encrypted file");
        goto cleanup;
    }
    in = NULL;

    if (!publish_temp(out, temp_path, destination, &temp_fd)) {
        out = NULL;
        temp_path = NULL;
        goto cleanup;
    }

    out = NULL;
    temp_path = NULL;
    printf("Decrypted successfully: %s\n", destination);
    ok = 1;

cleanup:
    if (in)
        fclose(in);
    if (out)
        fclose(out);
    if (temp_path) {
        unlink(temp_path);
        free(temp_path);
    }
    if (temp_fd >= 0)
        close(temp_fd);

    EVP_CIPHER_CTX_free(ctx);

    OPENSSL_cleanse(key, sizeof(key));

    OPENSSL_cleanse(inbuf, sizeof(inbuf));

    OPENSSL_cleanse(outbuf, sizeof(outbuf));

    free(destination);
    return ok;
}

int main(int argc, char *argv[])
{
    if (argc == 1) {
        banner();
        return 0;
    }

    if (argc != 4) {
        banner();
        fprintf(stderr, "Error: Invalid arguments.\n");
        return 1;
    }

    int success = 0;

    if (strcmp(argv[1], "encrypt") == 0) 
    {
        success = encrypt_text(argv[2], argv[3]);
    } 
    
    else if (strcmp(argv[1], "decrypt") == 0) 
    {
        success = decrypt_text(argv[2], argv[3]);
    } 
    
    else if (strcmp(argv[1], "encrypt-file") == 0) 
    {
        success = encrypt_file(argv[2], argv[3]);
    } 
    
    else if (strcmp(argv[1], "decrypt-file") == 0) 
    {
        success = decrypt_file(argv[2], argv[3]);
    } 
    
    else {
        banner();
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        return 1;
    }

    return success ? 0 : 1;
}
