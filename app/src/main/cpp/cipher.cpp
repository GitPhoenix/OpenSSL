#include <jni.h>
#include <string>
#include <Android/log.h>
#include <openssl/hmac.h>
#include<openssl/rsa.h>
#include<openssl/pem.h>
#include <openssl/md5.h>


#define TAG "body"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#define LOGF(...) __android_log_print(ANDROID_LOG_FATAL, TAG ,__VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG ,__VA_ARGS__)


extern "C" {
JNIEXPORT jbyteArray JNICALL
Java_com_alley_openssl_util_JniUtils_encodeByHmacSHA1(JNIEnv *env, jobject instance, jbyteArray src_) {
    LOGI("HmacSHA1->HMAC: Hash-based Message Authentication Code，即基于Hash的消息鉴别码");
    const char *key = "zsdApp@2238700@4008555056";
    jbyte *src = env->GetByteArrayElements(src_, NULL);
    jsize src_Len = env->GetArrayLength(src_);

    unsigned int result_len;
    unsigned char result[EVP_MAX_MD_SIZE];
    char buff[EVP_MAX_MD_SIZE];
    char hex[EVP_MAX_MD_SIZE];

    LOGI("HmacSHA1->调用函数进行哈希计算");
    HMAC(EVP_sha1(), key, strlen(key), (unsigned char *) src, src_Len, result, &result_len);

    strcpy(hex, "");
    LOGI("HmacSHA1->把哈希值按%%02x格式定向到缓冲区");
    for (int i = 0; i != result_len; i++) {
        sprintf(buff, "%02x", result[i]);
        strcat(hex, buff);
    }
    LOGI("HmacSHA1->%s", hex);

    LOGI("HmacSHA1->从jni释放数据指针");
    env->ReleaseByteArrayElements(src_, src, 0);

    jbyteArray signature = env->NewByteArray(strlen(hex));
    LOGI("HmacSHA1->在堆中分配ByteArray数组对象成功，将拷贝数据到数组中");
    env->SetByteArrayRegion(signature, 0, strlen(hex), (jbyte *) hex);

    return signature;
}

JNIEXPORT jstring JNICALL
Java_com_alley_openssl_util_JniUtils_encodeBySHA1(JNIEnv *env, jobject instance, jbyteArray src_) {
    jbyte *src = env->GetByteArrayElements(src_, NULL);
    jsize src_Len = env->GetArrayLength(src_);

    char buff[SHA_DIGEST_LENGTH];
    char hex[SHA_DIGEST_LENGTH * 2];
    unsigned char digest[SHA_DIGEST_LENGTH];

//    SHA1((unsigned char *)src, src_Len, digest);

    SHA_CTX ctx;
    SHA1_Init(&ctx);
    LOGI("SHA1->正在进行SHA1哈希计算");
    SHA1_Update(&ctx, src, src_Len);
    SHA1_Final(digest, &ctx);

    OPENSSL_cleanse(&ctx, sizeof(ctx));

    strcpy(hex, "");
    LOGI("SHA1->把哈希值按%%02x格式定向到缓冲区");
    for (int i = 0; i != sizeof(digest); i++) {
        sprintf(buff, "%02x", digest[i]);
        strcat(hex, buff);
    }
    LOGI("SHA1->%s", hex);

    LOGI("SHA1->从jni释放数据指针");
    env->ReleaseByteArrayElements(src_, src, 0);

    return env->NewStringUTF(hex);
}

JNIEXPORT jstring JNICALL
Java_com_alley_openssl_util_JniUtils_encodeBySHA224(JNIEnv *env, jobject instance, jbyteArray src_) {
    jbyte *src = env->GetByteArrayElements(src_, NULL);
    jsize src_Len = env->GetArrayLength(src_);

    char buff[SHA224_DIGEST_LENGTH];
    char hex[SHA224_DIGEST_LENGTH * 2];
    unsigned char digest[SHA224_DIGEST_LENGTH];

//    SHA224((unsigned char *)src, src_Len, digest);

    SHA256_CTX ctx;
    SHA224_Init(&ctx);
    LOGI("SHA224->正在进行SHA224哈希计算");
    SHA224_Update(&ctx, src, src_Len);
    SHA224_Final(digest, &ctx);

    OPENSSL_cleanse(&ctx, sizeof(ctx));

    strcpy(hex, "");
    LOGI("SHA224->把哈希值按%%02x格式定向到缓冲区");
    for (int i = 0; i != sizeof(digest); i++) {
        sprintf(buff, "%02x", digest[i]);
        strcat(hex, buff);
    }
    LOGI("SHA224->%s", hex);

    LOGI("SHA224->从jni释放数据指针");
    env->ReleaseByteArrayElements(src_, src, 0);

    return env->NewStringUTF(hex);
}

JNIEXPORT jstring JNICALL
Java_com_alley_openssl_util_JniUtils_encodeBySHA256(JNIEnv *env, jobject instance, jbyteArray src_) {
    jbyte *src = env->GetByteArrayElements(src_, NULL);
    jsize src_Len = env->GetArrayLength(src_);

    char buff[SHA256_DIGEST_LENGTH];
    char hex[SHA256_DIGEST_LENGTH * 2];
    unsigned char digest[SHA256_DIGEST_LENGTH];

//    SHA256((unsigned char *)src, src_Len, digest);

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    LOGI("SHA256->正在进行SHA256哈希计算");
    SHA256_Update(&ctx, src, src_Len);
    SHA256_Final(digest, &ctx);

    OPENSSL_cleanse(&ctx, sizeof(ctx));

    strcpy(hex, "");
    LOGI("SHA256->把哈希值按%%02x格式定向到缓冲区");
    for (int i = 0; i != sizeof(digest); i++) {
        sprintf(buff, "%02x", digest[i]);
        strcat(hex, buff);
    }
    LOGI("SHA256->%s", hex);

    LOGI("SHA256->从jni释放数据指针");
    env->ReleaseByteArrayElements(src_, src, 0);

    return env->NewStringUTF(hex);
}

JNIEXPORT jstring JNICALL
Java_com_alley_openssl_util_JniUtils_encodeBySHA384(JNIEnv *env, jobject instance, jbyteArray src_) {
    jbyte *src = env->GetByteArrayElements(src_, NULL);
    jsize src_Len = env->GetArrayLength(src_);

    char buff[SHA384_DIGEST_LENGTH];
    char hex[SHA384_DIGEST_LENGTH * 2];
    unsigned char digest[SHA384_DIGEST_LENGTH];

//    SHA384((unsigned char *)src, src_Len, digest);

    SHA512_CTX ctx;
    SHA384_Init(&ctx);
    LOGI("SHA384->正在进行SHA384哈希计算");
    SHA384_Update(&ctx, src, src_Len);
    SHA384_Final(digest, &ctx);

    OPENSSL_cleanse(&ctx, sizeof(ctx));

    strcpy(hex, "");
    LOGI("SHA384->把哈希值按%%02x格式定向到缓冲区");
    for (int i = 0; i != sizeof(digest); i++) {
        sprintf(buff, "%02x", digest[i]);
        strcat(hex, buff);
    }
    LOGI("SHA384->%s", hex);

    LOGI("SHA384->从jni释放数据指针");
    env->ReleaseByteArrayElements(src_, src, 0);

    return env->NewStringUTF(hex);
}

JNIEXPORT jstring JNICALL
Java_com_alley_openssl_util_JniUtils_encodeBySHA512(JNIEnv *env, jobject instance, jbyteArray src_) {
    jbyte *src = env->GetByteArrayElements(src_, NULL);
    jsize src_Len = env->GetArrayLength(src_);

    char buff[SHA512_DIGEST_LENGTH];
    char hex[SHA512_DIGEST_LENGTH * 2];
    unsigned char digest[SHA512_DIGEST_LENGTH];

//    SHA512((unsigned char *)src, src_Len, digest);

    SHA512_CTX ctx;
    SHA512_Init(&ctx);
    LOGI("SHA512->正在进行SHA256哈希计算");
    SHA512_Update(&ctx, src, src_Len);
    SHA512_Final(digest, &ctx);

    OPENSSL_cleanse(&ctx, sizeof(ctx));

    strcpy(hex, "");
    LOGI("SHA512->把哈希值按%%02x格式定向到缓冲区");
    for (int i = 0; i != sizeof(digest); i++) {
        sprintf(buff, "%02x", digest[i]);
        strcat(hex, buff);
    }
    LOGI("SHA512->%s", hex);

    LOGI("SHA512->从jni释放数据指针");
    env->ReleaseByteArrayElements(src_, src, 0);

    return env->NewStringUTF(hex);
}

JNIEXPORT jbyteArray JNICALL
Java_com_alley_openssl_util_JniUtils_encodeByAES(JNIEnv *env, jobject instance, jbyteArray keys_, jbyteArray src_) {
    LOGI("AES->对称密钥，也就是说加密和解密用的是同一个密钥");
    const unsigned char *iv = (const unsigned char *) "01234567890123456";
    jbyte *keys = env->GetByteArrayElements(keys_, NULL);
    jbyte *src = env->GetByteArrayElements(src_, NULL);
    jsize src_Len = env->GetArrayLength(src_);

    int outlen = 0, cipherText_len = 0;

    unsigned char *out = (unsigned char *) malloc(src_Len);
    //清空内存空间
    memset(out, 0, src_Len);

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    LOGI("AES->指定加密算法，初始化加密key/iv");
    EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, (const unsigned char *) keys, iv);
    LOGI("AES->进行加密操作");
    EVP_EncryptUpdate(&ctx, out, &outlen, (const unsigned char *) src, src_Len);
    cipherText_len = outlen;

    LOGI("AES->结束加密操作");
    EVP_EncryptFinal_ex(&ctx, out + outlen, &outlen);
    cipherText_len += outlen;

    LOGI("AES->EVP_CIPHER_CTX_cleanup");
    EVP_CIPHER_CTX_cleanup(&ctx);

    LOGI("AES->从jni释放数据指针");
    env->ReleaseByteArrayElements(keys_, keys, 0);
    env->ReleaseByteArrayElements(src_, src, 0);

    jbyteArray signature = env->NewByteArray(cipherText_len);
    LOGI("AES->在堆中分配ByteArray数组对象成功，将拷贝数据到数组中");
    env->SetByteArrayRegion(signature, 0, cipherText_len, (jbyte *) out);
    LOGI("AES->释放内存");
    free(out);

    return signature;
}

JNIEXPORT jbyteArray JNICALL
Java_com_alley_openssl_util_JniUtils_decodeByAES(JNIEnv *env, jobject instance, jbyteArray keys_, jbyteArray src_) {
    LOGI("AES->对称密钥，也就是说加密和解密用的是同一个密钥");
    const unsigned char *iv = (const unsigned char *) "01234567890123456";
    jbyte *keys = env->GetByteArrayElements(keys_, NULL);
    jbyte *src = env->GetByteArrayElements(src_, NULL);
    jsize src_Len = env->GetArrayLength(src_);

    int outlen = 0, plaintext_len = 0;

    unsigned char *out  = (unsigned char *) malloc(src_Len);
    memset(out, 0, src_Len);

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    LOGI("AES->指定解密算法，初始化解密key/iv");
    EVP_DecryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, (const unsigned char *) keys, iv);
    LOGI("AES->进行解密操作");
    EVP_DecryptUpdate(&ctx, out, &outlen, (const unsigned char *) src, src_Len);
    plaintext_len = outlen;

    LOGI("AES->结束解密操作");
    EVP_DecryptFinal_ex(&ctx, out + outlen, &outlen);
    plaintext_len += outlen;

    LOGI("AES->EVP_CIPHER_CTX_cleanup");
    EVP_CIPHER_CTX_cleanup(&ctx);

    LOGI("AES->从jni释放数据指针");
    env->ReleaseByteArrayElements(keys_, keys, 0);
    env->ReleaseByteArrayElements(src_, src, 0);

    jbyteArray signature = env->NewByteArray(plaintext_len);
    LOGI("AES->在堆中分配ByteArray数组对象成功，将拷贝数据到数组中");
    env->SetByteArrayRegion(signature, 0, plaintext_len, (jbyte *) out);
    LOGI("AES->释放内存");
    free(out);

    return signature;
}

JNIEXPORT jbyteArray JNICALL
Java_com_alley_openssl_util_JniUtils_encodeByRSAPubKey(JNIEnv *env, jobject instance, jbyteArray keys_, jbyteArray src_) {
    LOGI("RSA->非对称密码算法，也就是说该算法需要一对密钥，使用其中一个加密，则需要用另一个才能解密");
    jbyte *keys = env->GetByteArrayElements(keys_, NULL);
    jbyte *src = env->GetByteArrayElements(src_, NULL);
    jsize src_Len = env->GetArrayLength(src_);

    int ret = 0, src_flen = 0, cipherText_offset = 0, desText_len = 0, src_offset = 0;

    RSA *rsa = NULL;
    BIO *keybio = NULL;

    LOGI("RSA->从字符串读取RSA公钥");
    keybio = BIO_new_mem_buf(keys, -1);
    LOGI("RSA->从bio结构中得到RSA结构");
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, NULL, NULL, NULL);
    LOGI("RSA->释放BIO");
    BIO_free_all(keybio);

    int flen = RSA_size(rsa);
    desText_len = flen * (src_Len / flen + 1);

    unsigned char *srcOrigin = (unsigned char *) malloc(src_Len);
    unsigned char *cipherText = (unsigned char *) malloc(flen);
    unsigned char *desText = (unsigned char *) malloc(desText_len);
    memset(desText, 0, desText_len);

    memset(srcOrigin, 0, src_Len);
    memcpy(srcOrigin, src, src_Len);

    LOGI("RSA->进行公钥加密操作");
    //RSA_PKCS1_PADDING最大加密长度：128-11；RSA_NO_PADDING最大加密长度：128
    for (int i = 0; i <= src_Len / (flen - 11); i++) {
        src_flen = (i == src_Len / (flen - 11)) ? src_Len % (flen - 11) : flen - 11;
        if (src_flen == 0) {
            break;
        }

        memset(cipherText, 0, flen);
        ret = RSA_public_encrypt(src_flen, srcOrigin + src_offset, cipherText, rsa, RSA_PKCS1_PADDING);

        memcpy(desText + cipherText_offset, cipherText, ret);
        cipherText_offset += ret;
        src_offset += src_flen;
    }

    RSA_free(rsa);
    LOGI("RSA->CRYPTO_cleanup_all_ex_data");
    CRYPTO_cleanup_all_ex_data();

    LOGI("RSA->从jni释放数据指针");
    env->ReleaseByteArrayElements(keys_, keys, 0);
    env->ReleaseByteArrayElements(src_, src, 0);

    jbyteArray cipher = env->NewByteArray(cipherText_offset);
    LOGI("RSA->在堆中分配ByteArray数组对象成功，将拷贝数据到数组中");
    env->SetByteArrayRegion(cipher, 0, cipherText_offset, (jbyte *) desText);
    LOGI("RSA->释放内存");
    free(srcOrigin);
    free(cipherText);
    free(desText);

    return cipher;
}

JNIEXPORT jbyteArray JNICALL
Java_com_alley_openssl_util_JniUtils_decodeByRSAPrivateKey(JNIEnv *env, jobject instance, jbyteArray keys_, jbyteArray src_) {
    LOGI("RSA->非对称密码算法，也就是说该算法需要一对密钥，使用其中一个加密，则需要用另一个才能解密");
    jbyte *keys = env->GetByteArrayElements(keys_, NULL);
    jbyte *src = env->GetByteArrayElements(src_, NULL);
    jsize src_Len = env->GetArrayLength(src_);

    int ret = 0, src_flen = 0, plaintext_offset = 0, descText_len = 0, src_offset = 0;

    RSA *rsa = NULL;
    BIO *keybio = NULL;

    LOGI("RSA->从字符串读取RSA私钥");
    keybio = BIO_new_mem_buf(keys, -1);
    LOGI("RSA->从bio结构中得到RSA结构");
    rsa = PEM_read_bio_RSAPrivateKey(keybio, NULL, NULL, NULL);
    LOGI("RSA->释放BIO");
    BIO_free_all(keybio);

    int flen = RSA_size(rsa);
    descText_len = (flen - 11) * (src_Len / flen + 1);

    unsigned char *srcOrigin = (unsigned char *) malloc(src_Len);
    unsigned char *plaintext = (unsigned char *) malloc(flen - 11);
    unsigned char *desText = (unsigned char *) malloc(descText_len);
    memset(desText, 0, descText_len);

    memset(srcOrigin, 0, src_Len);
    memcpy(srcOrigin, src, src_Len);

    LOGI("RSA->进行私钥解密操作");
    //一次性解密数据最大字节数RSA_size
    for (int i = 0; i <= src_Len / flen; i++) {
        src_flen = (i == src_Len / flen) ? src_Len % flen : flen;
        if (src_flen == 0) {
            break;
        }

        memset(plaintext, 0, flen - 11);
        ret = RSA_private_decrypt(src_flen, srcOrigin + src_offset, plaintext, rsa, RSA_PKCS1_PADDING);

        memcpy(desText + plaintext_offset, plaintext, ret);
        plaintext_offset += ret;
        src_offset += src_flen;
    }

    RSA_free(rsa);
    LOGI("RSA->CRYPTO_cleanup_all_ex_data");
    CRYPTO_cleanup_all_ex_data();

    LOGI("RSA->从jni释放数据指针");
    env->ReleaseByteArrayElements(keys_, keys, 0);
    env->ReleaseByteArrayElements(src_, src, 0);

    jbyteArray cipher = env->NewByteArray(plaintext_offset);
    LOGI("RSA->在堆中分配ByteArray数组对象成功，将拷贝数据到数组中");
    env->SetByteArrayRegion(cipher, 0, plaintext_offset, (jbyte *) desText);
    LOGI("RSA->释放内存");
    free(srcOrigin);
    free(plaintext);
    free(desText);

    return cipher;
}

JNIEXPORT jbyteArray JNICALL
Java_com_alley_openssl_util_JniUtils_encodeByRSAPrivateKey(JNIEnv *env, jobject instance, jbyteArray keys_, jbyteArray src_) {
    LOGI("RSA->非对称密码算法，也就是说该算法需要一对密钥，使用其中一个加密，则需要用另一个才能解密");
    jbyte *keys = env->GetByteArrayElements(keys_, NULL);
    jbyte *src = env->GetByteArrayElements(src_, NULL);
    jsize src_Len = env->GetArrayLength(src_);

    int ret = 0, src_flen = 0, cipherText_offset = 0, desText_len = 0, src_offset = 0;

    RSA *rsa = NULL;
    BIO *keybio = NULL;

    LOGI("RSA->从字符串读取RSA私钥");
    keybio = BIO_new_mem_buf(keys, -1);
    LOGI("RSA->从bio结构中得到RSA结构");
    rsa = PEM_read_bio_RSAPrivateKey(keybio, NULL, NULL, NULL);
    LOGI("RSA->释放BIO");
    BIO_free_all(keybio);

    int flen = RSA_size(rsa);
    desText_len = flen * (src_Len / flen + 1);

    unsigned char *srcOrigin = (unsigned char *) malloc(src_Len);
    unsigned char *cipherText = (unsigned char *) malloc(flen);
    unsigned char *desText = (unsigned char *) malloc(desText_len);
    memset(desText, 0, desText_len);

    memset(srcOrigin, 0, src_Len);
    memcpy(srcOrigin, src, src_Len);

    LOGI("RSA->进行私钥加密操作");
    //RSA_PKCS1_PADDING最大加密长度：128-11；RSA_NO_PADDING最大加密长度：128
    for (int i = 0; i <= src_Len / (flen - 11); i++) {
        src_flen = (i == src_Len / (flen - 11)) ? src_Len % (flen - 11) : flen - 11;
        if (src_flen == 0) {
            break;
        }

        memset(cipherText, 0, flen);
        ret = RSA_private_encrypt(src_flen, srcOrigin + src_offset, cipherText, rsa, RSA_PKCS1_PADDING);

        memcpy(desText + cipherText_offset, cipherText, ret);
        cipherText_offset += ret;
        src_offset += src_flen;
    }

    RSA_free(rsa);
    LOGI("RSA->CRYPTO_cleanup_all_ex_data");
    CRYPTO_cleanup_all_ex_data();

    LOGI("RSA->从jni释放数据指针");
    env->ReleaseByteArrayElements(keys_, keys, 0);
    env->ReleaseByteArrayElements(src_, src, 0);

    jbyteArray cipher = env->NewByteArray(cipherText_offset);
    LOGI("RSA->在堆中分配ByteArray数组对象成功，将拷贝数据到数组中");
    env->SetByteArrayRegion(cipher, 0, cipherText_offset, (jbyte *) desText);
    LOGI("RSA->释放内存");
    free(srcOrigin);
    free(cipherText);
    free(desText);

    return cipher;
}

JNIEXPORT jbyteArray JNICALL
Java_com_alley_openssl_util_JniUtils_decodeByRSAPubKey(JNIEnv *env, jobject instance, jbyteArray keys_, jbyteArray src_) {
    LOGI("RSA->非对称密码算法，也就是说该算法需要一对密钥，使用其中一个加密，则需要用另一个才能解密");
    jbyte *keys = env->GetByteArrayElements(keys_, NULL);
    jbyte *src = env->GetByteArrayElements(src_, NULL);
    jsize src_Len = env->GetArrayLength(src_);

    int ret = 0, src_flen = 0, plaintext_offset = 0, desText_len = 0, src_offset = 0;

    RSA *rsa = NULL;
    BIO *keybio = NULL;

    LOGI("RSA->从字符串读取RSA公钥");
    keybio = BIO_new_mem_buf(keys, -1);
    LOGI("RSA->从bio结构中得到RSA结构");
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, NULL, NULL, NULL);
    LOGI("RSA->释放BIO");
    BIO_free_all(keybio);

    int flen = RSA_size(rsa);
    desText_len = (flen - 11) * (src_Len / flen + 1);

    unsigned char *srcOrigin = (unsigned char *) malloc(src_Len);
    unsigned char *plaintext = (unsigned char *) malloc(flen - 11);
    unsigned char *desText = (unsigned char *) malloc(desText_len);
    memset(desText, 0, desText_len);

    memset(srcOrigin, 0, src_Len);
    memcpy(srcOrigin, src, src_Len);

    LOGI("RSA->进行公钥解密操作");
    //一次性解密数据最大字节数RSA_size
    for (int i = 0; i <= src_Len / flen; i++) {
        src_flen = (i == src_Len / flen) ? src_Len % flen : flen;
        if (src_flen <= 0) {
            break;
        }

        memset(plaintext, 0, flen - 11);
        ret = RSA_public_decrypt(src_flen, srcOrigin + src_offset, plaintext, rsa, RSA_PKCS1_PADDING);

        memcpy(desText + plaintext_offset, plaintext, ret);
        plaintext_offset += ret;
        src_offset += src_flen;
    }

    RSA_free(rsa);
    LOGI("RSA->CRYPTO_cleanup_all_ex_data");
    CRYPTO_cleanup_all_ex_data();

    LOGI("RSA->从jni释放数据指针");
    env->ReleaseByteArrayElements(keys_, keys, 0);
    env->ReleaseByteArrayElements(src_, src, 0);

    jbyteArray cipher = env->NewByteArray(plaintext_offset);
    LOGI("RSA->在堆中分配ByteArray数组对象成功，将拷贝数据到数组中");
    env->SetByteArrayRegion(cipher, 0, plaintext_offset, (jbyte *) desText);
    LOGI("RSA->释放内存");
    free(srcOrigin);
    free(plaintext);
    free(desText);

    return cipher;
}

JNIEXPORT jbyteArray JNICALL
Java_com_alley_openssl_util_JniUtils_signByRSAPrivateKey(JNIEnv *env, jobject instance, jbyteArray keys_, jbyteArray src_) {
    LOGI("RSA->非对称密码算法，也就是说该算法需要一对密钥，使用其中一个加密，则需要用另一个才能解密");
    jbyte *keys = env->GetByteArrayElements(keys_, NULL);
    jbyte *src = env->GetByteArrayElements(src_, NULL);
    jsize src_Len = env->GetArrayLength(src_);

    unsigned int siglen = 0;
    unsigned char digest[SHA_DIGEST_LENGTH];

    RSA *rsa = NULL;
    BIO *keybio = NULL;

    LOGI("RSA->从字符串读取RSA公钥");
    keybio = BIO_new_mem_buf(keys, -1);
    LOGI("RSA->从bio结构中得到RSA结构");
    rsa = PEM_read_bio_RSAPrivateKey(keybio, NULL, NULL, NULL);
    LOGI("RSA->释放BIO");
    BIO_free_all(keybio);

    unsigned char *sign = (unsigned char *) malloc(129);
    memset(sign, 0, 129);

    SHA1((const unsigned char *) src, src_Len, digest);
    RSA_sign(NID_sha1, digest, SHA_DIGEST_LENGTH, sign, &siglen, rsa);

    RSA_free(rsa);
    LOGI("RSA->CRYPTO_cleanup_all_ex_data");
    CRYPTO_cleanup_all_ex_data();

    LOGI("RSA->从jni释放数据指针");
    env->ReleaseByteArrayElements(keys_, keys, 0);
    env->ReleaseByteArrayElements(src_, src, 0);

    jbyteArray cipher = env->NewByteArray(siglen);
    LOGI("RSA->在堆中分配ByteArray数组对象成功，将拷贝数据到数组中");
    env->SetByteArrayRegion(cipher, 0, siglen, (jbyte *) sign);
    LOGI("RSA->释放内存");
    free(sign);

    return cipher;
}

JNIEXPORT jint JNICALL
Java_com_alley_openssl_util_JniUtils_verifyByRSAPubKey(JNIEnv *env, jobject instance, jbyteArray keys_, jbyteArray src_, jbyteArray sign_) {
    LOGI("RSA->非对称密码算法，也就是说该算法需要一对密钥，使用其中一个加密，则需要用另一个才能解密");
    jbyte *keys = env->GetByteArrayElements(keys_, NULL);
    jbyte *src = env->GetByteArrayElements(src_, NULL);
    jbyte *sign = env->GetByteArrayElements(sign_, NULL);

    jsize src_Len = env->GetArrayLength(src_);
    jsize siglen = env->GetArrayLength(sign_);

    int ret;
    unsigned char digest[SHA_DIGEST_LENGTH];

    RSA *rsa = NULL;
    BIO *keybio = NULL;

    LOGI("RSA->从字符串读取RSA公钥");
    keybio = BIO_new_mem_buf(keys, -1);
    LOGI("RSA->从bio结构中得到RSA结构");
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, NULL, NULL, NULL);
    LOGI("RSA->释放BIO");
    BIO_free_all(keybio);

    SHA1((const unsigned char *) src, src_Len, digest);
    ret = RSA_verify(NID_sha1, digest, SHA_DIGEST_LENGTH, (const unsigned char *) sign, siglen, rsa);

    RSA_free(rsa);
    LOGI("RSA->CRYPTO_cleanup_all_ex_data");
    CRYPTO_cleanup_all_ex_data();

    LOGI("RSA->从jni释放数据指针");
    env->ReleaseByteArrayElements(keys_, keys, 0);
    env->ReleaseByteArrayElements(src_, src, 0);
    env->ReleaseByteArrayElements(sign_, sign, 0);

    return ret;
}

JNIEXPORT jbyteArray JNICALL
Java_com_alley_openssl_util_JniUtils_xOr(JNIEnv *env, jobject instance, jbyteArray src_) {
    LOGI("XOR->异或加解密: 相同为假，不同为真");
    const char keys[] = "zsd2238700";
    jbyte *src = env->GetByteArrayElements(src_, NULL);
    jsize src_Len = env->GetArrayLength(src_);

    char *chs = (char *) malloc(src_Len);
    memset(chs, 0, src_Len);
    memcpy(chs, src, src_Len);

    for (int i = 0; i < src_Len; i++) {
        *chs = *chs ^ keys[i % strlen(keys)];
        chs++;
    }
    chs = chs - src_Len;

    LOGI("XOR->从jni释放数据指针");
    env->ReleaseByteArrayElements(src_, src, 0);

    jbyteArray cipher = env->NewByteArray(src_Len);
    LOGI("XOR->在堆中分配ByteArray数组对象成功，将拷贝数据到数组中");
    env->SetByteArrayRegion(cipher, 0, src_Len, (const jbyte *) chs);
    LOGI("XOR->释放内存");
    free(chs);

    return cipher;
}

JNIEXPORT jstring JNICALL
Java_com_alley_openssl_util_JniUtils_MD5(JNIEnv *env, jobject instance, jbyteArray src_) {
    LOGI("MD5->信息摘要算法第五版");
    jbyte *src = env->GetByteArrayElements(src_, NULL);
    jsize src_Len = env->GetArrayLength(src_);

    char buff[3] = {'\0'};
    char hex[33] = {'\0'};
    unsigned char md5Text[MD5_DIGEST_LENGTH];

    MD5_CTX ctx;
    MD5_Init(&ctx);
    LOGI("MD5->进行MD5消息摘要计算");
    MD5_Update(&ctx, src, src_Len);
    MD5_Final(md5Text, &ctx);

    strcpy(hex, "");
    LOGI("MD5->把哈希值按%%02x格式定向到缓冲区");
    for (int i = 0; i != sizeof(md5Text); i++) {
        sprintf(buff, "%02x", md5Text[i]);
        strcat(hex, buff);
    }
    LOGI("MD5->%s", hex);

    LOGI("MD5->从jni释放数据指针");
    env->ReleaseByteArrayElements(src_, src, 0);

    return env->NewStringUTF(hex);
}

}