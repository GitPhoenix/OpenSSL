#include <jni.h>
#include <string>
#include <Android/log.h>
#include <openssl/hmac.h>


#define TAG "JNI"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_alley_openssl_util_JniUtils_getSignature(JNIEnv *env, jobject instance, jbyteArray value_) {
    const char *key = "5fd6s4gs8f7s1dfv23sdf4ag65rg4arhb4fb1f54bgf5gbvf1534as";
    LOGI("HmacSHA1->准备获取待加密数据");
    jbyte *value = env->GetByteArrayElements(value_, NULL);
    LOGI("HmacSHA1->准备计算待加密数据长度");
    size_t value_Len = env->GetArrayLength(value_);

    unsigned int result_len;
    unsigned char result[EVP_MAX_MD_SIZE];
    char buff[EVP_MAX_MD_SIZE];
    char hex[EVP_MAX_MD_SIZE];

    LOGI("HmacSHA1->准备进行加密计算");
    HMAC(EVP_sha1(), key, strlen(key), (unsigned char *) value, value_Len, result, &result_len);
    LOGI("HmacSHA1->加密计算结束");

    strcpy(hex, "");
    for (int i = 0; i != result_len; i++) {
        sprintf(buff, "%02x", result[i]);
        strcat(hex, buff);
    }
    LOGI("HmacSHA1->");
    LOGI("%s", hex);

    env->ReleaseByteArrayElements(value_, value, 0);
    LOGI("HmacSHA1->jni释放数据结束");
    jbyteArray signature = env->NewByteArray(strlen(hex));
    env->SetByteArrayRegion(signature, 0, strlen(hex), (jbyte *) hex);
    LOGI("HmacSHA1->准备以ByteArray格式返回数据");
    return signature;
}

