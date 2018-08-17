//
// Created by Phoenix on 2017/6/25.
//
#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include"zsd.h"

//换成你自己的apk-sha1值
const char *signatureOfApk = "2C7040544F268F47991CDCB5F54C7ACE74B53FC2";

const char digest[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

char *sha1OfApk(JNIEnv *env, jobject context) {
    //上下文对象
    jclass clazz = env->GetObjectClass(context);
    //反射获取PackageManager
    jmethodID methodID = env->GetMethodID(clazz, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    jobject package_manager = env->CallObjectMethod(context, methodID);
    if (package_manager == NULL) {
        LOGD("sha1OfApk->package_manager is NULL!!!");
        return NULL;
    }

    //反射获取包名
    methodID = env->GetMethodID(clazz, "getPackageName", "()Ljava/lang/String;");
    jstring package_name = (jstring) env->CallObjectMethod(context, methodID);
    if (package_name == NULL) {
        LOGD("sha1OfApk->package_name is NULL!!!");
        return NULL;
    }
    env->DeleteLocalRef(clazz);

    //获取PackageInfo对象
    jclass pack_manager_class = env->GetObjectClass(package_manager);
    methodID = env->GetMethodID(pack_manager_class, "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    env->DeleteLocalRef(pack_manager_class);
    jobject package_info = env->CallObjectMethod(package_manager, methodID, package_name, 0x40);
    if (package_info == NULL) {
        LOGD("sha1OfApk->getPackageInfo() is NULL!!!");
        return NULL;
    }
    env->DeleteLocalRef(package_manager);

    //获取签名信息
    jclass package_info_class = env->GetObjectClass(package_info);
    jfieldID fieldId = env->GetFieldID(package_info_class, "signatures", "[Landroid/content/pm/Signature;");
    env->DeleteLocalRef(package_info_class);
    jobjectArray signature_object_array = (jobjectArray) env->GetObjectField(package_info, fieldId);
    if (signature_object_array == NULL) {
        LOGD("sha1OfApk->signature is NULL!!!");
        return NULL;
    }
    jobject signature_object = env->GetObjectArrayElement(signature_object_array, 0);
    env->DeleteLocalRef(package_info);

    //签名信息转换成sha1值
    jclass signature_class = env->GetObjectClass(signature_object);
    methodID = env->GetMethodID(signature_class, "toByteArray", "()[B");
    env->DeleteLocalRef(signature_class);

    jbyteArray signature_byte = (jbyteArray) env->CallObjectMethod(signature_object, methodID);
    jclass byte_array_input_class = env->FindClass("java/io/ByteArrayInputStream");
    methodID = env->GetMethodID(byte_array_input_class, "<init>", "([B)V");
    jobject byte_array_input = env->NewObject(byte_array_input_class, methodID, signature_byte);
    jclass certificate_factory_class = env->FindClass("java/security/cert/CertificateFactory");
    methodID = env->GetStaticMethodID(certificate_factory_class, "getInstance", "(Ljava/lang/String;)Ljava/security/cert/CertificateFactory;");
    jstring x_509_jstring = env->NewStringUTF("X.509");
    jobject cert_factory = env->CallStaticObjectMethod(certificate_factory_class, methodID, x_509_jstring);
    methodID = env->GetMethodID(certificate_factory_class, "generateCertificate", ("(Ljava/io/InputStream;)Ljava/security/cert/Certificate;"));
    jobject x509_cert = env->CallObjectMethod(cert_factory, methodID, byte_array_input);
    env->DeleteLocalRef(certificate_factory_class);

    jclass x509_cert_class = env->GetObjectClass(x509_cert);
    methodID = env->GetMethodID(x509_cert_class, "getEncoded", "()[B");
    jbyteArray cert_byte = (jbyteArray) env->CallObjectMethod(x509_cert, methodID);
    env->DeleteLocalRef(x509_cert_class);

    jclass message_digest_class = env->FindClass("java/security/MessageDigest");
    methodID = env->GetStaticMethodID(message_digest_class, "getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    jstring sha1_jstring = env->NewStringUTF("SHA1");
    jobject sha1_digest = env->CallStaticObjectMethod(message_digest_class, methodID, sha1_jstring);
    methodID = env->GetMethodID(message_digest_class, "digest", "([B)[B");
    jbyteArray sha1_byte = (jbyteArray) env->CallObjectMethod(sha1_digest, methodID, cert_byte);
    env->DeleteLocalRef(message_digest_class);

    //转换成char
    jsize arraySize = env->GetArrayLength(sha1_byte);
    jbyte *sha1 = env->GetByteArrayElements(sha1_byte, NULL);
    char *hex = new char[arraySize * 2 + 1];
    for (int i = 0; i < arraySize; ++i) {
        hex[2 * i] = digest[((unsigned char) sha1[i]) / 16];
        hex[2 * i + 1] = digest[((unsigned char) sha1[i]) % 16];
    }
    hex[arraySize * 2] = '\0';

    LOGD("sha1OfApk->sha1 %s ", hex);
    return hex;
}

jboolean verifySha1OfApk(JNIEnv *env, jobject context) {
    char *signature = sha1OfApk(env, context);
    //比较签名
    if (strcmp(signature, signatureOfApk) == 0) {
        LOGD("sha1OfApk->签名验证成功");
        return static_cast<jboolean>(true);
    }
    LOGD("sha1OfApk->签名验证失败");
    return static_cast<jboolean>(false);
}
