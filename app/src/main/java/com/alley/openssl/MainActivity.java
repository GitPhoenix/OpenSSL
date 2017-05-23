package com.alley.openssl;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.util.Log;
import android.widget.TextView;

import com.alley.openssl.util.JniUtils;

public class MainActivity extends AppCompatActivity {
    private TextView tvSignature;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        initView();

        setSubView();

        initEvent();
    }

    private void initView() {
        tvSignature = (TextView) findViewById(R.id.sample_text);
    }

    private void setSubView() {
        JniUtils jni = new JniUtils();
        byte[] signature = jni.getSignature("Android CMake轻松实现基于OpenSSL的HmacSHA1签名".getBytes());
        String shiftSignature = Base64.encodeToString(signature, Base64.NO_WRAP);

        Log.i("JNI", "onCreate: 签名编码->" + shiftSignature);
        Log.i("JNI", "onCreate: 签名长度->" + shiftSignature.length());
        tvSignature.setText(shiftSignature);
    }

    private void initEvent() {

    }
}