package org.wso2.carbon.extension.captcha;

public class CustomCaptchaFilterConstants {

    private CustomCaptchaFilterConstants() {
        // prevent instantiation
    }

    public static final String RECAPTCHA_PARAM = "g-recaptcha-response";

    public static final String CUSTOM_CAPTCHA_BLOCK = "[custom.captcha]";
;    public static final String CLIENT_IDs  = "clientIds";
    public static final String SITE_VERIFY_URL = "siteVerifyUrl";
    public static final String SECRET_KEY = "secret_key";
    public static final String PROXY_HOST = "proxyHost";
    public static final String PROXY_PORT = "proxyPort";
}