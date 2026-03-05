package org.wso2.carbon.extension.captcha;

public class CustomCaptchaFilterConstants {

    private CustomCaptchaFilterConstants() {
        // prevent instantiation
    }

    public static final String RECAPTCHA_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify";
    public static final String COMMONAUTH_PATH = "/commonauth";
    public static final String RECAPTCHA_PARAM = "g-recaptcha-response";

    public static final String PARAM_SESSION_DATA_KEY   = "sessionDataKey";
    public static final String PARAM_RELYING_PARTY      = "relyingParty";


}