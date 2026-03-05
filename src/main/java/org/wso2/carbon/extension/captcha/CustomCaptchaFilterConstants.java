package org.wso2.carbon.extension.captcha;

public class CustomCaptchaFilterConstants {

    private CustomCaptchaFilterConstants() {
        // prevent instantiation
    }

    // -----------------------------------------------------------------------
    // Filter init-param names (configured in deployment.toml)
    // -----------------------------------------------------------------------
    public static final String PARAM_TARGET_SP       = "targetServiceProvider";
    public static final String PARAM_SECRET_KEY      = "reCaptchaSecretKey";
    public static final String PARAM_VERIFY_URL      = "reCaptchaVerifyUrl";
    public static final String PARAM_COMMONAUTH_PATH = "commonAuthPath";

    // -----------------------------------------------------------------------
    // Request parameter names
    // -----------------------------------------------------------------------
    public static final String RECAPTCHA_RESPONSE_PARAM = "g-recaptcha-response";
    public static final String PARAM_SESSION_DATA_KEY   = "sessionDataKey";
    public static final String PARAM_RELYING_PARTY      = "relyingParty";

    // -----------------------------------------------------------------------
    // Default values
    // -----------------------------------------------------------------------
    public static final String DEFAULT_TARGET_SP       = "MY_TARGET_APP";
    public static final String DEFAULT_SECRET_KEY      = "YOUR_SECRET_KEY";
    public static final String DEFAULT_VERIFY_URL      = "https://www.google.com/recaptcha/api/siteverify";
    public static final String DEFAULT_COMMONAUTH_PATH = "/commonauth";

    // -----------------------------------------------------------------------
    // HTTP
    // -----------------------------------------------------------------------
    public static final String HTTP_POST           = "POST";
    public static final String CONTENT_TYPE_FORM   = "application/x-www-form-urlencoded";

    // -----------------------------------------------------------------------
    // Google verify response
    // -----------------------------------------------------------------------
    public static final String RECAPTCHA_SUCCESS_SPACED  = "\"success\": true";
    public static final String RECAPTCHA_SUCCESS_COMPACT = "\"success\":true";

    // -----------------------------------------------------------------------
    // Error messages (matched against resource bundle keys in login.jsp)
    // -----------------------------------------------------------------------
    public static final String ERROR_RECAPTCHA_MISSING = "recaptcha.missing";
    public static final String ERROR_RECAPTCHA_FAILED  = "recaptcha.failed";

    // -----------------------------------------------------------------------
    // Logging
    // -----------------------------------------------------------------------
    public static final String LOG_INIT             = "[CustomCaptchaFilter] Initialized for SP: ";
    public static final String LOG_INTERCEPTING     = "[CustomCaptchaFilter] Intercepting /commonauth POST for target SP.";
    public static final String LOG_TOKEN_MISSING    = "[CustomCaptchaFilter] Missing reCAPTCHA token — redirecting.";
    public static final String LOG_VERIFY_FAILED    = "[CustomCaptchaFilter] reCAPTCHA verification failed — redirecting.";
    public static final String LOG_VERIFY_SUCCESS   = "[CustomCaptchaFilter] reCAPTCHA verified successfully.";
    public static final String LOG_VERIFY_API_ERROR = "[CustomCaptchaFilter] Error calling reCAPTCHA verify API: ";
    public static final String LOG_DESTROYED        = "[CustomCaptchaFilter] Destroyed.";
}