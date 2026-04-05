package org.wso2.carbon.extension.captcha;

import javax.servlet.*;
import javax.servlet.http.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;

import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;

import static org.wso2.carbon.extension.captcha.CustomCaptchaFilterConstants.*;

public class CustomCaptchaFilter implements Filter {

    private static final Log log = LogFactory.getLog(CustomCaptchaFilter.class);

    private static volatile boolean initialized = false;

    private static String siteVerifyUrl;
    private static String recaptchaSecret;
    private static Set<String> targetClientIds = Collections.emptySet();
    private static String proxyHost;
    private static int proxyPort = -1;

    private static final int CONNECT_TIMEOUT = 5000;
    private static final int READ_TIMEOUT = 5000;

    @Override
    public void init(FilterConfig filterConfig) {
        if (initialized) return;

        synchronized (CustomCaptchaFilter.class) {
            if (!initialized) {
                log.info("Initializing CustomCaptchaFilter...");
                loadCaptchaConfig();
                initialized = true;
            }
        }
    }

    private void loadCaptchaConfig() {
        String carbonHome = System.getProperty("carbon.home");

        if (carbonHome == null) {
            log.error("carbon.home system property is not set!");
            return;
        }

        File file = new File(carbonHome + "/repository/conf/deployment.toml");

        if (!file.exists()) {
            log.error("deployment.toml not found at: " + file.getAbsolutePath());
            return;
        }

        boolean inBlock = false;

        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {

            String line;
            while ((line = reader.readLine()) != null) {

                line = line.trim();

                if (line.isEmpty() || line.startsWith("#")) continue;

                if (line.startsWith("[") && line.endsWith("]")) {
                    inBlock = line.equals(CUSTOM_CAPTCHA_BLOCK);
                    continue;
                }

                if (!inBlock || !line.contains("=")) continue;

                String[] parts = line.split("=", 2);
                String key = parts[0].trim();
                String value = parts[1].replace("\"", "").trim();

                switch (key) {
                    case CLIENT_IDs:
                        targetClientIds = Arrays.stream(value.split(","))
                                .map(String::trim)
                                .filter(s -> !s.isEmpty())
                                .collect(Collectors.toSet());
                        break;

                    case SITE_VERIFY_URL:
                        siteVerifyUrl = value;
                        break;

                    case SECRET_KEY:
                        recaptchaSecret = value;
                        break;

                    case PROXY_HOST:
                        proxyHost = value;
                        break;

                    case PROXY_PORT:
                        try {
                            proxyPort = Integer.parseInt(value);
                        } catch (NumberFormatException e) {
                            log.warn("Invalid proxy port: " + value);
                        }
                        break;
                }
            }

        } catch (IOException e) {
            log.error("Error reading deployment.toml", e);
        }

        validateConfig();
    }

    private void validateConfig() {
        if (siteVerifyUrl == null || recaptchaSecret == null) {
            log.error("Captcha configuration is incomplete!");
        }

        log.info("Captcha enabled for client IDs: " + targetClientIds);
        log.info("reCAPTCHA response verification endpoint configured: " + siteVerifyUrl);

        if (proxyPort != -1 && (proxyHost == null || proxyHost.isEmpty())) {
            log.warn("Proxy port is set but proxy host is missing.");
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (!(request instanceof HttpServletRequest) || !(response instanceof HttpServletResponse)) {
            chain.doFilter(request, response);
            return;
        }

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        if (!"POST".equalsIgnoreCase(req.getMethod())) {
            chain.doFilter(request, response);
            return;
        }

        String sessionDataKey = req.getParameter("sessionDataKey");
        String clientId = getServiceProviderFromSessionDataKey(sessionDataKey);
        String referer = req.getHeader("Referer");

        if (clientId == null || !targetClientIds.contains(clientId)) {
            chain.doFilter(request, response);
            return;
        }

        log.info("Captcha validation required for client_id=" + clientId);

        boolean captchaValid;
        String gCaptchaResponse = req.getParameter(RECAPTCHA_PARAM);

        try {
            captchaValid = verifyCaptcha(gCaptchaResponse);
        } catch (Exception e) {
            log.error("Captcha verification failed due to exception", e);
            captchaValid = false;
        }

        if (!captchaValid) {
            log.warn("Captcha validation failed for client_id=" + clientId);
            String redirectUrl = constructFailureRedirectUrl(referer);
            res.sendRedirect(redirectUrl);
            return;
        }

        log.info("Captcha validation passed for client_id=" + clientId);

        chain.doFilter(request, response);
    }

    private boolean verifyCaptcha(String captcha) throws IOException {

        if (captcha == null || captcha.trim().isEmpty()) {
            log.warn("Captcha token is missing.");
            return false;
        }

        HttpURLConnection conn = getConnection();

        String payload = "secret=" + URLEncoder.encode(recaptchaSecret, StandardCharsets.UTF_8.name()) +
                "&response=" + URLEncoder.encode(captcha, StandardCharsets.UTF_8.name());

        try (OutputStream os = conn.getOutputStream()) {
            os.write(payload.getBytes(StandardCharsets.UTF_8));
        }

        int responseCode = conn.getResponseCode();

        if (responseCode != 200) {
            log.error("reCAPTCHA API returned non-200 response: " + responseCode);
            return false;
        }

        String responseBody;
        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {

            responseBody = br.lines().collect(Collectors.joining());
        }

        if (log.isDebugEnabled()) {
            log.debug("reCAPTCHA raw response: " + responseBody);
        }

        JSONObject json = new JSONObject(responseBody);
        return json.optBoolean("success", false);
    }

    private HttpURLConnection getConnection() throws IOException {

        URL url = new URL(siteVerifyUrl);
        HttpURLConnection conn;

        if (proxyHost != null && !proxyHost.isEmpty() && proxyPort > 0) {
            Proxy proxy = new Proxy(Proxy.Type.HTTP,
                    new InetSocketAddress(proxyHost, proxyPort));
            conn = (HttpURLConnection) url.openConnection(proxy);
        } else {
            conn = (HttpURLConnection) url.openConnection();
        }

        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setConnectTimeout(CONNECT_TIMEOUT);
        conn.setReadTimeout(READ_TIMEOUT);

        return conn;
    }

    private String constructFailureRedirectUrl(String referer) {

        try {
            URL url = new URL(referer);
            String query = url.getQuery();

            if (query == null) {
                throw new IllegalArgumentException("Query is null");
            }

            Map<String, String> params = Arrays.stream(query.split("&"))
                    .map(s -> s.split("=", 2))
                    .collect(Collectors.toMap(
                            a -> a[0],
                            a -> {
                                try {
                                    return a.length > 1 ? URLDecoder.decode(a[1], "UTF-8") : "";
                                } catch (UnsupportedEncodingException e) {
                                    throw new RuntimeException(e);
                                }
                            }
                    ));

            params.put("authFailure", "true");
            params.put("authFailureMsg", "recaptcha.fail.message");

            String newQuery = params.entrySet().stream()
                    .map(e -> e.getKey() + "=" + encode(e.getValue()))
                    .collect(Collectors.joining("&"));

            return url.getProtocol() + "://" + url.getHost()
                    + (url.getPort() != -1 ? ":" + url.getPort() : "")
                    + url.getPath() + "?" + newQuery;

        } catch (Exception e) {
            log.error("Error constructing redirect URL, falling back", e);

            return "/authenticationendpoint/login.do"
                    + "?authFailure=true&authFailureMsg=recaptcha.fail.message";
        }
    }

    private String encode(String val) {
        try {
            return URLEncoder.encode(val, "UTF-8");
        } catch (Exception e) {
            return val;
        }
    }

    private String getServiceProviderFromSessionDataKey(String sessionDataKey) {

        if (sessionDataKey == null) {
            log.warn("sessionDataKey is null");
            return null;
        }

        try {
            AuthenticationContext context =
                    FrameworkUtils.getAuthenticationContextFromCache(sessionDataKey);

            if (context != null && context.getRelyingParty() != null) {
                String clientId = context.getRelyingParty();
                log.info("Resolved Service Provider: " + clientId);
                return clientId;
            } else {
                log.warn("AuthenticationContext not found for sessionDataKey: " + sessionDataKey);
            }

        } catch (Exception e) {
            log.error("Error retrieving AuthenticationContext", e);
        }

        return null;
    }

    @Override
    public void destroy() {
    }
}