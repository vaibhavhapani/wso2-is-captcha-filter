package org.wso2.carbon.extension.captcha;

import javax.servlet.*;
import javax.servlet.http.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.File;
import java.io.FileReader;
import java.net.HttpURLConnection;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import static org.wso2.carbon.extension.captcha.CustomCaptchaFilterConstants.*;

public class CustomCaptchaFilter implements Filter {

    private static final Log log = LogFactory.getLog(CustomCaptchaFilter.class);

    private static String siteVerifyUrl;
    private static String recaptchaSecret;
    private Set<String> targetClientIds;
    private static String proxyHost;
    private static int proxyPort = -1;
    private static boolean initialized = false;

    public CustomCaptchaFilter() {
    }

    @Override
    public void init(FilterConfig filterConfig) {
        if (initialized) {
            return;
        }

        synchronized (CustomCaptchaFilter.class) {
            if (!initialized) {
                log.info("CUSTOM CAPTCHA FILTER INITIALIZED!!");
                loadCaptchaConfig();
            }
        }
    }

    private void loadCaptchaConfig() {

        try {
            String carbonHome = System.getProperty("carbon.home");
            File file = new File(carbonHome + "/repository/conf/deployment.toml");

            BufferedReader reader = new BufferedReader(new FileReader(file));
            String line;

            boolean inCustomCaptchaBlock = false;

            while ((line = reader.readLine()) != null) {
                line = line.trim();

                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }

                if (line.startsWith("[") && line.endsWith("]")) {
                    inCustomCaptchaBlock = line.equals(CUSTOM_CAPTCHA_BLOCK);
                    continue;
                }

                if (!inCustomCaptchaBlock || !line.contains("=")) {
                    continue;
                }

                // Split key and value
                String[] parts = line.split("=", 2);
                String key = parts[0].trim();
                String value = parts[1].replace("\"", "").trim();

                switch (key) {

                    case CLIENT_IDs:
                        targetClientIds = Arrays.stream(value.split(",")).map(String::trim).collect(Collectors.toSet());
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

                    default:
                        break;
                }
            }
            reader.close();
        } catch (Exception e) {
            log.error("Failed to load captcha configuration", e);
        }

        initialized = true;
        if (proxyPort != -1 && (proxyHost == null || proxyHost.isEmpty())) {
            log.warn("Proxy port is set but proxy host is missing");
        }
        log.info("Captcha enabled for SP client IDs: " + targetClientIds);
        log.info("reCAPTCHA verify endpoint: " + siteVerifyUrl);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;

        if (!"POST".equalsIgnoreCase(req.getMethod())) {
            chain.doFilter(request, response);
            return;
        }

        log.info("CustomCaptchaFilter triggered");

        String referer = req.getHeader("Referer");
        String clientId = extractClientId(referer);

        if (clientId != null && targetClientIds.contains(clientId)) {

            log.info("Captcha validation required for SP: " + clientId);
            boolean captchaValid = false;

            try {
                captchaValid = verifyCaptcha(req.getParameter(RECAPTCHA_PARAM));
            } catch (IOException e) {
                log.error("Google reCAPTCHA API unreachable: " + e.getMessage());
            }

            if (!captchaValid) {
                log.error("Captcha validation failed — redirecting.");

                String redirectUrl = constructFailureRedirectUrl(req, referer);
                ((HttpServletResponse) response).sendRedirect(redirectUrl);
                return;
            }
            log.info("Captcha validation passed.");
        }
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
    }

    private boolean verifyCaptcha(String captcha) throws IOException {

        if (captcha == null || captcha.trim().isEmpty()) {
            log.warn("Captcha token is missing.");
            return false;
        }

        HttpURLConnection conn = getHttpURLConnection();

        try (OutputStream os = conn.getOutputStream()) {
            os.write(("secret=" + recaptchaSecret + "&response=" + captcha).getBytes());
        }

        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
            String line;
            while ((line = br.readLine()) != null) sb.append(line);
        }

        log.info("Google reCAPTCHA response: " + sb);

        return sb.toString().contains("\"success\":true") || sb.toString().contains("\"success\": true");
    }

    private HttpURLConnection getHttpURLConnection() throws IOException {
        URL url = new URL(siteVerifyUrl);
        HttpURLConnection conn;

        if (proxyHost != null && !proxyHost.isEmpty() && proxyPort > 0) {
            log.info("Using proxy for reCAPTCHA call: " + proxyHost + ":" + proxyPort);
            Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyHost, proxyPort));
            conn = (HttpURLConnection) url.openConnection(proxy);
        } else {
            conn = (HttpURLConnection) url.openConnection();
        }

        conn.setRequestMethod("POST");
        conn.setDoOutput(true);

        return conn;
    }

    private String constructFailureRedirectUrl(HttpServletRequest req, String referer) {
        try {
            URL refererUrl = new URL(referer);
            String query = refererUrl.getQuery();

            Map<String, String> params = Arrays.stream(query.split("&")).map(s -> s.split("=", 2)).collect(Collectors.toMap(a -> a[0], a -> a.length > 1 ? URLDecoder.decode(a[1], StandardCharsets.UTF_8) : ""));

            params.put("authFailure", "true");
            params.put("authFailureMsg", "recaptcha.fail.message");

            String newQuery = params.entrySet().stream().map(e -> e.getKey() + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8)).collect(Collectors.joining("&"));

            return refererUrl.getProtocol() + "://" + refererUrl.getHost() + (refererUrl.getPort() != -1 ? ":" + refererUrl.getPort() : "") + refererUrl.getPath() + "?" + newQuery;
        } catch (MalformedURLException e) {
            log.error("Invalid Referer URL: " + referer, e);

            // fallback: minimal URL using request parameters
            String sessionDataKey = req.getParameter("sessionDataKey");
            String clientId = req.getParameter("client_id");
            return "/authenticationendpoint/login.do" + "?sessionDataKey=" + URLEncoder.encode(sessionDataKey, StandardCharsets.UTF_8) + "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8) + "&authFailure=true" + "&authFailureMsg=recaptcha.fail.message";
        }
    }

    private String extractClientId(String referer) {
        try {
            URL url = new URL(referer);
            String query = url.getQuery();

            if (query == null) {
                return null;
            }

            for (String param : query.split("&")) {
                if (param.startsWith("client_id=")) {
                    return URLDecoder.decode(param.split("=")[1], StandardCharsets.UTF_8);
                }
            }
        } catch (Exception e) {
            log.warn("Failed to extract client_id from referer", e);
        }
        return null;
    }

}