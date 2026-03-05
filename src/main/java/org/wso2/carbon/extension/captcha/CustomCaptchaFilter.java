package org.wso2.carbon.extension.captcha;

import javax.servlet.*;
import javax.servlet.http.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class CustomCaptchaFilter implements Filter {

    private static final Log log = LogFactory.getLog(CustomCaptchaFilter.class);

    private static final String SECRET = "e3er3sAefefefef8ZgcKjPJhl"; // replace these values with your keys
    private static final String TARGET_SP = "fefegegeggHSI5UV2_p4Hfmy6kQa";

    private static final String RECAPTCHA_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify";
    private static final String COMMONAUTH_PATH = "/commonauth";
    private static final String RECAPTCHA_PARAM = "g-recaptcha-response";

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;

        // Only intercept /commonauth
        if (!req.getRequestURI().contains(COMMONAUTH_PATH)) {
            chain.doFilter(request, response);
            return;
        }

        String referer = req.getHeader("Referer");

        if (referer != null && referer.contains(TARGET_SP)) {
            log.info("Captcha validation required for SP: " + TARGET_SP);

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

        HttpURLConnection conn = (HttpURLConnection) new URL(RECAPTCHA_VERIFY_URL).openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);

        try (OutputStream os = conn.getOutputStream()) {
            os.write(("secret=" + SECRET + "&response=" + captcha).getBytes());
        }

        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
            String line;
            while ((line = br.readLine()) != null) sb.append(line);
        }

        log.info("Google reCAPTCHA response: " + sb);

        return sb.toString().contains("\"success\":true")
                || sb.toString().contains("\"success\": true");
    }

    private String constructFailureRedirectUrl(HttpServletRequest req, String referer) {
        try {
            URL refererUrl = new URL(referer);
            String query = refererUrl.getQuery();

            // Convert query string to a map
            Map<String, String> params = Arrays.stream(query.split("&"))
                    .map(s -> s.split("=", 2))
                    .collect(Collectors.toMap(
                            a -> a[0],
                            a -> a.length > 1 ? URLDecoder.decode(a[1], StandardCharsets.UTF_8) : ""
                    ));

            // Add/override parameters for CAPTCHA failure
            params.put("authFailure", "true");
            params.put("authFailureMsg", "recaptcha.fail.message");

            // Reconstruct query string
            String newQuery = params.entrySet().stream()
                    .map(e -> e.getKey() + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                    .collect(Collectors.joining("&"));

            // Rebuild full redirect URL
            return refererUrl.getProtocol() + "://" + refererUrl.getHost()
                    + (refererUrl.getPort() != -1 ? ":" + refererUrl.getPort() : "")
                    + refererUrl.getPath()
                    + "?" + newQuery;

        } catch (MalformedURLException e) {
            log.error("Invalid Referer URL: " + referer, e);

            // fallback: minimal URL using request parameters
            String sessionDataKey = req.getParameter("sessionDataKey");
            String clientId = req.getParameter("client_id");
            return "/authenticationendpoint/login.do" +
                    "?sessionDataKey=" + URLEncoder.encode(sessionDataKey, StandardCharsets.UTF_8) +
                    "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8) +
                    "&authFailure=true" +
                    "&authFailureMsg=recaptcha.fail.message";
        }
    }

}