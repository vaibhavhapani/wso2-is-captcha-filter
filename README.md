# App-Specific reCAPTCHA for WSO2 Identity Server

Implements Google reCAPTCHA v2 for a **single service provider (SP)** without
enabling it globally, using a custom Tomcat servlet filter.

---

## Architecture Overview

```
User opens Application
        │
        ▼
Application redirects to WSO2 Authorization Endpoint
        │
        ▼
WSO2 loads login page (login.jsp)
        │
        ▼
User enters credentials + reCAPTCHA
        │
        ▼
Browser sends POST request to WSO2 IS server
        │
        ▼
CustomCaptchaFilter.doFilter()
        │
        │
        ├── Read request parameters
        │      relyingParty
        │      g-recaptcha-response
        │
        ├── Check if request is for TARGET_SP
        │
        │      if NOT target SP
        │           │
        │           └── Continue normal login flow
        │
        │      if TARGET_SP
        │           │
        │           ▼
        │      Verify CAPTCHA with Google API
        │
        │           │
        │     ┌─────┴───────────┐
        │     │                 │
        │  success           failure
        │     │                 │
        │     ▼                 ▼
        │ Continue         Redirect to
        │ login flow       login.do?authFailure=true
        │
        ▼
WSO2 Authentication Steps Execute
        │
        ▼
User Logged In
```

---

## Prerequisites

| Item                  | Details                                     |
|-----------------------|---------------------------------------------|
| WSO2 IS version       | 5.x / 6.x                                   |
| Java                  | 11+                                         |
| Maven                 | 3.6+                                        |
| Google reCAPTCHA keys | Register at https://www.google.com/recaptcha/admin |
| reCAPTCHA type        | v2 "I'm not a robot" checkbox               |

---

## Step 1 — Disable Server-Level reCAPTCHA

Disable if it is enabled, update in `<IS-HOME>/repository/conf/deployment.toml`:

```toml
[recaptcha]
enabled = false
```

This prevents the built-in `CaptchaFilter` from running globally so it does
not conflict with the per-app filter you are adding.

Restart is required for this change to take effect.

---

## Step 2 — Update login.jsp

Modify the login page for your specific application. The page is usually found at:

```
<IS-HOME>/repository/deployment/server/webapps/authenticationendpoint/login.jsp
```

### 2a. Detect the target SP

At the top of the scriptlet section, add:

```jsp
<%
    String targetSP  = "CLIENT_ID"; // ← client id of the service provider
    String currentRP = request.getParameter("relyingParty");
    boolean isTargetApp = targetSP.equalsIgnoreCase(currentRP);
%>
```

### 2b. Load google reCAPTCHA api url and site key

```jsp
   // find the below lines
    
   if (reCaptchaEnabled || reCaptchaResendEnabled) {
        reCaptchaKey = CaptchaUtil.reCaptchaSiteKey();
        reCaptchaAPI = CaptchaUtil.reCaptchaAPIURL();
    }
    
    // And replace them with below
    
    if (isTargetApp) {
        reCaptchaKey = "fsdfefgegeven6nvdvdvdfvedfefevecvece"; // add your key
        reCaptchaAPI = "https://www.google.com/recaptcha/api.js";
    }
```

### 2b. Load the reCAPTCHA JS (in `<head>`)

```jsp
Replace each occurence of the variable reCaptchaEnabled in <html> block wth isTargetApp
```

### 2c. Change in basicauth.jsp

<IS-HOME>/repository/deployment/server/webapps/authenticationendpoint/basicauth.jsp

```jsp
Find and replace the variable reCaptchaEnabled with isTargetApp
```

---

## Step 3 — Clone this repository and build the filter

```bash
cd wso2-is-captcha-filter/
mvn clean install
```

Output JAR: `target/custom-recaptcha-filter.jar`

---

## Step 4 — Deploy the JAR

Copy the JAR to the IS lib directory:

```
   <IS-HOME>/repository/components/lib/
```
---

## Step 5 — Configure the Filter in deployment.toml

Add the following to `<IS-HOME>/repository/conf/deployment.toml`:

```toml
[[tomcat.filter]]
name  = "CustomCaptchaFilter"
class = "org.wso2.carbon.extension.captcha.CustomCaptchaFilter"

[[tomcat.filter_mapping]]
name = "CustomCaptchaFilter"
url_pattern = "/commonauth"

[custom.captcha]
clientIds = "enqindsiqndiwndiwndindinian,MY_ACCOUNT,another_app, etc"
siteVerifyUrl = "https://www.google.com/recaptcha/api/siteverify"
secret = "YOUR_GOOGLE_API_SECRET_KEY"
```

---

## Step 6 — Restart IS

```bash
sh <IS-HOME>/bin/wso2server.sh restart
```

---

## Testing

1. Navigate to your SP's login URL.
2. The reCAPTCHA widget should appear below the username/password fields.
3. Attempt to submit without completing the widget will result in authentication failure.
4. An error message should be shown in case of failure.
5. Log in to any other SP - reCAPTCHA should NOT appear.

---

## Security Considerations

| Concern              | Mitigation                                                                                                                                                  |
|----------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Secret key exposure  | Store it as an environment variable and reference it in deployment.toml via `$env{RECAPTCHA_SECRET}`                                                        |

---
