package com.xpn.xwiki.sso;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.user.api.XWikiUser;
import com.xpn.xwiki.user.impl.xwiki.MyPersistentLoginManager;
import com.xpn.xwiki.user.impl.xwiki.XWikiAuthServiceImpl;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.securityfilter.filter.SecurityRequestWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.Base64Utils;
import org.w3c.dom.Document;
import org.xwiki.model.reference.DocumentReference;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

public class XWikiSSOAUthServiceImpl extends XWikiAuthServiceImpl {
    private static final Logger LOGGER = LoggerFactory.getLogger(XWikiSSOAUthServiceImpl.class);

    private MyPersistentLoginManager loginManager = new MyPersistentLoginManager();

    private static final String FORM_USERNAME = "j_username";
    private static final String FORM_PASSWORD = "j_password";

    @Override
    public XWikiUser checkAuth(XWikiContext context) throws XWikiException {
        HttpServletRequest request = null;
        HttpServletResponse response = context.getResponse();

        if (context.getRequest() != null) {
            request = context.getRequest().getHttpServletRequest();
        }

        if (request == null) {
            return null;
        }
        String ssoUrl = context.getWiki().Param("xwiki.authentication.sso.url", "https://sso.iflytek.com:8443");
        String callbackUrl = context.getWiki().Param("xwiki.authentication.sso.callback", "http://community.iflytek.com/xwiki/bin/view/Main/");
        long refreshInterval = context.getWiki().ParamAsLong("xwiki.authentication.sso.refresh.interval", 30L);
        String keystore = context.getWiki().Param("xwiki.authentication.sso.keystore", "sso.keystore");
        String keystorePwd = context.getWiki().Param("xwiki.authentication.sso.keystore.password", "iflytek");

        if (!System.getProperties().containsKey("javax.net.ssl.trustStore")) {
            System.setProperty("javax.net.ssl.trustStore", Thread.currentThread().getContextClassLoader().getResource("").getPath() + keystore);
        }
        if (!System.getProperties().containsKey("javax.net.ssl.trustStorePassword")) {
            System.setProperty("javax.net.ssl.trustStorePassword", keystorePwd);
        }
        // admin登录url，不走sso认证
        if (request.getRequestURI().contains("/xwiki/bin/login/XWiki/XWikiLogin")) {
            return null;
        }
        // admin登录
        if (request.getRequestURI().contains("/xwiki/bin/loginsubmit/XWiki/XWikiLogin")) {
            String username = context.getWiki().convertUsername(request.getParameter(FORM_USERNAME), context);
            String password = request.getParameter(FORM_PASSWORD);
            // Check for superadmin
            if (isSuperAdmin(username)) {
                Principal principal = authenticateSuperAdmin(password, context);
                if (principal != null) {
                    loginManager.setProtection("none");
                    loginManager.rememberLogin(request, response, username, password);
                    try {
                        response.sendRedirect(callbackUrl);
                    } catch (IOException e) {
                        LOGGER.error("redirect error", e);
                    }
                    return null;
                } else {
                    return null;
                }
            }
        }
        // logout 需要区分是否admin
        if (request.getRequestURI().contains("/logout/XWiki/XWikiLogout")) {
            try {
                String username = getCookieValue(request.getCookies(), "username", "false");
                SSOUser ssoUser = (SSOUser) request.getSession().getAttribute("sso_user_session");
                if (ssoUser != null) {
                    username = ssoUser.getAccountName();
                }
                request.getSession().invalidate();
                SecurityRequestWrapper securityRequestWrapper = new SecurityRequestWrapper(request, null, null, null);
                loginManager.forgetLogin(securityRequestWrapper, response);
                response.sendRedirect(String.format("%s/logout?service=%s", ssoUrl, callbackUrl));
                return new XWikiUser("XWiki." + username);
            } catch (Exception e) {
                LOGGER.error("logout error", e);
            }
        }
        // exclude resource
        if (request.getServletPath().contains("/resources/") || request.getServletPath().contains("/skins/")) {
            return null;
        }
        // 普通用户session认证
        SSOUser ssoUser = (SSOUser) request.getSession().getAttribute("sso_user_session");
        if (null != ssoUser && StringUtils.isNotEmpty(ssoUser.getAccountName())) {
            if (isSuperAdmin(ssoUser.getAccountName())) {
                return null;
            }
            long exitTimes = (System.currentTimeMillis() - ssoUser.getTimestamp()) / 1000L;
            try {
                if (exitTimes < refreshInterval || this.isLogin(request, ssoUrl)) {
                    return new XWikiUser("XWiki." + ssoUser.getAccountName());
                }
            } catch (IOException e) {
                LOGGER.error("check login status failed from sso", e);
                return null;
            }
        }
        // 管理员cookie认证
        loginManager.setProtection("none");
        String username = getCookieValue(request.getCookies(), "username", "false");
        String password = getCookieValue(request.getCookies(), "password", "false");
        if (StringUtils.isNotEmpty(username) && isSuperAdmin(username)) {
            Principal principal = authenticateSuperAdmin(password, context);
            if (principal != null) {
                return new XWikiUser(principal.getName());
            }
        }

        String ticket = request.getParameter("ticket");
        if (StringUtils.isNotEmpty(ticket)) {
            try {
                SSOUser user = new SSOUser();
                if (this.validateST(ticket, user, ssoUrl, getRequestUrl(request))) {
                    request.getSession().setAttribute("sso_user_session", user);
                    XWikiDocument userProfile =
                            context.getWiki().getDocument(
                                    new DocumentReference(context.getWikiId(), "XWiki", user.getAccountName()), context);
                    if (userProfile.isNew()) {
                        createUserFromSSO(userProfile, user, context);
                        LOGGER.debug("New XWiki user created: [{}]", userProfile.getDocumentReference());
                    }
                    return new XWikiUser("XWiki." + user.getAccountName());
                }
            } catch (Exception e) {
                LOGGER.error("validate token failed from sso", e);
            }
        }
        try {
            String url = String.format("%s/login?service=%s", ssoUrl, getRequestUrl(request));
            response.sendRedirect(url);
        } catch (IOException e) {
            LOGGER.error("redirect to sso failed", e);
        }
        return null;
    }

    private void createUserFromSSO(XWikiDocument userProfile, SSOUser user, XWikiContext context) throws XWikiException {
        Map<String, String> map = new HashMap<>();
        map.put("first_name", user.getName());
        map.put("last_name", user.getAccountName());
        map.put("email", String.format("%s@iflytek.com", user.getAccountName()));
        map.put("company", "科大讯飞");
        // Mark user active
        map.put("active", "1");

        context.getWiki().createUser(userProfile.getDocumentReference().getName(), map, context);
        XWikiDocument createdUserProfile = context.getWiki().getDocument(userProfile.getDocumentReference(), context);
        context.getWiki().saveDocument(createdUserProfile, "Created user profile from SSO server", context);
    }

    private boolean isLogin(HttpServletRequest request, String ssoUrl) throws IOException {
        String ip = StringUtils.isEmpty(request.getHeader("x-forwarded-for")) ? request.getRemoteAddr() : request.getHeader("x-forwarded-for");
        String browser = request.getHeader("User-Agent");
        String userSignId = Base64Utils.encodeToString(String.format("%s%s", ip, browser).getBytes());
        SSOUser tempUser = (SSOUser) request.getSession().getAttribute("sso_user_session");
        String url = String.format("%s/loginState/check?userSignId=%s&userAccount=%s", ssoUrl, userSignId, tempUser.getAccountName());
        HttpGet httpGet = new HttpGet(url);
        HttpClient client = HttpClientBuilder.create().build();
        HttpResponse response = client.execute(httpGet);
        String content = EntityUtils.toString(response.getEntity(), "utf-8");
        if (response.getStatusLine().getStatusCode() == 200 && Boolean.valueOf(content)) {
            tempUser.setTimestamp(System.currentTimeMillis());
            return true;
        } else {
            return false;
        }
    }

    private boolean validateST(String ticket, SSOUser ssoUser, String ssoUrl, String serviceUrl) throws Exception {
        String url = String.format("%s/p3/serviceValidate?ticket=%s&service=%s", ssoUrl, ticket, serviceUrl);
        HttpGet httpGet = new HttpGet(url);
        HttpClient client = HttpClientBuilder.create().build();
        HttpResponse response = client.execute(httpGet);
        String content = EntityUtils.toString(response.getEntity(), "utf-8");
        if (response.getStatusLine().getStatusCode() == 200) {
            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(content.getBytes("utf-8")));
            ssoUser.setAccountName(document.getElementsByTagName("cas:userAccount").item(0).getTextContent());
            ssoUser.setName(document.getElementsByTagName("cas:userName").item(0).getTextContent());
            ssoUser.setUserSource(Integer.valueOf(document.getElementsByTagName("cas:userSource").item(0).getTextContent()));
            ssoUser.setUserId(document.getElementsByTagName("cas:userId").item(0).getTextContent());
            ssoUser.setTimestamp(System.currentTimeMillis());
            return true;
        } else {
            return false;
        }
    }

    private String getRequestUrl(HttpServletRequest request) {
        String reqUrl = request.getRequestURL().toString();
        String url;
        if (null == request.getQueryString()) {
            url = reqUrl;
        } else if (request.getQueryString().contains("ticket")) {
            if (StringUtils.isNotEmpty(request.getParameter("ssoQuery"))) {
                url = String.format("%s?%s=%s", reqUrl, "ssoQuery", request.getParameter("ssoQuery"));
            } else {
                url = reqUrl;
            }
        } else {
            url = String.format("%s?%s=%s", reqUrl, "ssoQuery", Base64Utils.encodeToString(request.getQueryString().getBytes()));
        }
        return url;
    }

    private String getCookieValue(Cookie[] cookies, String cookieName, String defaultValue) {
        String value = defaultValue;
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookieName.equals(cookie.getName())) {
                    value = cookie.getValue();
                }
            }
        }
        return value;
    }
}
