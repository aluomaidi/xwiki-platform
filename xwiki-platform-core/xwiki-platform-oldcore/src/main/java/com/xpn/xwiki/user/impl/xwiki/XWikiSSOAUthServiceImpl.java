package com.xpn.xwiki.user.impl.xwiki;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.user.api.XWikiUser;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.Base64Utils;
import org.w3c.dom.Document;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;

public class XWikiSSOAUthServiceImpl extends XWikiAuthServiceImpl
{
    private static final Logger LOGGER = LoggerFactory.getLogger(XWikiSSOAUthServiceImpl.class);

    @Override
    public XWikiUser checkAuth(XWikiContext context) throws XWikiException
    {
        HttpServletRequest request = null;
        HttpServletResponse response = context.getResponse();

        if (context.getRequest() != null) {
            request = context.getRequest().getHttpServletRequest();
        }

        if (request == null) {
            return null;
        }
        SSOUser ssoUser = (SSOUser) request.getSession().getAttribute("sso_user_session");
        String ssoUrl = context.getWiki().Param("xwiki.authentication.sso.url", "https://sso.iflytek.com:8443");
        long refreshInterval = context.getWiki().ParamAsLong("xwiki.authentication.sso.refresh.interval", 10L);

        if (null != ssoUser && StringUtils.isNotEmpty(ssoUser.getAccountName())) {
            long exitTimes = (System.currentTimeMillis() - ssoUser.getTimestamp()) / 1000L;
            try {
                if (exitTimes < refreshInterval || this.isLogin(request, ssoUrl)) {
                    return new XWikiUser(ssoUser.getAccountName());
                }
            } catch (IOException e) {
                LOGGER.error("check login status failed from sso", e);
                return null;
            }
        }

        String ticket = request.getParameter("ticket");;
        if (StringUtils.isNotEmpty(ticket)) {
            try {
                SSOUser user = new SSOUser();
                if (this.validateST(ticket, user, request, ssoUrl)) {
                    request.getSession().setAttribute("sso_user_session", user);
                    response.sendRedirect(this.getSSOReturnUrl(request));
                    return new XWikiUser(user.getAccountName());
                }
            } catch (Exception e) {
                LOGGER.error("validate token failed from sso", e);
            }
        }
        try {
            response.sendRedirect(this.getSSOReturnUrl(request));
        } catch (IOException e) {
            LOGGER.error("redirect to sso failed", e);
        }
        return null;
    }

    private boolean isLogin(HttpServletRequest request, String ssoUrl) throws IOException {
        String ip = StringUtils.isEmpty(request.getHeader("x-forwarded-for")) ? request.getRemoteAddr() : request.getHeader("x-forwarded-for");
        String browser = request.getHeader("User-Agent");
        String userSignId = Base64Utils.encodeToString(String.format("%s%s", ip, browser).getBytes());
        SSOUser tempUser = (SSOUser)request.getSession().getAttribute("sso_user_session");
        String url = String.format("%s/loginState/check?userSignId=%s&userAccount=%s", ssoUrl, userSignId, tempUser.getAccountName());
        LOGGER.debug("登陆状态验证：" + url);
        HttpGet httpGet = new HttpGet(url);
        HttpClient client = HttpClientBuilder.create().build();
        HttpResponse response = client.execute(httpGet);
        String content = EntityUtils.toString(response.getEntity(), "utf-8");
        LOGGER.debug("登陆状态验证结果：" + content);
        if (response.getStatusLine().getStatusCode() == 200 && Boolean.valueOf(content)) {
            tempUser.setTimestamp(System.currentTimeMillis());
            return true;
        } else {
            return false;
        }
    }

    private boolean validateST(String ticket, SSOUser ssoUser, HttpServletRequest request, String ssoUrl) throws Exception {
        String url = String.format("%s/p3/serviceValidate?ticket=%s&service=%s", ssoUrl, ticket, this.getSSOServiceUrl(request));
        LOGGER.debug("ticket验证：" + url);
        HttpGet httpGet = new HttpGet(url);
        HttpClient client = HttpClientBuilder.create().build();
        HttpResponse response = client.execute(httpGet);
        String content = EntityUtils.toString(response.getEntity(), "utf-8");
        LOGGER.debug("ticket验证结果：" + content);
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

    protected String getSSOServiceUrl(HttpServletRequest request) {
        String url;
        if (null == request.getQueryString()) {
            url = request.getRequestURL().toString();
        } else if (request.getQueryString().contains("ticket")) {
            if (StringUtils.isNotEmpty(request.getParameter("ssoQuery"))) {
                url = String.format("%s?%s=%s", request.getRequestURL().toString(), "ssoQuery", request.getParameter("ssoQuery"));
            } else {
                url = request.getRequestURL().toString();
            }
        } else {
            url = String.format("%s?%s=%s", request.getRequestURL().toString(), "ssoQuery", Base64Utils.encodeToString(request.getQueryString().getBytes()));
        }

        return url;
    }

    protected String getSSOReturnUrl(HttpServletRequest request) {
        String url;
        if (null != request.getQueryString() && !StringUtils.isEmpty(request.getParameter("ssoQuery"))) {
            String params = new String(Base64Utils.decodeFromString(request.getParameter("ssoQuery")));
            url = String.format("%s?%s", request.getRequestURL().toString(), params);
        } else {
            url = request.getRequestURL().toString();
        }

        return url;
    }
}
