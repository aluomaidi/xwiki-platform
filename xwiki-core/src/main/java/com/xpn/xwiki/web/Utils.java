/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 *
 */
package com.xpn.xwiki.web;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.fileupload.FileItem;
import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.ecs.Filter;
import org.apache.ecs.filter.CharacterFilter;
import org.apache.log4j.MDC;
import org.apache.struts.upload.MultipartRequestWrapper;
import org.xwiki.component.manager.ComponentLookupException;
import org.xwiki.component.manager.ComponentManager;

import com.novell.ldap.util.Base64;
import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.plugin.fileupload.FileUploadPlugin;
import com.xpn.xwiki.xmlrpc.XWikiXmlRpcRequest;

public class Utils
{
    /** A key that is used for placing a map of replaced (for protection) strings in the context. */
    private static final String PLACEHOLDERS_CONTEXT_KEY = Utils.class.getCanonicalName() + "_placeholders";

    /** Whether placeholders are enabled or not. */
    private static final String PLACEHOLDERS_ENABLED_CONTEXT_KEY =
        Utils.class.getCanonicalName() + "_placeholders_enabled";

    /**
     * The component manager used by {@link #getComponent(String)} and {@link #getComponent(String, String)}. It is
     * useful for any non component code that need to initialize/access components.
     */
    private static ComponentManager componentManager;

    public static void parseTemplate(String template, XWikiContext context) throws XWikiException
    {
        parseTemplate(template, true, context);
    }

    public static void parseTemplate(String template, boolean write, XWikiContext context) throws XWikiException
    {
        XWikiResponse response = context.getResponse();

        // Set content-type and encoding (this can be changed later by pages themselves)
        if (context.getResponse() instanceof XWikiPortletResponse) {
            response.setContentType("text/html");
        } else {
            response.setContentType("text/html; charset=" + context.getWiki().getEncoding());
        }

        String action = context.getAction();
        if ((!"download".equals(action)) && (!"skin".equals(action))) {
            if (context.getResponse() instanceof XWikiServletResponse) {
                // Add a last modified to tell when the page was last updated
                if (context.getWiki().getXWikiPreferenceAsLong("headers_lastmodified", 0, context) != 0) {
                    if (context.getDoc() != null) {
                        response.setDateHeader("Last-Modified", context.getDoc().getDate().getTime());
                    }
                }
                // Set a nocache to make sure the page is reloaded after an edit
                if (context.getWiki().getXWikiPreferenceAsLong("headers_nocache", 1, context) != 0) {
                    response.setHeader("Pragma", "no-cache");
                    response.setHeader("Cache-Control", "no-cache");
                }
                // Set an expires in one month
                long expires = context.getWiki().getXWikiPreferenceAsLong("headers_expires", -1, context);
                if (expires == -1) {
                    response.setDateHeader("Expires", -1);
                } else if (expires != 0) {
                    response.setDateHeader("Expires", (new Date()).getTime() + 30 * 24 * 3600 * 1000L);
                }
            }
        }

        if (("download".equals(action)) || ("skin".equals(action))) {
            // Set a nocache to make sure these files are not cached by proxies
            if (context.getWiki().getXWikiPreferenceAsLong("headers_nocache", 1, context) != 0) {
                response.setHeader("Cache-Control", "no-cache");
            }
        }

        context.getWiki().getPluginManager().beginParsing(context);
        // This class allows various components in the rendering chain to use placeholders for some fragile data. For
        // example, the URL generated for the image macro should not be further rendered, as it might get broken by wiki
        // filters. For this to work, keep a map of used placeholders -> values in the context, and replace them when
        // the content is fully rendered. The rendering code can use Utils.createPlaceholder.
        // Initialize the placeholder map
        enablePlaceholders(context);
        String content = context.getWiki().parseTemplate(template + ".vm", context);
        // Replace all placeholders with the protected values
        content = replacePlaceholders(content, context);
        disablePlaceholders(context);
        content = context.getWiki().getPluginManager().endParsing(content.trim(), context);

        if (content.equals("")) {
            // get Error template "This template does not exist
            content = context.getWiki().parseTemplate("templatedoesnotexist.vm", context);
            content = content.trim();
        }

        if (!context.isFinished()) {
            if (context.getResponse() instanceof XWikiServletResponse) {
                // Set the content length to the number of bytes, not the
                // string length, so as to handle multi-byte encodings
                try {
                    response.setContentLength(content.getBytes(context.getWiki().getEncoding()).length);
                } catch (UnsupportedEncodingException e) {
                    e.printStackTrace();
                }
            }

            if (write) {
                try {
                    try {
                        response.getOutputStream().write(content.getBytes(context.getWiki().getEncoding()));
                    } catch (IllegalStateException ex) {
                        response.getWriter().write(content);
                    }
                } catch (IOException e) {
                    throw new XWikiException(XWikiException.MODULE_XWIKI_APP,
                        XWikiException.ERROR_XWIKI_APP_SEND_RESPONSE_EXCEPTION, "Exception while sending response", e);
                }
            }
        }

        try {
            response.getOutputStream().flush();
        } catch (Throwable ex) {
            try {
                response.getWriter().flush();
            } catch (Throwable ex2) {
            }
        }
    }

    public static String getRedirect(XWikiRequest request, String defaultRedirect)
    {
        String redirect = request.getParameter("xredirect");
        if ((redirect == null) || (redirect.equals(""))) {
            redirect = defaultRedirect;
        }

        return redirect;
    }

    public static String getRedirect(String action, String params, XWikiContext context)
    {
        String redirect = context.getRequest().getParameter("xredirect");
        if (StringUtils.isBlank(redirect)) {
            redirect = context.getDoc().getURL(action, params, true, context);
        }

        return redirect;
    }

    public static String getRedirect(String action, XWikiContext context)
    {
        return getRedirect(action, null, context);
    }

    public static String getPage(XWikiRequest request, String defaultpage)
    {
        String page = request.getParameter("xpage");
        if ((page == null) || (page.equals(""))) {
            page = defaultpage;
        }

        return page;
    }

    public static String getFileName(List<FileItem> filelist, String name)
    {
        FileItem fileitem = null;
        for (FileItem item : filelist) {
            if (name.equals(item.getFieldName())) {
                fileitem = item;
                break;
            }
        }

        if (fileitem == null) {
            return null;
        }

        return fileitem.getName();
    }

    public static byte[] getContent(List<FileItem> filelist, String name) throws XWikiException
    {
        FileItem fileitem = null;
        for (FileItem item : filelist) {
            if (name.equals(item.getFieldName())) {
                fileitem = item;
                break;
            }
        }

        if (fileitem == null) {
            return null;
        }

        byte[] data = new byte[(int) fileitem.getSize()];
        InputStream fileis = null;
        try {
            fileis = fileitem.getInputStream();
            fileis.read(data);
            fileis.close();
        } catch (IOException e) {
            throw new XWikiException(XWikiException.MODULE_XWIKI_APP,
                XWikiException.ERROR_XWIKI_APP_UPLOAD_FILE_EXCEPTION, "Exception while reading uploaded parsed file",
                e);
        }

        return data;
    }

    public static XWikiContext prepareContext(String action, XWikiRequest request, XWikiResponse response,
        XWikiEngineContext engine_context) throws XWikiException
    {
        XWikiContext context = new XWikiContext();
        String dbname = "xwiki";
        URL url = XWiki.getRequestURL(request);
        context.setURL(url);

        // Push the URL into the Log4j MDC context so that we can display it in the generated logs
        // using the
        // %X{url} syntax.
        MDC.put("url", url);

        context.setEngineContext(engine_context);
        context.setRequest(request);
        context.setResponse(response);
        context.setAction(action);
        context.setDatabase(dbname);

        int mode = 0;
        if (request instanceof XWikiXmlRpcRequest) {
            mode = XWikiContext.MODE_XMLRPC;
        } else if (request instanceof XWikiServletRequest) {
            mode = XWikiContext.MODE_SERVLET;
        } else if (request instanceof XWikiPortletRequest) {
            mode = XWikiContext.MODE_PORTLET;
        }
        context.setMode(mode);

        return context;
    }

    /**
     * Append request parameters from the specified String to the specified Map. It is presumed that the specified Map
     * is not accessed from any other thread, so no synchronization is performed. <p/> <strong>IMPLEMENTATION NOTE</strong>:
     * URL decoding is performed individually on the parsed name and value elements, rather than on the entire query
     * string ahead of time, to properly deal with the case where the name or value includes an encoded "=" or "&"
     * character that would otherwise be interpreted as a delimiter.
     * 
     * @param data Input string containing request parameters
     * @throws IllegalArgumentException if the data is malformed <p/> Code borrowed from Apache Tomcat 5.0
     */
    public static Map<String, String[]> parseParameters(String data, String encoding)
        throws UnsupportedEncodingException
    {
        if ((data != null) && (data.length() > 0)) {

            // use the specified encoding to extract bytes out of the
            // given string so that the encoding is not lost. If an
            // encoding is not specified, let it use platform default
            byte[] bytes = null;
            try {
                if (encoding == null) {
                    bytes = data.getBytes();
                } else {
                    bytes = data.getBytes(encoding);
                }
            } catch (UnsupportedEncodingException uee) {
            }

            return parseParameters(bytes, encoding);
        }

        return Collections.emptyMap();
    }

    /**
     * Append request parameters from the specified String to the specified Map. It is presumed that the specified Map
     * is not accessed from any other thread, so no synchronization is performed. <p/> <strong>IMPLEMENTATION NOTE</strong>:
     * URL decoding is performed individually on the parsed name and value elements, rather than on the entire query
     * string ahead of time, to properly deal with the case where the name or value includes an encoded "=" or "&"
     * character that would otherwise be interpreted as a delimiter. <p/> NOTE: byte array data is modified by this
     * method. Caller beware.
     * 
     * @param data Input string containing request parameters
     * @param encoding Encoding to use for converting hex
     * @throws UnsupportedEncodingException if the data is malformed <p/> Code borrowed from Apache Tomcat 5.0
     */
    public static Map<String, String[]> parseParameters(byte[] data, String encoding)
        throws UnsupportedEncodingException
    {
        Map<String, String[]> map = new HashMap<String, String[]>();

        if (data != null && data.length > 0) {
            int ix = 0;
            int ox = 0;
            String key = null;
            String value = null;
            while (ix < data.length) {
                byte c = data[ix++];
                switch ((char) c) {
                    case '&':
                        value = new String(data, 0, ox, encoding);
                        if (key != null) {
                            putMapEntry(map, key, value);
                            key = null;
                        }
                        ox = 0;
                        break;
                    case '=':
                        if (key == null) {
                            key = new String(data, 0, ox, encoding);
                            ox = 0;
                        } else {
                            data[ox++] = c;
                        }
                        break;
                    case '+':
                        data[ox++] = (byte) ' ';
                        break;
                    case '%':
                        data[ox++] = (byte) ((convertHexDigit(data[ix++]) << 4) + convertHexDigit(data[ix++]));
                        break;
                    default:
                        data[ox++] = c;
                }
            }
            // The last value does not end in '&'. So save it now.
            if (key != null) {
                value = new String(data, 0, ox, encoding);
                putMapEntry(map, key, value);
            }
        }

        return map;
    }

    /**
     * Convert a byte character value to hexidecimal digit value.
     * 
     * @param b the character value byte <p/> Code borrowed from Apache Tomcat 5.0
     */
    private static byte convertHexDigit(byte b)
    {
        if ((b >= '0') && (b <= '9')) {
            return (byte) (b - '0');
        }
        if ((b >= 'a') && (b <= 'f')) {
            return (byte) (b - 'a' + 10);
        }
        if ((b >= 'A') && (b <= 'F')) {
            return (byte) (b - 'A' + 10);
        }

        return 0;
    }

    /**
     * Put name value pair in map. <p/> Put name and value pair in map. When name already exist, add value to array of
     * values. <p/> Code borrowed from Apache Tomcat 5.0
     */
    private static void putMapEntry(Map<String, String[]> map, String name, String value)
    {
        String[] newValues = null;
        String[] oldValues = map.get(name);
        if (oldValues == null) {
            newValues = new String[1];
            newValues[0] = value;
        } else {
            newValues = new String[oldValues.length + 1];
            System.arraycopy(oldValues, 0, newValues, 0, oldValues.length);
            newValues[oldValues.length] = value;
        }
        map.put(name, newValues);
    }

    public static String formEncode(String value)
    {
        Filter filter = new CharacterFilter();
        filter.removeAttribute("'");
        String svalue = filter.process(value);
        return svalue;
    }

    public static String SQLFilter(String text)
    {
        try {
            return text.replaceAll("'", "''");
        } catch (Exception e) {
            return text;
        }
    }

    /**
     * @deprecated replaced by {@link com.xpn.xwiki.util.Util#encodeURI(String, XWikiContext)} since 1.3M2
     */
    @Deprecated
    public static String encode(String name, XWikiContext context)
    {
        try {
            return URLEncoder.encode(name, context.getWiki().getEncoding());
        } catch (Exception e) {
            return name;
        }
    }

    /**
     * @deprecated replaced by {@link com.xpn.xwiki.util.Util#decodeURI(String, XWikiContext)} since 1.3M2
     */
    @Deprecated
    public static String decode(String name, XWikiContext context)
    {
        try {
            // Make sure + is considered as a space
            String result = name.replaceAll("\\+", " ");

            // It seems Internet Explorer can send us back UTF-8
            // instead of ISO-8859-1 for URLs
            if (Base64.isValidUTF8(result.getBytes(), false)) {
                result = new String(result.getBytes(), "UTF-8");
            }

            // Still need to decode URLs
            return URLDecoder.decode(result, context.getWiki().getEncoding());
        } catch (Exception e) {
            return name;
        }
    }

    public static FileUploadPlugin handleMultipart(HttpServletRequest request, XWikiContext context)
    {
        FileUploadPlugin fileupload = null;
        try {
            if (request instanceof MultipartRequestWrapper) {
                fileupload = new FileUploadPlugin("fileupload", "fileupload", context);
                fileupload.loadFileList(context);
                context.put("fileuploadplugin", fileupload);
                MultipartRequestWrapper mpreq = (MultipartRequestWrapper) request;
                List<FileItem> fileItems = fileupload.getFileItems(context);
                for (FileItem item : fileItems) {
                    if (item.isFormField()) {
                        String sName = item.getFieldName();
                        String sValue = item.getString();
                        mpreq.setParameter(sName, sValue);
                    }
                }
            }
        } catch (Exception e) {
            if ((e instanceof XWikiException)
                && (((XWikiException) e).getCode() == XWikiException.ERROR_XWIKI_APP_FILE_EXCEPTION_MAXSIZE)) {
                context.put("exception", e);
            } else {
                e.printStackTrace();
            }
        }
        return fileupload;
    }

    /**
     * @param componentManager the component manager used by {@link #getComponent(String)} and
     *            {@link #getComponent(String, String)}
     */
    public static void setComponentManager(ComponentManager componentManager)
    {
        Utils.componentManager = componentManager;
    }

    /**
     * @return the component manager used by {@link #getComponent(String)} and {@link #getComponent(String, String)}
     */
    public static ComponentManager getComponentManager()
    {
        return componentManager;
    }

    /**
     * Lookup a XWiki component by role and hint.
     * 
     * @param role the class (aka role) that the component implements
     * @param hint a value to differentiate different component implementations for the same role
     * @return the component's instance
     */
    public static Object getComponent(Class< ? > role, String hint)
    {
        Object component = null;
        if (componentManager != null) {
            try {
                component = componentManager.lookup(role, hint);
            } catch (ComponentLookupException e) {
                throw new RuntimeException("Failed to load component [" + role .getName() 
                    + "] for hint [" + hint + "]", e);
            }
        } else {
            throw new RuntimeException("Component manager has not been initialized before lookup for [" 
                + role.getName() + "] for hint [" + hint + "]");
        }

        return component;
    }

    /**
     * Lookup a XWiki component by role (uses the default hint).
     * 
     * @param role the class (aka role) that the component implements
     * @return the component's instance
     */
    public static Object getComponent(Class< ? > role)
    {
        return getComponent(role, "default");
    }

    /**
     * @param <T> the component type
     * @param role the role for which to return implementing components
     * @return all components implementing the passed role
     * @since 2.0M3
     */
    public static <T> List<T> getComponentList(Class< T > role)
    {
        List<T> components;
        if (componentManager != null) {
            try {
                components = componentManager.lookupList(role);
            } catch (ComponentLookupException e) {
                throw new RuntimeException("Failed to load components with role [" + role.getName() + "]", e);
            }
        } else {
            throw new RuntimeException("Component manager has not been initialized before lookup for role ["
                + role.getName() + "]");
        }

        return components;
    }

    /**
     * Check if placeholders are enabled in the current context.
     * 
     * @param context The current context.
     * @return <code>true</code> if placeholders can be used, <code>false</code> otherwise.
     */
    public static boolean arePlaceholdersEnabled(XWikiContext context)
    {
        Boolean enabled = (Boolean) context.get(PLACEHOLDERS_ENABLED_CONTEXT_KEY);

        return enabled != null && enabled;
    }

    /**
     * Enable placeholder support in the current request context.
     * 
     * @param context The current context.
     */
    public static void enablePlaceholders(XWikiContext context)
    {
        context.put(PLACEHOLDERS_CONTEXT_KEY, new HashMap<String, String>());
        context.put(PLACEHOLDERS_ENABLED_CONTEXT_KEY, new Boolean(true));
    }

    /**
     * Disable placeholder support in the current request context.
     * 
     * @param context The current context.
     */
    public static void disablePlaceholders(XWikiContext context)
    {
        context.remove(PLACEHOLDERS_CONTEXT_KEY);
        context.remove(PLACEHOLDERS_ENABLED_CONTEXT_KEY);
    }

    /**
     * Create a placeholder key for a string that should be protected from further processing. The value is stored in
     * the context, and the returned key can be used by the calling code as many times in the rendering result. At the
     * end of the rendering process all placeholder keys are replaced with the values they replace.
     * 
     * @param value The string to hide.
     * @param context The current context.
     * @return The key to be used instead of the value.
     */
    public static String createPlaceholder(String value, XWikiContext context)
    {
        if (!arePlaceholdersEnabled(context)) {
            return value;
        }
        Map<String, String> renderingKeys = (Map<String, String>) context.get(PLACEHOLDERS_CONTEXT_KEY);
        String key;
        do {
            key = "KEY" + RandomStringUtils.randomAlphanumeric(10) + "KEY";
        } while (renderingKeys.containsKey(key));
        renderingKeys.put(key, value);

        return key;
    }

    /**
     * Insert back the replaced strings.
     * 
     * @param content The rendered content, with placeholders.
     * @param context The current context.
     * @return The content with all placeholders replaced with the real values.
     */
    public static String replacePlaceholders(String content, XWikiContext context)
    {
        if (!arePlaceholdersEnabled(context)) {
            return content;
        }

        String result = content;
        Map<String, String> renderingKeys = (Map<String, String>) context.get(PLACEHOLDERS_CONTEXT_KEY);
        for (Entry<String, String> e : renderingKeys.entrySet()) {
            result = result.replace(e.getKey(), e.getValue());
        }

        return result;
    }
}
