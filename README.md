# xwiki-platform
xwiki集成sso认证手册
1.将xwiki-platform-sso-6.4.5.jar和spring-core-4.3.8.RELEASE.jar拷贝到xwiki-enterprise-jetty-hsqldb-6.4.5/webapps/xwiki/WEB-INF/lib目录下
2.将sso.keystore拷贝到xwiki-enterprise-jetty-hsqldb-6.4.5/webapps/xwiki/WEB-INF/classes目录下
3.修改xwiki.cfg,增加如下几项配置,其中url\callback\keystore等信息按照实际情况填写，配置说明如下：

xwiki.authentication.authclass=com.xpn.xwiki.sso.XWikiSSOAUthServiceImpl
#sso地址ssoqxb.iflytek.com为测试地址，sso.iflytek.com为线上地址，线上接入需要oa提流程申请
xwiki.authentication.sso.url=https://ssoqxb.iflytek.com:8443/sso
# callback为sso回调的地址，建议只修改服务地址，不修改相对路径，如http://community.iflytek.com/xwiki/bin/view/Main
xwiki.authentication.sso.callback=http://172.31.131.211:8080/xwiki/bin/view/Main/
#证书位置，服务默认从类路径加载，即WEB-INF/classes目录下
xwiki.authentication.sso.keystore=sso.keystore
#证书密码,iflytek为sso测试环境使用，生产环境需要oa提流程获取
xwiki.authentication.sso.keystore.password=iflytek
#sso用户认证状态刷新，默认可不修改
xwiki.authentication.sso.refresh.interval=10

