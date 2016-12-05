# htjcvms互联网关键应用统一漏洞管理平台

##客户端检测脚本htjcvms_client.py 
	配置文件appconfig.xml
	在配置文件中定义漏洞管理服务器地址和告警邮件地址，并添加自身应用版本信息
	通过添加定时计划，通过此脚本实现从远处服务器查询最新应用版本信息，并对最新版本进行提示升级
	<pre>
	python htjcvms_clinet.py
	</pre>
    <?xml version="1.0" standalone="yes" ?>
    <system email="yeying0311@126.com" host='http://127.0.0.1:8000'>
    <app>
    <name>apache</name>
    <major>2.2</major>
    <mijorv>20</mijor>
    <date></date>
    </app>
    <app>
    <name>tomcat</name>
    <major>6.0</major>
    <mijor>20</mijor>
    <date></date>
    </app>
    </system>
	
##后台服务器程序htjcvms_server.py
	通过配置htjcvms.xml指定数据地址
	执行后生成htjcvms.db数据库，并在后台启动http服务并接受客户端查询请求
	<pre>
	python htjcvms_server.py
	</pre>