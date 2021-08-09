# ftpserver
简化版ftp服务器

本服务器支持命令：USER,PASS,CWD,CDUP,PORT,QUIT,PASV,TYPE,RETR,STOR,LIST,PWD,MKD,RMD,DELE,RNRT,RNTO,SYST,FEAT,SIZE，QUIT

支持[上传下载限速]、[断点续传]、[用户鉴权]、[空闲断开]

src/下为源码
tool/下leapftp为测试客户端
editplus是为了在服务器上编写代码方便使用的工具

【注】：
1.运行时主被动都连接不到本服务器———————————应检查 /etc/hosts 文件中localhost对应的ip是否为127.0.0.1,该IP需手动改为其他IP，方可正常通信

2.miniftp服务启动后，报parseconf_load_file: No such file or directory———————————需要将配置文件【miniftp.conf】与【miniftp】放在同一路径下

3.主动模式可以连接，但被动不可以连接；或者主动被动都不能连接———————————关闭防火墙

4.miniftp需要以root用户运行,关闭服务需要使用kill命令杀死进程
