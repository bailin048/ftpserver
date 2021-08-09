# ftpserver
简化版ftp服务器

本服务器支持命令：USER,PASS,CWD,CDUP,PORT,QUIT,PASV,TYPE,RETR,STOR,LIST,PWD,MKD,RMD,DELE,RNRT,RNTO,SYST,FEAT,SIZE，QUIT

支持[上传下载限速]、[断点续传]、[用户鉴权]、[空闲断开]

src/下为源码
tool/下leapftp为测试客户端
editplus是为了在服务器上编写代码方便使用的工具

【注】：
1.若运行时主被动都连接不到本服务器，则应检查 /etc/hosts 文件中localhost对应的ip是否为127.0.0.1,该IP需手动改为其他IP，方可正常通信
