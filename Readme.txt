该程序使用netfilter实现了Linux内核级的包防火墙，语言为C++。
该防火墙可对指定的ip地址，端口进行判断，实现包的接收或丢弃。
使用时，使用Make指令通过Makefile文件完成编译，编译平台为Linux的gcc平台。
在Ubuntu 14.0上完成测试成功运行，内核为linux-4.8.0。
