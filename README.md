# nmap-tarpit plugin
A plugin for detecting hosts protected by an IPS or Firewall with TCP Tarpit.
It simulates port scanning and tracks the response of the scanned system.

The script selects random ports from the upper and lower ranges and attempts to establish a connection.
If these random ports are open, then the host is marked as a TARPIT.
This allows for separate scanning of such hosts by adjusting the scanning parameters individually.

Usage examples:

    nmap -n -sn -Pn _TARGET_ --script tarpit.nse
    nmap -n -sn -Pn _TARGET_ --script tarpit.nse --script-args "lower_ports_count=5" -oX output.xml

Args:

lower_ports_count - count of random ports in range 1-1024. The default value is 7.

upper_ports_count - count of random ports in range 1025-65535. The default value is 7.

socket_timeout    - timeout for socket in milliseconds. The default value is 150.

---

一个用于检测使用 TCP Tarpit 保护的 IPS 或防火墙的主机的插件。该插件模拟端口扫描并跟踪被扫描系统的响应。

该脚本从上下范围中选择随机端口，并尝试建立连接。如果这些随机端口是开放的，则标记主机为 TARPIT。这允许通过单独调整扫描参数来扫描此类主机。

使用示例

    nmap -n -sn -Pn _TARGET_ --script tarpit.nse
    nmap -n -sn -Pn _TARGET_ --script tarpit.nse --script-args "lower_ports_count=5" -oX output.xml

的中文翻译是 "启动参数

lower_ports_count - 在1-1024范围内的随机端口数量。默认值为7。

upper_ports_count - 在1025-65535范围内的随机端口数量。默认值为7。

socket_timeout    - 套接字超时时间，单位是毫秒。默认值为150。
