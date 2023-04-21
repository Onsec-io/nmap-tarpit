# nmap-tarpit plugin
A plugin for detecting hosts protected by an IPS or Firewall with TCP Tarpit.
It simulates port scanning and tracks the response of the scanned system.

The script selects random ports from the upper and lower ranges and attempts to establish a connection.
If these random ports are open, then the host is marked as a TARPIT.
This allows for separate scanning of such hosts by adjusting the scanning parameters individually.

Usage examples:

    nmap -n -sn -Pn _TARGET_ --script tarpit.nse
    nmap -n -sn -Pn _TARGET_ --script tarpit.nse --script-args "ports_count=25" -oX output.xml

Args:

ports_count - count of random ports in range 1025-49151. The default value is 20.

socket_timeout - timeout for socket in milliseconds. The default value is 8000.

open_ports_percent - percentage of open ports at which the host will be marked as a tarpit. The default value is 80.


---

一个用于检测使用 TCP Tarpit 保护的 IPS 或防火墙的主机的插件。该插件模拟端口扫描并跟踪被扫描系统的响应。

该脚本从上下范围中选择随机端口，并尝试建立连接。如果这些随机端口是开放的，则标记主机为 TARPIT。这允许通过单独调整扫描参数来扫描此类主机。

使用示例

    nmap -n -sn -Pn _TARGET_ --script tarpit.nse
    nmap -n -sn -Pn _TARGET_ --script tarpit.nse --script-args "ports_count=25" -oX output.xml

的中文翻译是 "启动参数

ports_count - 1025-49151范围内随机端口的计数。默认值为20。

socket_timeout    - 套接字超时时间，单位是毫秒。默认值为200。

open_ports_percent - 开放端口百分比，当该主机的开放端口达到此百分比时将被标记为 tarpit。默认值为80。
