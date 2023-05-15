# nmap-tarpit plugin
A plugin for detecting hosts protected by an IPS or Firewall with TCP Tarpit.
It simulates port scanning and tracks the response of the scanned system.

The script selects random ports from the upper and lower ranges and attempts to establish a connection.
If these random ports are open, then the host is marked as a TARPIT.
This allows for separate scanning of such hosts by adjusting the scanning parameters individually.

Usage examples:

With default settings

    # nmap \
        -T4 \
        -sn \
        -PE \
        -PY \
        -PO \
        -PS21,22,25,80,443,8080 \
        -PA21,22,25,80,443,8080 \
        --script tarpit.nse \
        -oX output.xml \
        _TARGET_

With arguments

    # nmap \
        -T4 \
        -sn \
        -PE \
        -PY \
        -PO \
        -PS21,22,25,80,443,8080 \
        -PA21,22,25,80,443,8080 \
        -script tarpit.nse --script-args "ports_count=25, scan1_timeout=300, scan2_timeout=1000, open_ports_percent=75" \
        -oX output.xml \
        _TARGET_

Args:

ports_count - count of random ports in range 1025-49151. The default value is 14.

scan1_timeout - timeout for the first cycle of port scanning. The cycle is necessary to provoke the host to trigger tarpit. The default value is 500ms.

scan2_timeout - timeout for the second cycle of port scanning, at this stage the main checking is performed. The default value is 2500ms.

open_ports_percent - percentage of open ports at which the host will be marked as a tarpit. The default value is 70.


---

一个用于检测使用 TCP Tarpit 保护的 IPS 或防火墙的主机的插件。该插件模拟端口扫描并跟踪被扫描系统的响应。

该脚本从上下范围中选择随机端口，并尝试建立连接。如果这些随机端口是开放的，则标记主机为 TARPIT。这允许通过单独调整扫描参数来扫描此类主机。

使用示例

    # nmap \
        -T4 \
        -sn \
        -PE \
        -PY \
        -PO \
        -PS21,22,25,80,443,8080 \
        -PA21,22,25,80,443,8080 \
        --script tarpit.nse \
        -oX output.xml \
        _TARGET_

带有参数

      # nmap \
        -T4 \
        -sn \
        -PE \
        -PY \
        -PO \
        -PS21,22,25,80,443,8080 \
        -PA21,22,25,80,443,8080 \
        -script tarpit.nse --script-args "ports_count=25, scan1_timeout=300, scan2_timeout=1000, open_ports_percent=75" \
        -oX output.xml \
        _TARGET_

的中文翻译是 "启动参数

ports_count - 随机端口的数量在 1025-49151 范围内。默认值为14。

scan1_timeout - 端口扫描的第一个循环的超时时间。循环必要来促使主机触发tarpit。默认值为500ms。

scan2_timeout - 端口扫描的第二个循环的超时时间，此阶段进行主要检查。默认值为2500ms。

open_ports_percent - 开放端口的百分比，该主机将被标记为 tarpit。默认值为70。
