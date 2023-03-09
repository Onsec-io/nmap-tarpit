description = [[
A script for detecting hosts protected by an IPS or Firewall with TCP Tarpit.
It simulates port scanning and tracks the response of the scanned system.

The script selects random ports from the upper and lower ranges and attempts to establish a connection.
If these random ports are open, then the host is marked as a TARPIT.
This allows for separate scanning of such hosts by adjusting the scanning parameters individually.
]]

---
-- @usage
-- nmap -n -sn -Pn _TARGET_ --script tarpit.nse
-- nmap -n -sn -Pn _TARGET_ --script tarpit.nse --script-args "lower_ports_count=5" -oX output.xml
--
-- @output
--
-- @args tarpit.lower_ports_count
--       Set the count of random ports in range 1-1024. The default value is 7.
-- @args tarpit.upper_ports_count
--       Set the count of random ports in range 1025-65535. The default value is 7.
-- @args tarpit.socket_timeout
--       Set the timeout for socket in milliseconds. The default value is 200.
--
-- @changelog
-- 2023-03-05 - v0.1 - created by 0x566164696D
-- 2023-03-09 - v0.2 - minor improvements
--

author     = "0x566164696D"
license    = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery"}

local nmap      = require "nmap"
local stdnse    = require "stdnse"
local coroutine = require "coroutine"
local math      = require "math"
local table     = require "table"

local lower_ports_count = stdnse.get_script_args('tarpit.lower_ports_count') or 7
local upper_ports_count = stdnse.get_script_args('tarpit.upper_ports_count') or 7
local socket_timeout    = stdnse.get_script_args('tarpit.socket_timeout')    or 200


local function random_ports()
  local ports = {22, 80, 443, 3306, 3389, 8080}
  math.randomseed(os.time())

  for _=1, tonumber(lower_ports_count) do
    table.insert(ports, math.random(1, 1024))
  end

  for _=1, tonumber(upper_ports_count) do
    table.insert(ports, math.random(1025, 65535))
  end
  table.sort(ports)
  return ports
end


local function check_port(ip, port, result)
  local condvar = nmap.condvar(result)
  local socket = nmap.new_socket()
  socket:set_timeout(socket_timeout)
  stdnse.debug1("Trying %s:%s", ip, port)
  local status, err = socket:connect(ip, port)
  if status then
    table.insert(result, port)
  end
  condvar "signal"
end


local function check_ports_multithread(ip, ports)
  local result = {}
  local condvar = nmap.condvar(result)
  local threads = {}

  for _, port in pairs(ports) do
    local co = stdnse.new_thread( check_port, ip, port, result )
    threads[co] = true
  end

  -- wait for all threads to finish up
  repeat
    for t in pairs(threads) do
      if ( coroutine.status(t) == "dead" ) then threads[t] = nil end
    end
    if ( next(threads) ) then
      condvar "wait"
    end
  until( next(threads) == nil )
  return result
end


prerule = function()
  stdnse.verbose2(
    string.format("Params - lower: %s, upper: %s, timeout: %s", lower_ports_count, upper_ports_count, socket_timeout )
  )
  return true
end

hostrule = function(host)
  return true
end


action = function(host)
  if host == nil then
    return
  end

  local ports            = random_ports()
  local scan1_open_ports = check_ports_multithread(host.ip, ports)
  stdnse.verbose2(string.format("%s: random ports         : %s", host.ip, table.concat(ports, ",") ))

  if #scan1_open_ports == 0 then
    return
  end

  table.sort(scan1_open_ports)
  stdnse.verbose2(string.format("%s: 1st scan opened ports: %s", host.ip, table.concat(scan1_open_ports, ",") ))

  if #scan1_open_ports == #ports then
    stdnse.verbose2("Random ports are equal to open ports (scan 1).")
    return stdnse.format_output(true, string.format("%s: IPS / TCP TARPIT detected!", host.ip ) )
  end

  local scan2_open_ports = check_ports_multithread(host.ip, ports)

  if #scan2_open_ports == 0 then
    return
  end

  table.sort(scan2_open_ports)
  stdnse.verbose2(string.format("%s: 2nd scan opened ports: %s", host.ip, table.concat(scan2_open_ports, ",") ))

  if #ports == #scan2_open_ports then
    stdnse.verbose2("Random ports are equal to open ports (scan 2).")
    return stdnse.format_output(true, string.format("%s: IPS / TCP TARPIT detected!", host.ip ) )
  end

end
