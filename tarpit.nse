description = [[
A script for detecting hosts protected by an IPS or Firewall with TCP Tarpit.
It simulates port scanning and tracks the response of the scanned system.

The script selects random ports and attempts to establish a connection.
If these random ports are open, then the host is marked as a TARPIT.
This allows for separate scanning of such hosts by adjusting the scanning parameters individually.
]]

---
-- @usage
-- nmap -n -sn -Pn _TARGET_ --script tarpit.nse
-- nmap -n -sn -Pn _TARGET_ --script tarpit.nse --script-args "ports_count=25" -oX output.xml
--
-- @output
--
-- @args tarpit.ports_count
--       Set the count of random ports in range 1025-49151. The default value is 14.
-- @args tarpit.scan1_timeout
--       Set the timeout for socket in milliseconds. The default value is 500.
-- @args tarpit.scan2_timeout
--       Set the timeout for socket in milliseconds. The default value is 2500.
-- @args tarpit.open_ports_percent
--       Sets the percentage of open ports at which the host will be marked as a tarpit. The default value is 70.
--
-- @changelog
-- 2023-03-05 - v0.1 - first version
-- 2023-03-09 - v0.2 - minor improvements
-- 2023-04-20 - v0.3 - The generation of random ports has been rewritten.
--                     Triggering has been added when the specified percentage of open ports is exceeded.
-- 2023-05-14 - v0.4 - Default timeouts changed
--

author     = "0x566164696D"
license    = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery"}

local nmap      = require "nmap"
local stdnse    = require "stdnse"
local coroutine = require "coroutine"
local math      = require "math"
local table     = require "table"

local ports_count        = stdnse.get_script_args('tarpit.ports_count')        or 14
local scan1_timeout      = stdnse.get_script_args('tarpit.scan1_timeout')      or 500
local scan2_timeout      = stdnse.get_script_args('tarpit.scan2_timeout')      or 2500
local open_ports_percent = stdnse.get_script_args('tarpit.open_ports_percent') or 70


local function locate( table_, value )
    for i = 1, #table_ do
        if table_[i] == value then return true end
    end
    return false
end

local function random_ports()
  -- local ports = { 21, 22, 23, 80, 135, 389, 443, 445 }
  local ports = {}
  math.randomseed(os.time())

  while( #ports < tonumber(ports_count) )
  do
    local random_port = math.random(1025, 49151) --49152–65535 ephemeral range RFC 6335
    if not locate(ports, random_port) then
      table.insert(ports, random_port)
    end
  end

  table.sort(ports)
  return ports
end

local function check_port(ip, port, result, timeout)
  local condvar = nmap.condvar(result)
  local socket = nmap.new_socket()
  socket:set_timeout(timeout)
  stdnse.debug2("Trying %s:%s", ip, port)
  local status, err = socket:connect(ip, port)
  if status then
    table.insert(result, port)
  end
  condvar "signal"
end


local function check_ports_multithread(ip, ports, timeout)
  local result = {}
  local condvar = nmap.condvar(result)
  local threads = {}

  for _, port in pairs(ports) do
    local co = stdnse.new_thread( check_port, ip, port, result, timeout)
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
    string.format("Ports count: %s, scan1_timeout: %s, scan2_timeout: %s, open percent: %s", ports_count, scan1_timeout, scan2_timeout, open_ports_percent )
  )
  return true
end

hostrule = function()
  return true
end


action = function(host)
  if host == nil then
    return
  end

  local ports            = random_ports()
  stdnse.verbose2(string.format("%s: random ports         : %s", host.ip, table.concat(ports, ",") ))
  local scan1_open_ports = check_ports_multithread(host.ip, ports, tonumber(scan1_timeout))

  if #scan1_open_ports == 0 then
    return
  end

  table.sort(scan1_open_ports)
  stdnse.verbose2(string.format("%s: 1st scan opened ports: %s", host.ip, table.concat(scan1_open_ports, ",") ))

  if #scan1_open_ports == #ports then
    stdnse.verbose2("Random ports are equal to open ports (scan 1).")
    return stdnse.format_output(true, string.format("%s: IPS / TCP TARPIT detected!", host.ip ) )
  end

  local scan2_open_ports = check_ports_multithread(host.ip, ports, tonumber(scan2_timeout))

  if #scan2_open_ports == 0 then
    return
  end

  table.sort(scan2_open_ports)
  stdnse.verbose2(string.format("%s: 2nd scan opened ports: %s", host.ip, table.concat(scan2_open_ports, ",") ))

  if #ports == #scan2_open_ports then
    stdnse.verbose2("Random ports are equal to open ports (scan 2).")
    return stdnse.format_output(true, string.format("%s: IPS / TCP TARPIT detected!", host.ip ) )
  end

  if ( #scan2_open_ports / #ports * 100 ) >= tonumber(open_ports_percent)  then
    stdnse.verbose2(string.format("Open ports percent > %s", open_ports_percent ))
    return stdnse.format_output(true, string.format("%s: IPS / TCP TARPIT detected!", host.ip ) )
  end


end
