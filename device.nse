local snmp = require "snmp"
local shortport = require "shortport"

description = [[
Get MAC address from printers
]]

---
-- @usage
-- nmap -sS -p 161 --script snmp-device-mac <target>
--
-- @output
-- |_snmp-device-mac: 
-- |  MAC Address: 00:01:02:03:04:AB
-- |  Interface: 1
-- |  Port: 9100
-- |  Printer Type: LaserJet
-- |
-- |  MAC Address: 11:22:33:44:55:BB
-- |  Interface: 2
-- |  Port: 631
-- |  Printer Type: InkJet
-- <snip>
--

author = "Esteban Dauksis"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}
dependencies = {"snmp-brute"}

-- List of printer ports and their associated printer types
local printer_ports = {
    {515, "LaserJet"},
    {631, "InkJet"},
    {9100, "LaserJet"},
    {1865, "DotMatrix"}
}

-- Consolidate printer port scanning into a single function
local function scan_printer_ports(host)
    local port
    for i, p in ipairs(printer_ports) do
        port = p[1]
        local status = nmap.scan_port(host, port, "tcp")
        if status == "open" then
            return port, p[2]
        end
    end
end

-- SNMP authentication and encryption settings
local snmp_settings = {
    version = "2c",
    community = "public",
    timeout = 5000,
    retries = 2,
    security_level = "authPriv",
    security_name = "snmpuser",
    auth_protocol = "MD5",
    auth_password = "snmppass",
    priv_protocol = "DES",
    priv_password = "snmppass"
}

action = function(host)
    local socket = nmap.new_socket()

    -- Set SNMP settings for socket
    socket:set_smnp_settings(snmp_settings)

    -- Consolidate printer port scanning into single function
    local port, printer_type = scan_printer_ports(host)

    if not port then
        return
    end

    local payload
    local options = { reqId = 28428 }
    payload = snmp.encode(snmp.buildPacket(snmp.buildGetRequest(options, "1.3.6.1.2.1.2.2.1.6.1")))

    local status, response = socket:snmp_request(host, payload, port, "udp")
    if not status or status == "TIMEOUT" then
        return
    end

    local mac_address = snmp.fetchFirst(response)
    if not mac_address or mac_address == "" then
        return
    end

    -- Format output as table for easier reading and parsing
    local output = {}
    output[#output+1] = string.format("MAC Address: %02x:%02x:%02x:%02x:%02x:%02x", string.byte(mac_address, 1, 6))
    output[#output+1] = string.format("Interface: %d", 1)
    output[#output+1] = string.format("Port: %d", port)
    output[#output+1] = string.format("Printer Type: %s", printer_type)

    --
local payload
local options = { reqId = 28429 }
payload = snmp.encode(snmp.buildPacket(snmp.buildGetRequest(options, "1.3.6.1.2.1.2.2.1.6.2")))

local status, response = socket:snmp_request(host, payload, port, "udp")
if not status or status == "TIMEOUT" then
    return output
end

local mac_address = snmp.fetchFirst(response)
if not mac_address or mac_address == "" then
    return output
end

-- Format output as table for easier reading and parsing
local output = {}
output[#output+1] = string.format("MAC Address: %02x:%02x:%02x:%02x:%02x:%02x", string.byte(mac_address, 1, 6))
output[#output+1] = string.format("Interface: %d", 2)
output[#output+1] = string.format("Port: %d", port)
output[#output+1] = string.format("Printer Type: %s", printer_type)

return output
