local shortport = require "shortport"
local http = require "http"
local nmap = require "nmap"
local stdnse = require "stdnse"

description = [[
Get MAC address from network devices such printers and scanners
]]

---
-- @usage
-- nmap -sS -p 9100 --script http-device-mac <target>
--
-- @output
-- |_http-device-mac: 00:01:02:03:04:AB
-- <snip>
--

author = "Esteban Dauksis"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

action = function(host,port)

    local function extract_mac(response_body)
        -- Try to extract a MAC address from the response body using a regular expression
        local mac = response_body:match("(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)")
        if mac ~= nil then
            return mac
        end
        return nil
    end

    local function check_http_url(url)
        -- Try to connect to the target host using the specified URL and extract a MAC address
        local response = http.get(host, port, url)
        if response.status == 200 then
            local mac = extract_mac(response.body)
            if mac ~= nil then
                return mac
            end
        end
        return nil
    end

    local function check_snmp()
        -- Try to extract the MAC address from the device's SNMP system description OID
        local snmp_response = stdnse.snmp_get(host, {"1.3.6.1.2.1.1.1.0"})
        if snmp_response ~= nil and snmp_response[1] ~= nil then
            local mac = snmp_response[1]:match("(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)")
            if mac ~= nil then
                return mac
            end
        end
        return nil
    end

    local function check_arp()
        -- Try to extract the MAC address from the device's ARP table
        local arp_table = stdnse.get_arptable(host)
        if arp_table ~= nil then
            for _, entry in ipairs(arp_table) do
                if entry.ip == host.ip then
                    return entry.mac
                end
            end
        end
        return nil
    end

    local socket = nmap.new_socket()

    socket:set_timeout(5000)

    local catch = function()
        socket:close()
    end

    local try = nmap.new_try(catch)

    -- URLs that may expose the device's MAC address
    local urls = {
        "/en/mnt/sysinfo.htm",
        "/hp/jetdirect/configpage.htm",
        "/configpage.htm",
        "/card.asp?Lang=en",
        "/cgi-bin/admin/management.cgi?_la=4",
        "/web/guest/es/websys/netw/getInterface.cgi",
        "/info_config_network.html?tab=Status&menu=NetConfig",
        "/hp/device/info_configuration.htm",
        "/start/start.htm",
        "/Istatus.htm"
    }

    -- Try to extract MAC address using each URL
    for _, url in ipairs(urls) do
        local mac = check_http_url(url)
        if mac ~= nil then
            return mac
        end
    end

    -- Try to extract MAC address using SNMP and ARP methods
        local mac = check_snmp()
    if mac ~= nil then
        return mac
    end

    mac = check_arp()
    if mac ~= nil then
        return mac
    end

    -- Return nil if no MAC address was found
    return nil

end

