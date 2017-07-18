#!/usr/bin/env lua
--
-- apt install lua5.2 lua-socket
--
function string.fromhex(str)
    return (str:gsub('..', function (cc)
        return string.char(tonumber(cc, 16))
    end))
end
function string.tohex(str)
    return (str:gsub('.', function (c)
        return string.format('%02x', string.byte(c))
    end))
end
local socket = require("socket")
local udp = assert(socket.udp())
local data
local ola = string.fromhex('01000000')
udp:settimeout(1)
assert(udp:setoption('broadcast', true))
assert(udp:setoption('dontroute', true))

assert(udp:setsockname("10.5.5.254",47900))
assert(udp:setpeername("10.5.5.107",10001))

for i = 0, 2, 1 do
  assert(udp:send(ola))
  data = udp:receive()
  if data then
    break
  end
end


if data == nil then
  print("timeout")
else
	tab={}
  hex = string.tohex(data)
  cont = 1
  pri = 1
  while true do
	if pri == (#hex +1 ) then break end
		tab[cont] = string.fromhex(hex:sub(pri,pri+1))
	cont = cont + 1
	pri = pri + 2
  end
	for i = 1, #tab do
	if	tab[i] == '\00' then inicio = true end
	if tab[i] == '\01' then inicio = false end
	if inicio then io.write(tab[i]) end
	end
end
