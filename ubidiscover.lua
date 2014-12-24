-- Wireshark plugin for Ubiquiti Discovery protocol
-- Put this file in ~/.wireshark/plugins

ubidisc_proto = Proto("ubidisc", "Ubiquiti Discovery")

ubidisc_proto.fields.hwaddr = ProtoField.ether("ubidisc.hwaddr", "Hardware Address")
ubidisc_proto.fields.address = ProtoField.bytes("ubidisc.address", "Address Pair")
ubidisc_proto.fields.address_hwaddr = ProtoField.ether("ubidisc.address_hwaddr", "Hardware Address")
ubidisc_proto.fields.address_ipv4 = ProtoField.ipv4("ubidisc.address_ipv4", "IPV4 Address")
ubidisc_proto.fields.firmware = ProtoField.string("ubidisc.firmware", "Firmware Version")
ubidisc_proto.fields.uptime = ProtoField.uint32("ubidisc.uptime", "Uptime")
ubidisc_proto.fields.hostname = ProtoField.string("ubidisc.hostname", "Hostname")
ubidisc_proto.fields.product = ProtoField.string("ubidisc.product", "Product")
ubidisc_proto.fields.essid = ProtoField.string("ubidisc.essid", "ESSID")
ubidisc_proto.fields.wmode = ProtoField.uint8("ubidisc.wmode", "Wireless Mode")
ubidisc_proto.fields.sysid = ProtoField.uint16("ubidisc.sysid", "System ID", base.HEX)

ubidisc_proto.fields.generic = ProtoField.bytes("ubidisc.generic", "Unknown Field")

function ubidisc_proto.dissector(buffer, pinfo, tree)
   pinfo.cols.protocol = "Ubiquiti"
   local subtree = tree:add(ubidisc_proto, buffer(), "Ubiquiti Discovery")
   local pktlen = buffer:len()
   local current = 4
   local total_len = buffer(2,2):uint()

   while current < pktlen do
      local f_type = buffer(current, 1):uint()
      local f_length = buffer(current+1,2):uint()
      local x

      if f_type == 1 then
	 subtree:add(ubidisc_proto.fields.hwaddr, buffer(current+3, f_length))
      elseif f_type == 2 then
	 local addr = subtree:add(ubidisc_proto.fields.address, buffer(current+3, f_length))
	 addr:add(ubidisc_proto.fields.address_hwaddr, buffer(current+3, 6))
	 addr:add(ubidisc_proto.fields.address_ipv4, buffer(current+9, 4))
      elseif f_type == 3 then
	 subtree:add(ubidisc_proto.fields.firmware, buffer(current+3, f_length))
      elseif f_type == 10 then
	 subtree:add(ubidisc_proto.fields.uptime, buffer(current+3, f_length))
      elseif f_type == 11 then
	 subtree:add(ubidisc_proto.fields.hostname, buffer(current+3, f_length))
      elseif f_type == 12 then
	 subtree:add(ubidisc_proto.fields.product, buffer(current+3, f_length))
      elseif f_type == 13 then
	 subtree:add(ubidisc_proto.fields.essid, buffer(current+3, f_length))
      elseif f_type == 14 then
	 subtree:add(ubidisc_proto.fields.wmode, buffer(current+3, f_length))
      elseif f_type == 16 then
	 subtree:add(ubidisc_proto.fields.sysid, buffer(current+3, f_length))
      else
	 subtree:add(ubidisc_proto.fields.generic, buffer(current+3, f_length))
      end

      current = current + f_length + 3
   end
end

udp_table = DissectorTable.get("udp.port")
udp_table:add(10001, ubidisc_proto)
