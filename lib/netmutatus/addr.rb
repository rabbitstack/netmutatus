# The MIT License (MIT)
#
# Copyright (c) 2017 Nedim Sabic (Rabbitstack)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

require 'netmutatus/netlink'
require 'netmutatus/link'
require 'netmutatus/veth'
require 'netmutatus/errors'
require 'ffi'

module Netmutatus
  # Provides an abstraction for manipulating link's ip addresses.
  class Addr
    include Netlink

    attr_reader :ip

    # Creates a new address for the specific link device.
    #
    # @param [Object] link the link that receives this address either for addition or removal
    # @param [String] ip the ip address in ipv4 or ipv6 format with an optional subnet mask (i.e. 172.17.0.23/24)
    def initialize(link, ip)
      raise TypeError, "Invalid link object" unless link.kind_of?(Netmutatus::Link) \
        || link.kind_of?(Netmutatus::Veth)
      @link = link
      @ip = ip
      @addr = rtnl_addr_alloc
      if @addr.null?
        raise Errors::NetlinkError, 'Unable to allocate address'
      end

      addr = FFI::MemoryPointer.new(:pointer)
      if nl_addr_parse(FFI::MemoryPointer.from_string(ip), 0, addr) < 0
        raise Errors::NetlinkError, "Unable to parse addresss for #{ip} character string"
      end

      rtnl_addr_set_local(@addr, addr.get_pointer(0))

      # set the link index for the ip addresss structure
      rtnl_addr_set_ifindex(@addr, link.index)
    end

    # Attempts to assign ip address to the link.
    def add
      Netlink.do_in_netlink(Netlink::NETLINK_ROUTE) do |sock|
        status = rtnl_addr_add(sock,
                               @addr,
                               0)
        if status < 0
          raise Errors::NetlinkError, "Unable to set ip address for #{@link.name} link: #{Netlink.error(status)}"
        end
        rtnl_addr_put(@addr)
        rtnl_link_put(@link.raw)
      end
      self
    end

    # Removes an ip address from the link device.
    def remove
      Netlink.do_in_netlink(Netlink::NETLINK_ROUTE) do |sock|
        status = rtnl_addr_delete(sock,
                                  @addr,
                                  0)
        if status < 0
          raise Errors::NetlinkError, "Unable to delete ip address for #{@link.name} link: #{Netlink.error(status)}"
        end
        rtnl_addr_put(@addr)
        rtnl_link_put(@link.raw)
      end
    end
  end
end