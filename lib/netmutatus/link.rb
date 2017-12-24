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
require 'netmutatus/errors'
require 'netmutatus/addr'
require 'ffi'

module Netmutatus
  # Provides an abstraction layer to manipulate the configuration
  # of virtual and physical network devices aka network interfaces.
  #
  class Link
    include Netlink

    attr_reader :name

    DUMMY_LINK_TYPE = "dummy"

    # Creates or retrieves the specified link device.
    #
    # @param [string] name human readable link name
    # @param [bool] force flag determines if
    #   link should be created in case it's not found.
    #   By default, it attempts to create a new link if
    #   the provided one is not found in the cache.
    def initialize(name, force=true)
      @cache = alloc_cache
      @name = name
      @state = :down
      @mac = nil
      @broadcast = '255.255.255.255'
      @index = 0
      @group = :default
      @mtu = 1500
      @txqlen = 0

      @addrs = {}

      @link = rtnl_link_get_by_name(@cache, FFI::MemoryPointer.from_string(@name))

      if force and @link.null?
        # no matching links found, try to create a new link
        @link = rtnl_link_alloc

        rtnl_link_set_name(@link, FFI::MemoryPointer.from_string(@name))
        rtnl_link_set_type(@link, FFI::MemoryPointer.from_string(DUMMY_LINK_TYPE))

        Netlink.do_in_netlink(Netlink::NETLINK_ROUTE) do |sock|
          status = rtnl_link_add(sock,
                                @link,
                                Netlink::NLM_F_CREATE | Netlink::NLM_F_EXCL |
                                Netlink::NLM_F_ACK)
          if status < 0
            raise Errors::NetlinkError, "Unable to create #{@name} link: #{Netlink.error(status)}"
          end
        end
      end

      raise Errors::Netlink, "#{@name} link not found" unless exists?
    end

    # Deletes a link.
    # @return [bool] true if the link has been deleted successfully, false otherwise
    def delete
      Netlink.do_in_netlink(Netlink::NETLINK_ROUTE) do |sock|
        if rtnl_link_delete(sock, @link) == 0
          @link = nil
          return true
        end
        false
      end
    end

    # Gets the operational state of the link.
    # @return [Symbol] the symbol describing the link state.
    def state
      oper_state = rtnl_link_get_operstate(@link)
      case oper_state
        when Netlink::IF_OPER_UP
          @state = :up
        when Netlink::IF_OPER_DOWN
          @state = :down
        when Netlink::IF_OPER_UNKNOWN
          @state = :unknown
        when Netlink::IF_OPER_DORMANT
          @state = :dormant
        when Netlink::IF_OPER_LOWERLAYERDOWN
          @state = :layerdown
        when Netlink::IF_OPER_NOTPRESENT
          @state = :notpresent
        when Netlink::IF_OPER_TESTING
          @state = :testing
        else
          @state = :unknown
      end
      @state
    end

    # Sets the link operational state.
    # @param [Symbol] state the new link state
    def state=(state)
      case state
        when :up
          oper_state = Netlink::IF_OPER_UP
        when :down
          oper_state = Netlink::IF_OPER_DOWN
        when :unknown
          oper_state = Netlink::IF_OPER_UNKNOWN
        when :dormant
          oper_state = Netlink::IF_OPER_DORMANT
        when :layerdown
          oper_state = Netlink::IF_OPER_LOWERLAYERDOWN
        when :notpresent
          oper_state = Netlink::IF_OPER_NOTPRESENT
        when :testing
          oper_state = Netlink::IF_OPER_TESTING
        else
          raise Netlink::Error, "#{state} is not a valid operational state"
      end
      alloc = rtnl_link_alloc
      rtnl_link_set_operstate(alloc, oper_state)
      emit_change(alloc)
      @state = state
    end

    # Retrieves the integer which uniquely identifies the link.
    # @return [int] the numeric value identifying the link
    def index
      @index = rtnl_link_get_ifindex(@link)
    end

    # Sets the index for the link.
    # @param [int] index the link index value
    def index=(index)
      alloc = rtnl_link_alloc
      rtnl_link_set_ifindex(alloc, index)
      emit_change(alloc)
      @index = index
    end

    # Gets the identifier of the group to which the link belongs.
    # The operations can be applied to a group of links instead of
    # just a single link.
    # @return [Numeric] the numeric value of the link's group
    def group
      @group = rtnl_link_get_group(@link)
    end

    # Sets the identifier of the link's group. Any changes made to
    # a group propagates to all the links.
    # @param [Numeric] group the group identifier
    def group=(group)
      alloc = rtnl_link_alloc
      rtnl_link_set_group(alloc, group)
      emit_change(alloc)
      @group = group
    end

    # Gets the physical / MAC address of the link.
    # @return [str] the MAC address of the link
    def mac
      addr = rtnl_link_get_addr(@link)
      buf = FFI::MemoryPointer.new(:char, Netlink::MAXMACADDR)
      mac = nl_addr2str(addr, buf, Netlink::MAXMACADDR)
      mac.get_string(0) unless mac.null?
    end

    def mac=(mac)

    end

    # Adds a new ip address to this link device.
    #
    # @param [String] ip the ip address in ipv4 or ipv6 format
    def add_address(ip)
      if @addrs.key?(ip)
        return
      end
      @addrs[ip] =  Netmutatus::Addr.new(self, ip).add
    end

    # Removes an ip address from this link device.
    #
    # @param [String] ip the ip address in ipv4 or ipv6 format
    def remove_address(ip)
      if @addrs.key?(ip)
        @addrs[ip].remove(ip)
      else
        Netmutatus::Addr.new(self, ip).remove
      end
      @addrs.delete(ip) if @addrs.key?(ip)
    end

    def exists?
      !@link.nil? and !@link.null?
    end

    def up?
      @state == :up
    end

    def raw
      @link
    end

    private

    # Allocates the link cache where the links can be hold.
    # A netlink message is sent to the kernel requesting a full dump of all configured links.
    # The returned messages are parsed and filled into the cache. If the operation succeeds
    # the resulting cache will a link object for each link configured in the kernel.
    #
    # @return [FFI::MemoryPointer] the pointer to the allocated cache
    def alloc_cache
      cache = FFI::MemoryPointer.new(:pointer)
      Netlink.do_in_netlink(Netlink::NETLINK_ROUTE) do |sock|
        if rtnl_link_alloc_cache(sock, 0, cache) < 0
          raise Errors::NetlinkError, 'Unable to allocate Netlink cache'
        end
      end
      cache.get_pointer(0)
    end


    def emit_change(change)
      Netlink.do_in_netlink(Netlink::NETLINK_ROUTE) do |sock|
        status = rtnl_link_change(sock,
                                  @link,
                                  change, 0)
        if status < 0
          raise Errors::NetlinkError, "Failed to apply changes to #{@name} link: #{Netlink.error(status)}"
        end
        rtnl_link_put(@link)
        rtnl_link_put(change)
      end
    end

  end

end
