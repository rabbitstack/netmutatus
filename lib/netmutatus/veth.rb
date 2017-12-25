# The MIT License (MIT)
#
# Copyright (c) 2016 Nedim Sabic (Rabbitstack)
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
require 'netmutatus/errors'
require 'ffi'

module Netmutatus
  # Virtual Ethernet (veth) mimics a physical network interface
  # and is often used to connect two different network namespaces.
  # The veth kernel device comes with a pair of interfaces, the veth
  # interface and the peer interface which allows to route the traffic
  # from one global namespace to the other one.
  class Veth
    include Netlink

    attr_reader :veth_name, :peer_name

    # Creates a new veth network interface and its corresponding peer link.
    #
    # @param [String] veth_name veth interface name
    # @param [String] peer_name peer interface name
    # @param [bool] force determines if veth links are created if not found in the cache
    def initialize(veth_name, peer_name, force=true)
      @cache = Netlink.alloc_cache
      @veth_name = veth_name
      @peer_name = peer_name
      @veth_addrs = {}
      @peer_addrs = {}

      @veth = rtnl_link_get_by_name(@cache, FFI::MemoryPointer.from_string(veth_name))
      @peer = rtnl_link_get_by_name(@cache, FFI::MemoryPointer.from_string(peer_name))

      if (@veth.null? && @peer.null?) && force
        # no veth and peer links found, so we attempt to create them
        Netlink.do_in_netlink(Netlink::NETLINK_ROUTE) do |sock|
          @veth = rtnl_link_veth_alloc

          if @veth.null?
            raise Errors::VethError, 'Unable to allocate veth link'
          end
          @peer = rtnl_link_veth_get_peer(@veth)

          # initialize interface names
          rtnl_link_set_name(@veth, FFI::MemoryPointer.from_string(veth_name))
          rtnl_link_set_name(@peer, FFI::MemoryPointer.from_string(peer_name))

          status = rtnl_link_add(sock,
                                 @veth,
                                 Netlink::NLM_F_CREATE |
                                 Netlink::NLM_F_EXCL |
                                 Netlink::NLM_F_ACK)

          if status < 0
            raise Errors::VethError, "Unable to add veth pair #{veth_name} <-> #{peer_name}: #{Netlink.error(status)}"
          end

          rtnl_link_put(@peer)
          rtnl_link_put(@veth)

          # reallocate cache and retrieve the links
          @cache = Netlink.alloc_cache
          @veth = rtnl_link_get_by_name(@cache, FFI::MemoryPointer.from_string(veth_name))
          @peer = rtnl_link_get_by_name(@cache, FFI::MemoryPointer.from_string(peer_name))
          if @veth.null? || @peer.null?
            raise Errors::VethError, "Failed to retrieve veth pair #{veth_name} <-> #{peer_name} from the cache"
          end
        end
      end
    end

    # Adds an ip address for veth interface.
    #
    # @param [String] ip the ip address in ipv4 or ipv6 format
    def add_veth_address(ip)
      if @veth_addrs.key?(ip)
        return
      end
      @veth_addrs[ip] = Netmutatus::Addr.new(self, ip).add
    end

    # Adds an ip address for peer interface.
    #
    # @param [String] ip the ip address in ipv4 or ipv6 format
    def add_peer_address(ip)
      if @peer_addrs.key?(ip)
        return
      end
      @peer_addrs[ip] = Netmutatus::Addr.new(self, ip, veth_peer=true).add
    end

    def veth_index
      rtnl_link_get_ifindex(@veth)
    end

    def peer_index
      rtnl_link_get_ifindex(@peer)
    end

    def raw_veth
      @veth
    end

    def raw_peer
      @peer
    end
  end
end