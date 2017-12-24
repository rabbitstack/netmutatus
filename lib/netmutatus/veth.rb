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

    # Creates a new veth network interface and its corresponding peer link.
    #
    # @param [String] veth_name veth interface name
    # @param [String] peer_name peer interface name
    def initialize(veth_name, peer_name)
      Netlink.do_in_netlink(Netlink::NETLINK_ROUTE) do |sock|
        @veth = rtnl_link_veth_alloc

        if @veth.null?
          raise Errors::VethError, 'Unable to allocate veth link'
        end
        @peer = rtnl_link_veth_get_peer(@veth)

        # initialize interface names
        rtnl_link_set_name(@veth, FFI::MemoryPointer.from_string(veth_name))
        rtnl_link_set_name(@peer, FFI::MemoryPointer.from_string(peer_name))

        status = rtnl_link_add(sock, @veth,
                               Netlink::NLM_F_CREATE |
                               Netlink::NLM_F_EXCL |
                               Netlink::NLM_F_ACK)
        if status < 0
          raise Errors::VethError, "Unable to add veth pair #{veth_name} <-> #{peer_name}: #{Netlink.error(status)}"
        end
        rtnl_link_put(@peer)
        rtnl_link_put(@veth)
      end
    end

  end

end