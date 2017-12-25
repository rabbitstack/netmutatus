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

require 'ffi'

module Netmutatus
  module Netlink
    extend FFI::Library

    ffi_lib 'libnl-route-3.so', 'libnl-3.so'

    RTM_NEWLINK = 16

    # netlink protocols
    NETLINK_ROUTE = 0
    NETLINK_NETFILTER = 12

    # flag values
    NLM_F_REQUEST = 1
    NLM_F_MULTI   = 2
    NLM_F_ACK     = 4
    NLM_F_ECHO    = 8

    # modifiers to new netlink request
    NLM_F_REPLACE = 0x100
    NLM_F_EXCL    = 0x200
    NLM_F_CREATE  = 0x400
    NLM_F_APPEND  = 0x800

    # address family
    AF_INET = 2

    MAXIFNAME = 30
    MAXMACADDR = 17

    # link status
    IF_OPER_UNKNOWN = 0
    IF_OPER_NOTPRESENT = 1
    IF_OPER_DOWN = 2
    IF_OPER_LOWERLAYERDOWN = 3
    IF_OPER_TESTING = 4
    IF_OPER_DORMANT = 5
    IF_OPER_UP = 6
    IFF_UP = 0x0001

    # Allocates a new netlink socket.
    # @returns pointer to newly allocated socket or null
    attach_function :nl_socket_alloc, [], :pointer

    # Creates a new netlink socket and binds the socket
    # to the protocol.
    # @returns 0 on success or negative error code
    attach_function :nl_connect, [:pointer, :int], :int

    # Closes the netlink socket.
    attach_function :nl_close, [:pointer], :void

    attach_function :nl_cache_put, [:pointer], :void

    attach_function :nl_geterror, [:int], :pointer

    attach_function :nl_addr_parse, [:pointer, :int, :pointer], :int

    attach_function :nl_addr2str, [:pointer, :pointer, :int], :pointer

    # Allocates a link object of type veth.
    # @returns allocated link object or null
    attach_function :rtnl_link_veth_alloc, [], :pointer

    # Adds a virtual link.
    # @returns 0 on success or negative error code
    attach_function :rtnl_link_add, [:pointer, :pointer, :int], :int

    # Changes a virtual link.
    # @returns 0 on success or negative error code
    attach_function :rtnl_link_change, [:pointer, :pointer, :pointer, :int], :int

    # Returns a link object reference.
    attach_function :rtnl_link_put, [:pointer], :void

    # Allocates a link object.
    # @returns allocated link object or null
    attach_function :rtnl_link_alloc, [], :pointer

    # Return name of a link object.
    # @returns link object name
    attach_function :rtnl_link_get_name, [:pointer], :char

    # Set a name of the link object.
    attach_function :rtnl_link_set_name, [:pointer, :pointer], :void

    # Set the type of link object.
    attach_function :rtnl_link_set_type, [:pointer, :pointer], :int

    # Gets the peer link of a veth link.
    # @returns the peer link object
    attach_function :rtnl_link_veth_get_peer, [:pointer], :pointer

    # Lookups link in cache by link name.
    # @returns returns the link object or null if match can't be found
    attach_function :rtnl_link_get_by_name, [:pointer, :pointer], :pointer

    # Allocates link cache and fill in all configured links. The kernel
    # will respond with full a full dump of configured links.
    # @returns 0 on success or negative error code
    attach_function :rtnl_link_alloc_cache, [:pointer, :int, :pointer], :int

    # Deletes a link.
    # @returns if no matching link exists, returns negative error code
    # or 0 otherwise
    attach_function :rtnl_link_delete, [:pointer, :pointer], :int

    # Sets operational status of the link object.
    attach_function :rtnl_link_set_operstate, [:pointer, :uint8], :void

    # Gets operational status of the link object.
    # @returns operational status
    attach_function :rtnl_link_get_operstate, [:pointer], :uint8

    attach_function :rtnl_link_veth_add, [:pointer, :pointer, :pointer, :int], :int

    attach_function :rtnl_link_name2i, [:pointer, :pointer], :int

    attach_function :rtnl_link_i2name, [:pointer, :int, :string, :size_t], :pointer

    attach_function :rtnl_link_get_ifindex, [:pointer], :int

    attach_function :rtnl_link_set_ifindex, [:pointer, :int], :void

    attach_function :rtnl_link_get_addr, [:pointer], :pointer

    attach_function :rtnl_link_set_addr, [:pointer, :pointer], :void

    attach_function :rtnl_link_get_group, [:pointer], :int

    attach_function :rtnl_link_set_group, [:pointer, :int], :void

    attach_function :rtnl_link_get, [:pointer, :int], :pointer

    attach_function :rtnl_link_set_flags, [:pointer, :uint], :void

    attach_function :rtnl_link_unset_flags, [:pointer, :uint], :void

    attach_function :rtnl_addr_alloc, [], :pointer

    attach_function :rtnl_addr_put, [:pointer], :void

    attach_function :rtnl_addr_add, [:pointer, :pointer, :int], :int

    attach_function :rtnl_addr_delete, [:pointer, :pointer, :int], :int

    attach_function :rtnl_addr_set_local, [:pointer, :pointer], :int

    attach_function :rtnl_addr_set_ifindex, [:pointer, :int], :void

    attach_function :rtnl_link_get_master, [:pointer], :int

    attach_function :rtnl_link_set_master, [:pointer, :int], :void

    attach_function :rtnl_link_bridge_alloc, [], :pointer

    attach_function :rtnl_link_bridge_add, [:pointer, :pointer], :int

    attach_function :rtnl_link_enslave, [:pointer, :pointer, :pointer], :int

    attach_function :rtnl_link_release, [:pointer, :pointer], :int

    attach_function :rtnl_link_set_ns_fd, [:pointer, :int], :void

    attach_function :rtnl_link_set_ns_pid, [:pointer, :int], :void

    # Allocates a netlink socket and binds it to the protocol and local
    # port specified by `nl_sock` structure.
    #
    # @param [String] proto netlink protocol to use
    def self.do_in_netlink(proto)
      sock = Netlink.nl_socket_alloc
      if sock.null?
        raise NetlinkError, 'Unable to allocate netlink socket'
      end
      if Netlink.nl_connect(sock, proto) < 0
        raise NetlinkError, 'Unable to bind netlink socket'
      end
      yield sock
      Netlink.nl_close(sock)
    end

    # Allocates the link cache where the links can be hold.
    # A netlink message is sent to the kernel requesting a full dump of all configured links.
    # The returned messages are parsed and filled into the cache. If the operation succeeds
    # the resulting cache will a link object for each link configured in the kernel.
    #
    # @return [FFI::MemoryPointer] the pointer to the allocated cache
    def self.alloc_cache
      cache = FFI::MemoryPointer.new(:pointer)
      Netlink.do_in_netlink(Netlink::NETLINK_ROUTE) do |sock|
        if Netlink.rtnl_link_alloc_cache(sock, 0, cache) < 0
          raise Errors::NetlinkError, 'Unable to allocate Netlink cache'
        end
      end
      cache.get_pointer(0)
    end

    # Returns an human readable error message from Netlink error code.
    #
    # @param [Number] error netlink error code
    def self.error(error)
      Netlink.nl_geterror(error).get_string(0)
    end

  end
end

