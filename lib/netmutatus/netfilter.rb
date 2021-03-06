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
require 'netmutatus/errors'
require 'netmutatus/netlink'

module Netmutatus
  module Netfilter
    extend FFI::Library

    ffi_lib FFI::Library::LIBC, 'libnftnl.so', 'libmnl.so'

    # netfilter commands
    NFT_MSG_NEWTABLE = 0
    NFT_MSG_GETTABLE = 1
    NFT_MSG_DELTABLE = 2
    NFT_MSG_NEWCHAIN = 3
    NFT_MSG_GETCHAIN = 4
    NFT_MSG_DELCHAIN = 5
    NFT_MSG_NEWRULE = 6
    NFT_MSG_GETRULE = 7
    NFT_MSG_DELRULE = 8
    NFT_MSG_NEWSET = 9
    NFT_MSG_GETSET = 10
    NFT_MSG_DELSET = 11
    NFT_MSG_NEWSETELEM = 12
    NFT_MSG_GETSETELEM = 13
    NFT_MSG_DELSETELEM = 14
    NFT_MSG_MAX = 15

    # table flags
    NFT_TABLE_ATTR_NAME = 0
    NFT_TABLE_ATTR_FAMILY = 1
    NFT_TABLE_ATTR_FLAGS = 2

    # protocols
    NFPROTO_INET = 1
    NFPROTO_IPV4 = 2
    NFPROTO_ARP = 3
    NFPROTO_BRIDGE = 7
    NFPROTO_IPV6 = 10

    # chain attributes
    NFT_CHAIN_ATTR_NAME = 0
    NFT_CHAIN_ATTR_FAMILY = 1
    NFT_CHAIN_ATTR_TABLE = 2
    NFT_CHAIN_ATTR_HOOKNUM = 3
    NFT_CHAIN_ATTR_PRIO = 4
    NFT_CHAIN_ATTR_POLICY = 5
    NFT_CHAIN_ATTR_TYPE = 10

    # chain types
    NFT_CHAIN_T_DEFAULT = 0
    NFT_CHAIN_T_ROUTE = 1
    NFT_CHAIN_T_NAT = 2

    # chain hook types
    NF_INET_PRE_ROUTING = 0
    NF_INET_LOCAL_IN = 1
    NF_INET_FORWARD = 2
    NF_INET_LOCAL_OUT = 3
    NF_INET_POST_ROUTING = 4

    # rule attributes
    NFT_RULE_ATTR_FAMILY = 0
    NFT_RULE_ATTR_TABLE = 1
    NFT_RULE_ATTR_CHAIN = 2
    NFT_RULE_ATTR_HANDLE = 3

    # rule expressions
    NFT_EXPR_PAYLOAD_DREG = 1
    NFT_EXPR_PAYLOAD_BASE = 2
    NFT_EXPR_PAYLOAD_OFFSET = 3
    NFT_EXPR_PAYLOAD_LEN = 4

    NFT_EXPR_CMP_SREG = 1
    NFT_EXPR_CMP_OP = 2
    NFT_EXPR_CMP_DATA = 3

    NFT_EXPR_TG_NAME = 1
    NFT_EXPR_TG_REV = 2
    NFT_EXPR_TG_INFO = 3

    NFT_EXPR_IMM_DREG = 1
    NFT_EXPR_IMM_DATA = 2
    NFT_EXPR_IMM_VERDICT = 3
    NFT_EXPR_IMM_CHAIN = 4

    NFT_EXPR_NAT_TYPE = 1
    NFT_EXPR_NAT_FAMILY = 2
    NFT_EXPR_NAT_REG_ADDR_MIN = 3
    NFT_EXPR_NAT_REG_ADDR_MAX = 4
    NFT_EXPR_NAT_REG_PROTO_MIN = 5
    NFT_EXPR_NAT_REG_PROTO_MAX = 6
    NFT_EXPR_NAT_FLAGS = 7

    NFT_PAYLOAD_NETWORK_HEADER = 1
    NFT_PAYLOAD_TRANSPORT_HEADER = 2

    # netfilter registers
    NFT_REG_VERDICT = 0
    NFT_REG_1 = 1
    NFT_REG_2 = 2

    # verdict types
    NFT_CONTINUE = -1
    NFT_BREAK   = -2
    NFT_JUMP    = -3
    NFT_GOTO    = -4
    NFT_RETURN  = -5

    NFT_NAT_SNAT = 0
    NFT_NAT_DNAT = 1

    # responses from hook functions
    NF_DROP = 0
    NF_ACCEPT = 1

    # netfilter expression operators
    NFT_CMP_EQ = 0

    # ip protocols
    IPPROTO_TCP = 6
    IPPROTO_UDP = 17

    class NlMsgHdr < FFI::Struct
      layout :nlmsg_len, :uint32,
             :nlmsg_type, :uint16,
             :nlmsg_flags, :uint16,
             :nlmsg_seq, :uint32,
             :nlmsg_pid, :uint32

    end

    class NfGenMsg < FFI::Struct
      layout :nfgen_family, :uint8,
             :version, :uint8,
             :res_id, :int16
    end

    # ip.h
    class IpHdr < FFI::Struct
      layout :tos, :uint8,
             :tot_len, :uint16,
             :id, :uint16,
             :frag_off, :uint16,
             :ttl, :uint8,
             :protocol, :uint8,
             :check, :uint16,
             :saddr, :uint32,
             :daddr, :uint32
    end

    # tcp.h
    class TcpHdr < FFI::Struct
      layout :source, :uint16,
             :dest, :uint16,
             :seq, :uint32,
             :ack_seq, :uint32,
             :window, :uint16,
             :check, :uint16,
             :urg_ptr, :uint16
    end

    # udp.h
    class UdpHdr < FFI::Struct
      layout :source, :uint16,
             :dest, :uint16,
             :len, :uint16,
             :check, :uint16
    end

    # C declaration
    # struct nft_table *  nft_table_alloc (void)
    # Allocates a netfilter table structure
    attach_function :nft_table_alloc, [], :pointer

    # C declaration
    # struct nlmsghdr *  nft_nlmsg_build_hdr (char *buf, uint16_t cmd, uint16_t family, uint16_t type, uint32_t seq)
    attach_function :nft_nlmsg_build_hdr, [:pointer, :uint16, :uint16, :uint16, :uint32], NlMsgHdr.ptr

    # C declaration
    # void  nft_table_nlmsg_build_payload (struct nlmsghdr *nlh, const struct nft_table *t)
    #
    attach_function :nft_table_nlmsg_build_payload, [NlMsgHdr.ptr, :pointer], :void

    # C declaration
    # void nft_table_attr_set  (struct nft_table *  t, uint16_t attr, const void *  data)
    # Sets the attribute for the nft_table structure
    attach_function :nft_table_attr_set, [:pointer, :uint, :pointer], :void

    # C declaration
    # void nft_table_free  ( struct nft_table *   t )
    attach_function :nft_table_free, [:pointer], :void

    # C declaration
    # void   nft_table_attr_set_u32 (struct nft_table *t, uint16_t attr, uint32_t val)
    attach_function :nft_table_attr_set_u32, [:pointer, :uint16, :uint32], :void

    attach_function :nft_table_attr_get_u32, [:pointer, :uint16], :uint32

    attach_function :nft_table_attr_set_str, [:pointer, :uint16, :pointer], :void


    # C declaration
    # struct mnl_socket *   mnl_socket_open (int bus)
    attach_function :mnl_socket_open, [:int], :pointer

    attach_function :mnl_socket_close, [:pointer], :void

    attach_function :mnl_socket_bind, [:pointer, :uint, :uint32], :int

    # C declaration
    # ssize_t  mnl_socket_sendto (const struct mnl_socket *nl, const void *buf, size_t len)
    attach_function :mnl_socket_sendto, [:pointer, :pointer, :size_t], :int

    # C declaration
    # ssize_t  mnl_socket_recvfrom (const struct mnl_socket *nl, void *buf, size_t bufsiz)
    attach_function :mnl_socket_recvfrom, [:pointer, :pointer, :size_t], :size_t

    attach_function :nft_batch_is_supported, [], :int

    attach_function :nft_batch_begin, [:pointer, :uint32], :void

    attach_function :nft_batch_end, [:pointer, :uint32], :void

    attach_function :mnl_nlmsg_batch_start, [:pointer, :size_t], :pointer

    attach_function :mnl_nlmsg_batch_next, [:pointer], :bool

    attach_function :mnl_nlmsg_batch_current, [:pointer], :pointer

    attach_function :mnl_nlmsg_batch_stop, [:pointer], :void

    attach_function :mnl_nlmsg_batch_head, [:pointer], :pointer

    attach_function :mnl_nlmsg_batch_size, [:pointer], :size_t

    attach_function :mnl_nlmsg_put_header, [:pointer], NlMsgHdr.ptr

    attach_function :mnl_nlmsg_put_extra_header, [:pointer, :size_t], NfGenMsg.ptr

    # C declaration
    # unsigned int  mnl_socket_get_portid (const struct mnl_socket *nl)
    attach_function :mnl_socket_get_portid, [:pointer], :uint

    callback :mnl_cb_t, [:pointer, :pointer], :int
    # int mnl_cb_run (const void *buf, size_t numbytes, unsigned int seq, unsigned int portid, mnl_cb_t cb_data, void *data)
    attach_function :mnl_cb_run, [:pointer, :size_t, :uint, :uint, :mnl_cb_t, :pointer], :int


    # chains

    attach_function :nft_chain_alloc, [], :pointer

    attach_function :nft_chain_free, [:pointer], :void

    attach_function :nft_chain_attr_set, [:pointer, :uint, :pointer], :void

    attach_function :nft_chain_attr_set_u32, [:pointer, :uint16, :uint32], :void

    attach_function :nft_chain_nlmsg_build_payload, [:pointer, :pointer], :void

    # rules

    attach_function :nft_rule_expr_set_u32, [:pointer, :uint16, :uint32], :void

    attach_function :nft_rule_expr_set_u16, [:pointer, :uint16, :uint16], :void

    attach_function :nft_rule_attr_get_u32, [:pointer, :uint16], :uint32

    attach_function :nft_rule_expr_set, [:pointer, :uint16, :pointer, :uint32], :void

    attach_function :nft_rule_expr_alloc, [:pointer], :pointer

    attach_function :nft_rule_expr_free, [:pointer], :void

    attach_function :nft_rule_add_expr, [:pointer, :pointer], :void

    attach_function :nft_rule_alloc, [], :pointer

    attach_function :nft_rule_free, [:pointer], :void

    attach_function :nft_rule_attr_set, [:pointer, :uint16, :pointer], :void

    attach_function :nft_rule_attr_set_u32, [:pointer, :uint16, :uint32], :void

    attach_function :nft_rule_nlmsg_build_payload, [:pointer, :pointer], :void

    attach_function :getpagesize, [], :int

    attach_function :htons, [:uint16], :uint16

    attach_function :htonl, [:uint32], :uint32

    attach_function :strerror, [:int], :pointer

    # Assembles and sends a batch via Netfilter datagram socket.
    #
    # @param [FFI::MemoryPointer] batch pointer to allocated batch
    # @param [FFI::MemoryPointer] buffer stores the allocated batch
    # @param [Numeric] seq the unique sequence id
    def self.emit_netfilter_req(batch, buffer, seq)
      sock = mnl_socket_open(Netlink::NETLINK_NETFILTER)

      if sock.null?
        raise Errors::NetfilterError, 'Unable to open Netfilter socket'
      end

      if mnl_socket_bind(sock, 0, 0) < 0
          raise Errors::NetfilterError, 'Unable to bind Netfilter socket'
      end

      if mnl_socket_sendto(sock,
                           mnl_nlmsg_batch_head(batch),
                           mnl_nlmsg_batch_size(batch)) < 0
          raise Errors::NetfilterError, 'Cannot send batch via Netfilter socket'
      end

      portid = mnl_socket_get_portid(sock)
      mnl_nlmsg_batch_stop(batch)

      # check for result
      ret = mnl_socket_recvfrom(sock, buffer, buffer.size)
      while ret > 0
        ret = mnl_cb_run(buffer, ret, seq, portid, nil, nil)
        if ret <= 0
          break
        end
        ret = mnl_socket_recvfrom(sock, buffer, buffer.size)
      end

      if ret < 0
        raise Errors::NetfilterError, "Unable to execute Netfilter command: #{Netfilter.strerror(FFI.errno).get_string(0)}"
      end

      mnl_socket_close(sock)
    end

    # Initializes a batch storing it inside the buffer. A single batch
    # can hold multiple messages. This function also makes a room for
    # a new message inside the batch.
    #
    # @param [Numeric] seq the unique sequence id of this batch
    def self.begin_batch(seq)
      pagesize = Netfilter.getpagesize
      buffer = FFI::MemoryPointer.new(:char, pagesize < 8192 ? pagesize : 8192)

      batch = Netfilter.mnl_nlmsg_batch_start(buffer, buffer.size)
      if batch.null?
        raise Errors::Netlink, "Unable to start batch"
      end

      Netfilter.nft_batch_begin(mnl_nlmsg_batch_current(batch), Netfilter.increment_seq(seq))
      Netfilter.mnl_nlmsg_batch_next(batch)

      return batch, buffer
    end

    # Ends the current batch identified with provided sequence.
    #
    # @param [FFI::MemoryPointer] batch pointer to allocated batch
    # @param [Numeric] seq the unique sequence id of this batch
    def self.end_batch(batch, seq)
      Netfilter.nft_batch_end(mnl_nlmsg_batch_current(batch), Netfilter.increment_seq(seq))
      Netfilter.mnl_nlmsg_batch_next(batch)
    end

    # Checks if batching support is present. It will raise an error
    # if no support for batching is available.
    def self.batch_supported?
     raise Errors::NetfilterError, 'Unable to communicate with netfilter interface. Batching feature is not supported' \
        unless Netfilter.nft_batch_is_supported
    end

    def self.init_seq
      Time.now.to_i
    end

    def self.increment_seq(seq)
      seq += 1
    end

  end
end

