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

require 'netmutatus/errors'
require 'netmutatus/netfilter'
require 'netmutatus/netlink'
require 'ffi'

module Netmutatus
   module Netfilter

      class Table
        include Netfilter

        # Creates a new netfilter table.
        #
        # The table represents the container
        # for chains. Unlike in iptables, there
        # are no built-in tables in netfilter
        # tables. Tables can have any of these
        # families including ip, ipv6, arp, bridge
        # and inet.
        # @param [String] name netfilter table name
        # @param [Symbol] family table protocol family
        def initialize(name, family=:ip)
          @name = name
          @family = Netfilter::NFPROTO_IPV4
          case family
            when :ip
              @family = Netfilter::NFPROTO_IPV4
            when :ipv6
              @family = Netfilter::NFPROTO_IPV6
            when :inet
              @family = Netfilter::NFPROTO_INET
            when :arp
              @family = Netfilter::NFPROTO_ARP
            when :bridge
              @family = Netfilter::NFPROTO_BRIDGE
            else
              raise Errors::NetfilterErrror, "#{family} is unsupported family. Please choose :ip|:ipv6|:inet|:arp|:bridge"
          end

          table = nft_table_alloc

          if table.null?
              raise Errors::NetfilterError, 'Unable to allocate netfilter table'
          end

          # set basic table attributes
          nft_table_attr_set_u32(table, Netfilter::NFT_TABLE_ATTR_FAMILY, family)
          nft_table_attr_set_str(table, Netfilter::NFT_TABLE_ATTR_NAME, FFI::MemoryPointer.from_string(@name))

          # create table
          emit_table_req(Netfilter::NFT_MSG_NEWTABLE, table, family)
        end

        private

        # Emits a Netfilter request with specific Netfilter table command.
        #
        # @param [Numeric] cmd the identifier of the Netfilter table command
        # @param [FFI::MemoryPointer] table pointer to allocated table structure
        # @param [Numeric] family the identifier of the table family
        # @param [Numeric] flags bitwise pattern for table flags
        def emit_table_req(cmd, table, family, flags=nil)
            Netfilter.batch_supported?

            seq = Netfilter.init_seq
            batch, buffer = Netfilter.begin_batch(seq)

            # build up the netfilter message
            # (header + payload)
            seq = Netfilter.increment_seq(seq)
            table_flags = flags != nil ? Netlink::NLM_F_ACK | flags : Netlink::NLM_F_ACK
            header = nft_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                         cmd,
                                         family,
                                         table_flags, seq)
            nft_table_nlmsg_build_payload(header, table)
            nft_table_free(table)
            mnl_nlmsg_batch_next(batch)

            Netfilter.end_batch(batch, seq)

            # send request to the netfilter subsystem
            Netfilter.emit_netfilter_req(batch, buffer, seq)
        end
      end
   end
end
