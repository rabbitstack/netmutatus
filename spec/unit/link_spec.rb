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

require 'rspec'
require 'mocha'
require 'netmutatus/link'
require 'netmutatus/netlink'
require 'netmutatus/errors'

describe Netmutatus::Link do

  describe '.new' do
    let(:cache_mock) { mock('Cache') }
    let(:link_mock) { mock('Link') }
    let(:new_link_mock) { mock('Link') }
    let(:sock_mock) { mock('Sock') }

    context 'retrieves the link' do
      it 'retrieves an existing link' do
        Netmutatus::Link.any_instance.stubs(:do_in_netlink).yields(sock_mock)
        Netmutatus::Link.any_instance.stubs(:rtnl_link_alloc_cache).returns(0)
        Netmutatus::Link.any_instance.stubs(:rtnl_link_get_by_name).returns(link_mock)
        link_mock.expects(:null?).times(3).returns(false)
        link = Netmutatus::Link.new('eth1')
        expect(link.name).to eq 'eth1'
        expect(link.exists?).to be_truthy
      end

      it 'fails to allocate the link cache' do
        Netmutatus::Link.any_instance.stubs(:do_in_netlink).yields(sock_mock)
        Netmutatus::Link.any_instance.stubs(:rtnl_link_alloc_cache).returns(-1)
        expect{ Netmutatus::Link.new('eth1') }.to raise_error(Netmutatus::Errors::NetlinkError)
      end
    end

    context 'creates the link' do
      it 'creates a new link' do
        Netmutatus::Link.any_instance.stubs(:alloc_cache).returns(cache_mock)
        Netmutatus::Link.any_instance.stubs(:rtnl_link_get_by_name).returns(link_mock)
        Netmutatus::Link.any_instance.stubs(:rtnl_link_alloc).returns(new_link_mock)
        Netmutatus::Link.any_instance.stubs(:rtnl_link_add).returns(1)
        Netmutatus::Link.any_instance.stubs(:rtnl_link_set_name).returns(0)
        Netmutatus::Link.any_instance.stubs(:rtnl_link_set_type).returns(0)
        Netmutatus::Link.any_instance.stubs(:do_in_netlink).yields(sock_mock)
        link_mock.expects(:null?).returns(true)
        new_link_mock.expects(:null?).twice.returns(false)
        link = Netmutatus::Link.new('eth1', true)
        expect(link.exists?).to be_truthy
      end

      it 'fails to create a new link' do
        Netmutatus::Link.any_instance.stubs(:alloc_cache).returns(cache_mock)
        Netmutatus::Link.any_instance.stubs(:rtnl_link_get_by_name).returns(link_mock)
        Netmutatus::Link.any_instance.stubs(:rtnl_link_alloc).returns(new_link_mock)
        Netmutatus::Link.any_instance.stubs(:rtnl_link_set_name).returns(0)
        Netmutatus::Link.any_instance.stubs(:rtnl_link_set_type).returns(0)
        Netmutatus::Link.any_instance.stubs(:rtnl_link_add).returns(-1)
        Netmutatus::Link.any_instance.stubs(:do_in_netlink).yields(sock_mock)
        link_mock.expects(:null?).returns(true)
        expect {Netmutatus::Link.new('eth1', true)}.to raise_error(Netmutatus::Errors::NetlinkError)
      end
    end
  end

  describe '#delete' do
    let(:cache_mock) { mock('Cache') }
    let(:sock_mock) { mock('Sock') }
    let(:link_mock) { mock('Link') }

    it 'deletes the link successfully' do
      Netmutatus::Link.any_instance.stubs(:alloc_cache).returns(cache_mock)
      Netmutatus::Link.any_instance.stubs(:do_in_netlink).yields(sock_mock)
      Netmutatus::Link.any_instance.stubs(:rtnl_link_get_by_name).returns(link_mock)
      Netmutatus::Link.any_instance.stubs(:rtnl_link_delete).returns(0)
      link_mock.expects(:null?).twice.returns(false)
      link = Netmutatus::Link.new('eth1')
      expect(link.delete).to be_truthy
      expect(link.exists?).to be_falsey
    end

    it 'fails to delete the link' do
      Netmutatus::Link.any_instance.stubs(:alloc_cache).returns(cache_mock)
      Netmutatus::Link.any_instance.stubs(:do_in_netlink).yields(sock_mock)
      Netmutatus::Link.any_instance.stubs(:rtnl_link_get_by_name).returns(link_mock)
      Netmutatus::Link.any_instance.stubs(:rtnl_link_delete).returns(-1)
      link_mock.expects(:null?).times(3).returns(false)
      link = Netmutatus::Link.new('eth1')
      expect(link.delete).to be_falsey
      expect(link.exists?).to be_truthy
    end

  end
end
