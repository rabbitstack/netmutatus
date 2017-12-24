# Netmutatus

**Netmutatus** (still in active development) provides native bindings for `netlink` and `netfilter` Linux subsystems offering the user a neat abstraction layer for creating link devices, `veth` interfaces, manipulating routing tables or handling packet filtering or address translation through `netfilter` among other tasks.

- [x] link devices
- [x] veth devices
- [ ] addresses
- [ ] bridging
- [ ] bonding
- [ ] routing
- [x] netfilter tables
- [ ] netfilter chains
- [ ] netfilter rules
- [ ] MACVLAN
- [ ] VLAN
- [ ] VXLAN
- [ ] neighbours

## Requirements

Ensure `libnl-route`, `libnl`, `libnftnl` and `libmnl` shared objects are present on your system. Most distros already ship
with those libraries, but in any case you can fetch them with the following command if you're on Ubuntu/Debian:

```bash
$ sudo apt-get install libnl-route-3-200 libnl-3-200 libnftnl4 libmnl0
```

Also, make sure to create symbolic links for above libraries to match the name of the shared object expected by `ffi`:

```bash
$ sudo ln -s /lib/x86_64-linux-gnu/libnl-3.so.200 /lib/x86_64-linux-gnu/libnl-3.so
$ sudo ln -s /usr/lib/x86_64-linux-gnu/libnl-route-3.so.200 /usr/lib/x86_64-linux-gnu/libnl-route-3.so
$ sudo ln -s /usr/lib/x86_64-linux-gnu/libnftnl.so.4 /usr/lib/x86_64-linux-gnu/libnftnl.so
$ sudo ln -s /lib/x86_64-linux-gnu/libmnl.so.0 /lib/x86_64-linux-gnu/libmnl.so
```
