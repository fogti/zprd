# zprd

## USAGE

ZPRD is a simple, unencrypted IPv4 tunnel tool,
which is a server and can be a client.

The ZPRD was created to tunnel through complex routing setups
with firewalls, NATs and VPNs.

## NOTES

 - The ZPRD establishes peer connections at startup.

 - The ZPRD manages incomming connections.

 - The ZPRD **doesn't encrypt** any data, as it is designed
   to have very less overhead. It is intended to be used
   in combination with VPN software.

 - The ZPRD ONLY tunnels IPv4 packets over UDP and IPv4.

   - protocol stacking: ```ethernet > ipv4 > udp > ipv4 > payload```

## Manual Setup

 - compile zprd / installation

```
  mkdir -p build && cd build
  cmake .. && make -j3 && make install
```

 - setup /etc/zprd.conf (content; initial)

```  Itun3```

 - setup interface (this is usually done by the daemontools)

```
  ip tuntap add mode tun user ... tun3
  ip addr add .../24 dev tun3
  # MTU = base MTU (1500) - UDP (8) - IP (20)
  ip link set dev tun3 mtu 1472
  ip link set dev tun3 up
```

 - start zprd (this is usually done by the daemontools)

```  ./zprd```

## Setup using daemontools on Gentoo

 - fetch the portage overlay

```
  cd /usr
  git clone https://github.com/zserik/portage-zscheile
```

 - emerge the package with: ```emerge -av =net-misc/zprd-9999```

 - setup /etc/zprd.conf (content; initial)

```
  Itun3
  A192.168.0.1/24
```

 - enable the service with: ```ln -s -t /service /etc/zprd```

 - enable svscan with: ```rc-update add svscan```

 - start svscan with: ```/etc/init.d/svscan restart```
