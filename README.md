# EtherApe - Graphical Network Monitor

## Overview
EtherApe is a graphical network monitor that displays network activity graphically. The program visually shows connections between various hosts, highlighting protocols with different colors.

It uses GNOME libraries for its user interface and libpcap for packet capture and filtering. EtherApe started as an etherman clone but now has unique features like "interape" mode (-m ip) and "tcp-ape" mode (-m tcp).

## Dependencies
The following dependencies are required to compile and run EtherApe:

- `libgoocanvas-2.0-dev` - For the canvas UI component
- `libpopt-dev` - For command-line argument parsing
- Standard build tools (`build-essential`, `autoconf`, etc.)

## Installation

### Compilation Process

1. Configure the build system:
   ```
   ./configure
   ```

2. Compile the software:
   ```
   make
   ```

3. Install the software (requires superuser privileges):
   ```
   sudo make install
   ```

By default, binaries will be copied to `/usr/local/sbin`. To uninstall later, run:
```
sudo make uninstall
```

### Post-Installation Steps

If the installation fails in the documentation part, but the main executable is compiled and installed, you may need to manually copy UI files:

```
sudo mkdir -p /usr/local/share/etherape/glade
sudo cp glade/etherape.ui glade/etherape.png /usr/local/share/etherape/glade/
```

## Running EtherApe

EtherApe requires root privileges to capture packets:

```
sudo etherape
```

Or to view help:

```
etherape --help
```

### Configuration

EtherApe will use `/etc/ethers` if there is one. If not, it will try to reverse lookup the IP address.

> **IMPORTANT!** It is particularly important when running EtherApe to have the ethernet address of your router in `/etc/ethers`. If not, your router will have as name whatever IP address it was forwarding traffic from when it was first heard.

### Using Filters

EtherApe supports standard libpcap filter syntax for capturing specific types of traffic:

```
sudo etherape -f "tcp port 80 or tcp port 443"  # Capture only HTTP and HTTPS traffic
```

Common filter examples:
- `host 192.168.1.1` - Show only traffic to/from a specific host
- `port 22` - Show only SSH traffic
- `not port 53` - Exclude DNS traffic
- `icmp` - Show only ICMP (ping) traffic
- `tcp` - Show only TCP traffic

## Features

- Graphical display of network connections
- Protocol filtering and colorization
- Interface selection
- Packet capture and replay
- Multiple viewing modes (interape, tcp-ape)
- IPv4 and IPv6 support

## Troubleshooting

- If you encounter "missing separator" errors in the doc/Makefile during installation, it's usually safe to ignore as long as the main executable was installed.
- If EtherApe crashes with errors about missing UI files, follow the post-installation steps above.

## Porting

Historically EtherApe has been compiled and run on:
* Linux: Debian, Slackware, RedHat, modified linuxppc, Debian m68k
* NetBSD 1.4T (i386)
* Sparc Solaris 7 with gcc 2.95.2

EtherApe should probably compile and run on other Unix-like operating systems.

## Further Information

- See the EtherApe web page at https://etherape.sourceforge.io/
- To receive updates about new releases, go to http://sourceforge.net/project/?group_id=2712 and click "Monitor this module"
- See README.bugs for instructions on how to send a bug report. 