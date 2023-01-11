# fwtapper

An in-kernel packet tapping (duplicating) service.

# How to run?
The tapper has two ends - a `transmit` end which transmits encapsulated packets to a destination ip,
and a `recieve` end which recieves encapsulated packets and decapsulates them.

To run the transmit end, run the following cmd:
```
sudo ./fwtapper transmit --destination-ip 10.0.100.8 --destination-mac 00:0d:3a:e8:06:ca
```

To run the recieve end, use the following cmd:
```
sudo ./fwtapper recieve --source-ips "10.0.100.5,..."
```

# How to verify the program is loaded properly?
Use the following command: `ip link`, and find the added interface `egress-iface` listed.
To see the `bpf` filter added use the following: `sudo tc -s -d filter show dev eth0 ingress`.
