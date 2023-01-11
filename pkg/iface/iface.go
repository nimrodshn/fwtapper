package iface

import (
	"fmt"
	"log"
	"net"

	"github.com/vishvananda/netlink"
)

// VerifyExists verifies if an interface named 'ifaceName' exists.
func VerifyExists(ifaceName string) (netlink.Link, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	egressIfaceMissing := true
	for _, iface := range interfaces {
		if iface.Name == ifaceName {
			egressIfaceMissing = false
		}
	}
	// Create the egress interface if its missing.
	var egressIface netlink.Link
	if egressIfaceMissing {
		la := netlink.NewLinkAttrs()
		la.Name = ifaceName
		egressIface = &netlink.Dummy{
			LinkAttrs: la,
		}
		err := netlink.LinkAdd(egressIface)
		if err != nil {
			log.Printf("could not add link %s: %v\n", la.Name, err)
			return nil, err
		}
		err = netlink.LinkSetUp(egressIface)
		if err != nil {
			log.Printf("could not activate link %s: %v\n", la.Name, err)
			return nil, err
		}
	} else {
		egressIface, err = netlink.LinkByName(ifaceName)
		if err != nil {
			return nil, err
		}
	}
	return egressIface, nil
}

// DetacheIface detaches the interface associated with iface.
func DetachIface(iface netlink.Link) error {
	return netlink.LinkDel(iface)
}

func GetIPAddress(iface netlink.Link) (net.IP, error) {
	defIface, err := net.InterfaceByIndex(iface.Attrs().Index)
	if err != nil {
		return nil, err
	}
	addrs, err := defIface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP, nil
			}
		}
	}
	return nil, fmt.Errorf("failed to find address attached to interface '%s'",
		iface.Attrs().Name)
}
