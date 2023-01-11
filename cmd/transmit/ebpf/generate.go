// NOTE: The following comment is used to generate (using `go generate`) the eBPF object files and embed them into our code.
// Please, do not remove this line.  For more information see https://pkg.go.dev/github.com/cilium/ebpf/cmd/bpf2go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go ebpf ../bpf/bpf.c
package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	MAC_ADDR_SIZE  = 6
	IPv4_ADDR_SIZE = 4
	UINT_SIZE      = 4
)

// Represents the redirect destination.
type Destination struct {
	DefaultIfaceIdx uint32
	EgressIfaceIdx  uint32
	LocalIP         net.IP
	DestinationIP   net.IP
	SourceMac       net.HardwareAddr
	DestinationMAC  net.HardwareAddr
}

// MarshalBinary is required since net.IP and net.HardwareAddr are
// slices (pointers to array of arbitrary size),
// thus the default encoding would not know how to encode it to binary.
// For more information see: https://stackoverflow.com/a/65842289/3891733.
func (d Destination) MarshalBinary() (data []byte, err error) {
	size := UINT_SIZE + UINT_SIZE + IPv4_ADDR_SIZE + IPv4_ADDR_SIZE + MAC_ADDR_SIZE + MAC_ADDR_SIZE
	res := make([]byte, size)

	binary.LittleEndian.PutUint32(res, d.DefaultIfaceIdx)
	binary.LittleEndian.PutUint32(res[UINT_SIZE:], d.EgressIfaceIdx)
	copy(res[2*UINT_SIZE:], d.LocalIP)
	copy(res[2*UINT_SIZE+IPv4_ADDR_SIZE:], d.DestinationIP)
	copy(res[2*UINT_SIZE+2*IPv4_ADDR_SIZE:], d.SourceMac)
	copy(res[2*UINT_SIZE+2*IPv4_ADDR_SIZE+MAC_ADDR_SIZE:], d.DestinationMAC)
	return res, nil
}

// A wrapper containing the objects associated with the eBPF program attached;
// Including references to the eBPF maps and Filter and Qdisc that the the program is attached to.
// Used for user-space manipulation.
type Objects struct {
	objects             ebpfObjects
	ingressTapperFilter netlink.Filter
	egressTapperFilter  netlink.Filter
	tapperQdisc         netlink.Qdisc
	routerFilter        netlink.Filter
	routerQdisc         netlink.Qdisc
}

// LoadTappingPrograms loads the tc program to the kernel and attaches the program (by its file descriptor)
// to the {source, egress}Iface provided.
func LoadTappingPrograms(sourceIface netlink.Link, egressIface netlink.Link) (*Objects, error) {
	objs := ebpfObjects{}
	if err := loadEbpfObjects(&objs, nil); err != nil {
		return nil, err
	}

	tapperQdisc, ingresssTapperFilter, egressTapperFilter, err := attachTappingProgram(objs, sourceIface)
	if err != nil {
		return nil, err
	}

	routerQdisc, routerFilter, err := attachRoutingProgram(objs, egressIface)
	if err != nil {
		return nil, err
	}

	return &Objects{
		objs,
		ingresssTapperFilter,
		egressTapperFilter,
		tapperQdisc,
		routerFilter,
		routerQdisc,
	}, nil
}

// attachTappingProgram attaches the tapping program to the sourceIface
// for both the egress and ingress paths.
// this program taps (duplicate) packets from the source iface and redirects them to the egress
// interface for rerouting.
func attachTappingProgram(objs ebpfObjects, sourceIface netlink.Link) (
	netlink.Qdisc, netlink.Filter, netlink.Filter, error) {
	// Create a 'clsact' qdisc and attach it to our
	// source interface. This qdisc will than be used
	// to attach our bpf program on its ingress hook.
	// This qdisc is a dummy providing the necessary ingress/egress
	// hook points for our bpf program.
	// For more information please see: https://docs.cilium.io/en/latest/bpf/#tc-traffic-control
	attrs := netlink.QdiscAttrs{
		LinkIndex: sourceIface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}

	if err := netlink.QdiscAdd(qdisc); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to add qdisc: %v", err.Error())
	}

	ingressFilter := createTapperFilterForQdisc(netlink.HANDLE_MIN_INGRESS, sourceIface, objs)
	err := netlink.FilterAdd(ingressFilter)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to add filter err: %v", err.Error())
	}

	egressFilter := createTapperFilterForQdisc(netlink.HANDLE_MIN_EGRESS, sourceIface, objs)
	err = netlink.FilterAdd(egressFilter)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to add filter err: %v", err.Error())
	}

	return qdisc, ingressFilter, egressFilter, nil
}

func createTapperFilterForQdisc(path int, iface netlink.Link, objs ebpfObjects) netlink.Filter {
	var fd int
	switch path {
	case netlink.HANDLE_MIN_INGRESS:
		fd = objs.IngressTapper.FD()
	case netlink.HANDLE_MIN_EGRESS:
		fd = objs.EgressTapper.FD()
	}

	ingressFilterAttrs := netlink.FilterAttrs{
		LinkIndex: iface.Attrs().Index,
		Parent:    uint32(path),
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}

	return &netlink.BpfFilter{
		FilterAttrs:  ingressFilterAttrs,
		Fd:           fd,
		Name:         "tapper",
		DirectAction: true,
	}
}

// attachRoutingProgram attaches the tapping program to the egressIface
// this program routes packets out to the monitor host.
func attachRoutingProgram(objs ebpfObjects, egressIface netlink.Link) (netlink.Qdisc, netlink.Filter, error) {
	// Create a 'clsact' qdisc and attach it to our
	// source interface. This qdisc will than be used
	// to attach our bpf program on its ingress hook.
	// This qdisc is a dummy providing the necessary ingress/egress
	// hook points for our bpf program.
	// For more information please see: https://docs.cilium.io/en/latest/bpf/#tc-traffic-control
	attrs := netlink.QdiscAttrs{
		LinkIndex: egressIface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}

	if err := netlink.QdiscAdd(qdisc); err != nil {
		return nil, nil, fmt.Errorf("failed to add qdisc: %v", err.Error())
	}

	filterattrs := netlink.FilterAttrs{
		LinkIndex: egressIface.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}

	filter := &netlink.BpfFilter{
		FilterAttrs:  filterattrs,
		Fd:           objs.Router.FD(),
		Name:         "router",
		DirectAction: true,
	}

	err := netlink.FilterAdd(filter)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to add filter err: %v", err.Error())
	}

	return qdisc, filter, nil
}

func (o *Objects) UpdateDestinationsMap(key uint32, destination Destination) error {
	return o.objects.Destinations.Put(key, destination)
}

func (o *Objects) Detach() error {
	if err := o.objects.Close(); err != nil {
		return fmt.Errorf("failed to remove eBPF program: %v", err)
	}
	if err := netlink.FilterDel(o.routerFilter); err != nil {
		return fmt.Errorf("failed to delete filter: %v", err)
	}
	if err := netlink.QdiscDel(o.routerQdisc); err != nil {
		return fmt.Errorf("failed to delete qdisc: %v", err)
	}
	if err := netlink.FilterDel(o.ingressTapperFilter); err != nil {
		return fmt.Errorf("failed to delete filter: %v", err)
	}
	if err := netlink.FilterDel(o.egressTapperFilter); err != nil {
		return fmt.Errorf("failed to delete filter: %v", err)
	}
	if err := netlink.QdiscDel(o.tapperQdisc); err != nil {
		return fmt.Errorf("failed to delete qdisc: %v", err)
	}
	return nil
}
