// NOTE: The following comment is used to generate (using `go generate`) the eBPF object files and embed them into our code.
// Please, do not remove this line.  For more information see https://pkg.go.dev/github.com/cilium/ebpf/cmd/bpf2go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go ebpf ../bpf/bpf.c

package ebpf

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	IPv4_ADDR_SIZE = 4
)

type Origin net.IP

type DecapIface uint32

// MarshalBinary is required since net.IP is a slice (pointers to array of arbitrary size),
// thus the default encoding would not know how to encode it to binary.
// For more information see: https://stackoverflow.com/a/65842289/3891733.
func (d Origin) MarshalBinary() (data []byte, err error) {
	res := make([]byte, IPv4_ADDR_SIZE)
	copy(res, d)
	return res, nil
}

// A wrapper containing the objects associated with the eBPF program attached;
// Including references to the eBPF maps and Filter and Qdisc that the the program is attached to.
// Used for user-space manipulation.
type Objects struct {
	objects ebpfObjects
	filter  netlink.Filter
	qdisc   netlink.Qdisc
}

// LoadEncapsulateProgram loads the tc program to the kernel and attaches the program (by its file descriptor)
// to the ingress iface provided.
func LoadEncapsulateProgram(ingressIface netlink.Link) (*Objects, error) {
	objs := ebpfObjects{}
	if err := loadEbpfObjects(&objs, nil); err != nil {
		return nil, err
	}
	// Create a 'clsact' qdisc and attach it to our
	// source interface. This qdisc will than be used
	// to attach our bpf program on its ingress hook.
	// This qdisc is a dummy providing the necessary ingress/egress
	// hook points for our bpf program.
	// For more information please see: https://docs.cilium.io/en/latest/bpf/#tc-traffic-control
	attrs := netlink.QdiscAttrs{
		LinkIndex: ingressIface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}

	if err := netlink.QdiscAdd(qdisc); err != nil {
		return nil, fmt.Errorf("failed to add qdisc: %v", err.Error())
	}

	filterattrs := netlink.FilterAttrs{
		LinkIndex: ingressIface.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}

	filter := &netlink.BpfFilter{
		FilterAttrs:  filterattrs,
		Fd:           objs.Decap.FD(),
		Name:         "decap",
		DirectAction: true,
	}

	err := netlink.FilterAdd(filter)
	if err != nil {
		return nil, fmt.Errorf("failed to add filter err: %v", err.Error())
	}

	return &Objects{
		objs,
		filter,
		qdisc,
	}, nil
}

func (o *Objects) UpdateOriginsMap(key Origin, value uint32) error {
	return o.objects.OriginsMap.Put(key, value)
}

func (o *Objects) UpdateDecapIfaceArray(key uint32, value DecapIface) error {
	return o.objects.DecapIfaceMap.Put(key, value)
}

func (o *Objects) Detach() error {
	if err := o.objects.Close(); err != nil {
		return fmt.Errorf("failed to remove eBPF program: %v", err)
	}
	if err := netlink.FilterDel(o.filter); err != nil {
		return fmt.Errorf("failed to delete filter: %v", err)
	}
	if err := netlink.QdiscDel(o.qdisc); err != nil {
		return fmt.Errorf("failed to delete qdisc: %v", err)
	}
	return nil
}
