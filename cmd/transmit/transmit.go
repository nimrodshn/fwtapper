package transmit

import (
	"errors"
	"log"
	"net"

	"fwtapper/cmd/transmit/ebpf"
	"fwtapper/pkg/iface"
	"fwtapper/pkg/signals"

	"github.com/cilium/ebpf/rlimit"
	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
)

var (
	defaultKey uint32 = 0
)

var Cmd = cobra.Command{
	Use:   "transmit",
	Short: "Runs the in-kernel FW tapper transmit end.",
	Run:   runTapper,
}

type Args struct {
	egressIface    string
	sourceiface    string
	destinationMac string
	destinationIP  string
}

var cmdLineArgs Args

func init() {
	Cmd.Flags().StringVar(&cmdLineArgs.destinationMac, "destination-mac", "", "The mac address for the destination host.")
	Cmd.Flags().StringVar(&cmdLineArgs.destinationIP, "destination-ip", "", "The IP address for the destination host.")
	Cmd.Flags().StringVar(&cmdLineArgs.egressIface, "egress-iface", "tap0", "The interface used for egressing tapped (cloned) traffic.")
	Cmd.Flags().StringVar(&cmdLineArgs.sourceiface, "source-iface", "eth0", "The interface used as source for tapping traffic (defaults to 'eth0').")
}

func runTapper(cmd *cobra.Command, args []string) {
	if err := validateFlags(cmdLineArgs); err != nil {
		log.Fatal(err)
	}

	// Allow the current process to lock memory for eBPF resources, if necessary.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memory lock: %v", err)
	}

	sourceIface, err := netlink.LinkByName(cmdLineArgs.sourceiface)
	if err != nil {
		log.Fatalf("Failed to find default interface '%s': %v", cmdLineArgs.sourceiface, err)
	}

	localIP, err := iface.GetIPAddress(sourceIface)
	if err != nil {
		log.Fatalf("Failed to find IP address for interface '%s': %v", sourceIface.Attrs().Name, err)
	}

	egressIface, err := iface.VerifyExists(cmdLineArgs.egressIface)
	if err != nil {
		log.Fatalf("Failed to verify egress interface '%s': %v", cmdLineArgs.egressIface, err)
	}
	defer iface.DetachIface(egressIface)

	// Load pre-compiled programs and maps into the kernel.
	objs, err := ebpf.LoadTappingPrograms(sourceIface, egressIface)
	if err != nil {
		log.Fatalf("Failed to load eBPF objects to kernel: %v", err)
	}
	defer objs.Detach()

	// Set destinations map with our egress interface to route traffic to it.
	destMAC, err := net.ParseMAC(cmdLineArgs.destinationMac)
	if err != nil {
		log.Fatalf("Failed to parse provided mac address '%s': %v", cmdLineArgs.destinationMac, err)
	}
	destination := ebpf.Destination{
		DefaultIfaceIdx: uint32(sourceIface.Attrs().Index),
		EgressIfaceIdx:  uint32(egressIface.Attrs().Index),
		LocalIP:         localIP.To4(),
		DestinationIP:   net.ParseIP(cmdLineArgs.destinationIP).To4(),
		SourceMac:       sourceIface.Attrs().HardwareAddr,
		DestinationMAC:  destMAC,
	}
	err = objs.UpdateDestinationsMap(defaultKey, destination)
	if err != nil {
		log.Fatalf("failed to update destinations map: %v", err)
	}

	log.Println("Waiting for events..")
	<-signals.CreateChannel()
	log.Println("Exiting...")
}

func validateFlags(cmdLineArgs Args) error {
	if cmdLineArgs.destinationMac == "" {
		return errors.New("the 'destination-mac' argument must be provided")
	}
	if cmdLineArgs.destinationIP == "" {
		return errors.New("the 'destination-ip' argument must be provided")
	}
	return nil
}
