package recieve

import (
	"errors"
	"log"
	"net"

	"fwtapper/cmd/recieve/ebpf"
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
	Use:   "recieve",
	Short: "Runs the in-kernel FW tapper recieve end.",
	Run:   runTapperRecieve,
}

type Args struct {
	ingressIface string
	sourceIPs    []string
	decapIface   string
}

var cmdLineArgs Args

func init() {
	Cmd.Flags().StringSliceVar(&cmdLineArgs.sourceIPs, "source-ips", nil, "The IP address for the source host.")
	Cmd.Flags().StringVar(&cmdLineArgs.ingressIface, "ingress-iface", "eth0", "The interface used for ingressing traffic.")
	Cmd.Flags().StringVar(&cmdLineArgs.decapIface, "decap-iface", "decap0", "The interface used for routing the decapsulated traffic.")
}

func runTapperRecieve(cmd *cobra.Command, args []string) {
	if err := validateFlags(cmdLineArgs); err != nil {
		log.Fatal(err)
	}

	// Allow the current process to lock memory for eBPF resources, if necessary.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memory lock: %v", err)
	}
	ingressIface, err := netlink.LinkByName(cmdLineArgs.ingressIface)
	if err != nil {
		log.Fatalf("Failed to find ingress interface '%s': %v", cmdLineArgs.ingressIface, err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs, err := ebpf.LoadEncapsulateProgram(ingressIface)
	if err != nil {
		log.Fatalf("Failed to load eBPF objects to kernel: %v", err)
	}
	defer objs.Detach()

	decapIface, err := iface.VerifyExists(cmdLineArgs.decapIface)
	if err != nil {
		log.Fatalf("Failed to verify decap interface '%s': %v", cmdLineArgs.decapIface, err)
	}
	defer iface.DetachIface(decapIface)

	err = objs.UpdateDecapIfaceArray(defaultKey, ebpf.DecapIface(decapIface.Attrs().Index))
	if err != nil {
		log.Fatalf("failed to update decap_interface map: %v", err)
	}

	origins := parseOrigins(cmdLineArgs.sourceIPs)
	for _, origin := range origins {
		err = objs.UpdateOriginsMap(origin, 1)
		if err != nil {
			log.Fatalf("failed to update origins map: %v", err)
		}
	}

	log.Println("Waiting for events..")
	<-signals.CreateChannel()
	log.Println("Exiting...")
}

func validateFlags(cmdLineArgs Args) error {
	if len(cmdLineArgs.sourceIPs) == 0 {
		return errors.New("the 'source-ips' argument must be provided, zero source IPs were provided")
	}
	return nil
}

func parseOrigins(sourceIPs []string) []ebpf.Origin {
	res := make([]ebpf.Origin, len(cmdLineArgs.sourceIPs))
	for i, ip := range cmdLineArgs.sourceIPs {
		res[i] = ebpf.Origin(net.ParseIP(ip).To4())
	}
	return res
}
