package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strconv"

	"github.com/avast/retry-go"
	"github.com/gammazero/workerpool"
	dhcp4 "github.com/packethost/dhcp4-go"
	"github.com/packethost/pkg/env"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/tinkerbell/boots/conf"
	"github.com/tinkerbell/boots/job"
	"github.com/tinkerbell/boots/metrics"
)

var listenAddr = conf.BOOTPBind
var server *DHCPServer

type DHCPServer struct {
	start      net.IP        // Start of IP range to distribute
	subnet     net.IP        // Hardware subnet mask
	gateway    net.IP        // Gateway IP
	leaseRange int           // Number of IPs to distribute (starting from start)
	leases     map[int]lease // Map to keep track of leases
}

type lease struct {
	nic string // Client's CHAddr
}

func init() {
	var start string
	if start = os.Getenv("START_IP"); start == "" {
		start = "192.168.1.2/24"
	}
	ip, mask, err := net.ParseCIDR(start)
	subnet := net.IP(mask.Mask)

	if err != nil {
		mainlog.Fatal(err)
	}

	var gateway string
	if gateway = os.Getenv("PUBLIC_IP"); gateway == "" {
		gateway = "192.168.1.1"
	}
	gatewayIP := net.ParseIP(gateway)

	var leaseRange string
	if leaseRange = os.Getenv("LEASE_RANGE"); leaseRange == "" {
		leaseRange = "253"
	}
	leaserange, err := strconv.Atoi(leaseRange)

	if err != nil {
		mainlog.Fatal(err)
	}

	server = &DHCPServer{
		start:      ip,
		subnet:     subnet,
		gateway:    gatewayIP,
		leaseRange: leaserange,
		leases:     make(map[int]lease, leaserange),
	}

	flag.StringVar(&listenAddr, "dhcp-addr", listenAddr, "IP and port to listen on for DHCP.")
}

// ServeDHCP is a useless comment
func ServeDHCP() {
	poolSize := env.Int("BOOTS_DHCP_WORKERS", runtime.GOMAXPROCS(0)/2)
	handler := dhcpHandler{pool: workerpool.New(poolSize)}
	defer handler.pool.Stop()

	err := retry.Do(
		func() error {
			return errors.Wrap(dhcp4.ListenAndServe(listenAddr, handler), "serving dhcp")
		},
	)
	if err != nil {
		mainlog.Fatal(errors.Wrap(err, "retry dhcp serve"))
	}
}

type dhcpHandler struct {
	pool *workerpool.WorkerPool
}

func (d dhcpHandler) ServeDHCP(w dhcp4.ReplyWriter, req *dhcp4.Packet) {
	d.pool.Submit(func() { d.serveDHCP(w, req) })
}

func (d dhcpHandler) serveDHCP(w dhcp4.ReplyWriter, req *dhcp4.Packet) {
	mac := req.GetCHAddr()
	if conf.ShouldIgnoreOUI(mac.String()) {
		mainlog.With("mac", mac).Info("mac is in ignore list")
		return
	}

	if req.GetMessageType().String() == "DHCPRELEASE" {
		server.releaseLease(mac)
		return
	}

	gi := req.GetGIAddr()
	if conf.ShouldIgnoreGI(gi.String()) {
		mainlog.With("giaddr", gi).Info("giaddr is in ignore list")
		return
	}

	metrics.DHCPTotal.WithLabelValues("recv", req.GetMessageType().String(), gi.String()).Inc()
	labels := prometheus.Labels{"from": "dhcp", "op": req.GetMessageType().String()}
	metrics.JobsTotal.With(labels).Inc()
	metrics.JobsInProgress.With(labels).Inc()
	timer := prometheus.NewTimer(metrics.JobDuration.With(labels))

	circuitID, err := getCircuitID(req)
	if err != nil {
		mainlog.With("mac", mac, "err", err).Info("error parsing option82")
	} else {
		mainlog.With("mac", mac, "circuitID", circuitID).Info("parsed option82/circuitid")
	}

	var j = job.Job{}
	j, err = job.CreateFromDHCP(mac, gi, circuitID)
	if err != nil {
		// Tink did not find any HW
		mainlog.With("mac", mac, "err", err).Info("retrieved hw is empty. MAC address is unknown to tink")
		metrics.JobsInProgress.With(labels).Dec()
		timer.ObserveDuration()

		// Check if we want to use default workflows
		if os.Getenv("ENABLE_DEFAULT_WORKFLOWS") != "1" {
			// We don't want default workflows, so just return
			return
		} else {
			mainlog.With("mac", mac).Info("Default workflow enabled")

			// Assign IP address
			var free int = -1
			if free = server.freeLease(); free == -1 {
				// No free IP address to assign
				mainlog.With("mac", mac).Error(err, "No IP addresses left to assign")
				metrics.JobsInProgress.With(labels).Dec()
				timer.ObserveDuration()
				return
			}
			IPaddr := IPAdd(server.start, free)

			// We want default workflows, so at first we will need to create a hardware
			j, err = job.CreateHWFromDHCP(mac, gi, circuitID, IPaddr, server.subnet, server.gateway)
			if err != nil {
				mainlog.With("mac", mac).Error(err, "failed to create hw")
				metrics.JobsInProgress.With(labels).Dec()
				timer.ObserveDuration()
				return
			}
			server.addLease(mac, IPaddr)
			mainlog.Info("DHCPServer has assigned " + strconv.Itoa(len(server.leases)) + " leases of a maximum " + strconv.Itoa(server.leaseRange))

			// Hardware is now created, we must now grab the 'default' template
			tid, err := job.GetTemplate("default")
			if err != nil {
				mainlog.With("mac", mac).Error(err, "no default template exists")
				metrics.JobsInProgress.With(labels).Dec()
				timer.ObserveDuration()
				return
			}

			// We have the 'default' template ID, now to make a workflow from it
			wid, err := job.CreateWorkflow(tid, mac)
			if err != nil {
				mainlog.With("mac", mac).Error(err, "failed to create workflow")
				metrics.JobsInProgress.With(labels).Dec()
				timer.ObserveDuration()
				return
			}
			mainlog.With("mac", mac).Info(fmt.Sprintf(`Created workflow (%s) for machine (%s) with IP (%s)`, wid, mac.String(), IPaddr.String()))
		}
	}
	go func() {
		if j.ServeDHCP(w, req) {
			metrics.DHCPTotal.WithLabelValues("send", "DHCPOFFER", gi.String()).Inc()
		}
		metrics.JobsInProgress.With(labels).Dec()
		timer.ObserveDuration()
	}()
}

func getCircuitID(req *dhcp4.Packet) (string, error) {
	var circuitID string
	// Pulling option82 information from the packet (this is the relaying router)
	// format: byte 1 is option number, byte 2 is length of the following array of bytes.
	eightytwo, ok := req.GetOption(dhcp4.OptionRelayAgentInformation)
	if ok {
		if int(eightytwo[1]) < len(eightytwo) {
			circuitID = string(eightytwo[2:eightytwo[1]])
		} else {
			return circuitID, errors.New("option82 option1 out of bounds (check eightytwo[1])")
		}
	}
	return circuitID, nil
}

func (s *DHCPServer) freeLease() int {
	b := rand.Intn(s.leaseRange) // Try random first
	for _, v := range [][]int{{b, s.leaseRange}, {0, b}} {
		for i := v[0]; i < v[1]; i++ {
			if _, ok := s.leases[i]; !ok {
				return i
			}
		}
	}
	return -1
}

func (s *DHCPServer) addLease(mac net.HardwareAddr, reqIP net.IP) {
	if leaseNum := IPRange(s.start, reqIP) - 1; leaseNum >= 0 && leaseNum < s.leaseRange {
		if l, exists := s.leases[leaseNum]; !exists || l.nic == mac.String() {
			s.leases[leaseNum] = lease{nic: mac.String()}
		}
	}
}

func (s *DHCPServer) releaseLease(mac net.HardwareAddr) {
	for i, v := range server.leases {
		if v.nic == mac.String() {
			delete(server.leases, i)
			break
		}
	}
}

// IPAdd returns a copy of start + add.
// IPAdd(net.IP{192,168,1,1},30) returns net.IP{192.168.1.31}
func IPAdd(ip net.IP, add int) net.IP {
	inc := uint(add)
	i := ip.To4()
	v := uint(i[0])<<24 + uint(i[1])<<16 + uint(i[2])<<8 + uint(i[3])
	v += inc
	v3 := byte(v & 0xFF)
	v2 := byte((v >> 8) & 0xFF)
	v1 := byte((v >> 16) & 0xFF)
	v0 := byte((v >> 24) & 0xFF)
	return net.IPv4(v0, v1, v2, v3)
}

// IPRange returns how many ips in the ip range from start to stop (inclusive)
func IPRange(start, stop net.IP) int {
	return int(binary.BigEndian.Uint32(stop.To4())) - int(binary.BigEndian.Uint32(start.To4())) + 1
}
