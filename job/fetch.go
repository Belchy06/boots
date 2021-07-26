package job

import (
	"net"

	"github.com/golang/groupcache/singleflight"
	"github.com/tinkerbell/boots/packet"
)

var (
	servers singleflight.Group
)

func discoverHardwareFromDHCP(mac net.HardwareAddr, giaddr net.IP, circuitID string) (packet.Discovery, error) {
	fetch := func() (interface{}, error) {
		return client.DiscoverHardwareFromDHCP(mac, giaddr, circuitID)
	}
	v, err := servers.Do(mac.String(), fetch)
	if err != nil {
		return nil, err
	}
	return v.(packet.Discovery), nil
}

func createHardwareFromDHCP(mac net.HardwareAddr, giaddr net.IP, circuitID string, ip net.IP, subnet net.IP, gateway net.IP) (packet.Discovery, error) {
	create := func() (interface{}, error) {
		return client.CreateHardwareFromDHCP(mac, giaddr, circuitID, ip, subnet, gateway)
	}
	v, err := servers.Do(mac.String(), create)
	if err != nil {
		return nil, err
	}
	return v.(packet.Discovery), nil
}

func discoverHardwareFromIP(ip net.IP) (packet.Discovery, error) {
	fetch := func() (interface{}, error) {
		return client.DiscoverHardwareFromIP(ip)
	}
	v, err := servers.Do(ip.String(), fetch)
	if err != nil {
		return nil, err
	}
	return v.(packet.Discovery), nil
}
