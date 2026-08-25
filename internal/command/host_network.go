package command

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"warptweet.com/warptweet/internal/enrollment"
	"warptweet.com/warptweet/internal/inspectnet"
	"warptweet.com/warptweet/internal/server"
)

type hostPublicationFlags struct {
	Listen          onceStringFlag
	ListenInterface onceStringFlag
	Advertise       onceStringFlag
	EnrollListen    onceStringFlag
	EnrollAdvertise onceStringFlag
}

type hostPublication struct {
	DataListen   server.BindEndpoint
	EnrollListen server.BindEndpoint
	DataDial     server.DialEndpoint
	EnrollDial   server.DialEndpoint
}

func resolveHostPublication(
	flags hostPublicationFlags,
	stored *server.Config,
	discover func() (netip.Addr, error),
	ifaces []inspectnet.Interface,
) (hostPublication, error) {
	if flags.Listen.set && flags.ListenInterface.set {
		return hostPublication{}, fmt.Errorf("host --listen cannot be combined with --listen-interface")
	}
	dataListen, err := resolveDataListen(flags, stored, discover, ifaces)
	if err != nil {
		return hostPublication{}, err
	}
	dataDial, err := resolveDataDial(flags.Advertise, dataListen, stored)
	if err != nil {
		return hostPublication{}, err
	}
	dataChanged := flags.Listen.set || flags.ListenInterface.set || flags.Advertise.set
	enrollListen, err := resolveEnrollListenFlag(flags.EnrollListen, dataListen, stored, dataChanged)
	if err != nil {
		return hostPublication{}, err
	}
	enrollDial, err := resolveEnrollDial(flags.EnrollAdvertise, dataDial, stored, dataChanged)
	if err != nil {
		return hostPublication{}, err
	}
	return hostPublication{
		DataListen:   dataListen,
		EnrollListen: enrollListen,
		DataDial:     dataDial,
		EnrollDial:   enrollDial,
	}, nil
}

func resolveDataListen(
	flags hostPublicationFlags,
	stored *server.Config,
	discover func() (netip.Addr, error),
	ifaces []inspectnet.Interface,
) (server.BindEndpoint, error) {
	if flags.ListenInterface.set {
		addr, err := inspectnet.AddressForInterface(flags.ListenInterface.value, ifaces)
		if err != nil {
			return server.BindEndpoint{}, err
		}
		return server.BindEndpoint{Address: addr, Port: defaultHostListenPort}, nil
	}
	listen, err := resolveListen(flags.Listen.value, stored, discover)
	if err != nil {
		return server.BindEndpoint{}, err
	}
	return server.BindEndpoint{Address: listen.Addr(), Port: listen.Port()}, nil
}

func resolveDataDial(advertise onceStringFlag, dataListen server.BindEndpoint, stored *server.Config) (server.DialEndpoint, error) {
	listenDial := server.DialFromBind(dataListen)
	if !advertise.set {
		if stored != nil && !sameDialEndpointValue(stored.Network.Data.Dial, listenDial) {
			return stored.Network.Data.Dial, nil
		}
		return listenDial, nil
	}
	if advertise.value == "" {
		return listenDial, nil
	}
	parsed, err := parsePublishedEndpoint(advertise.value)
	if err != nil {
		return server.DialEndpoint{}, fmt.Errorf("advertise: %w", err)
	}
	if sameDialEndpointValue(parsed, listenDial) {
		return listenDial, nil
	}
	return parsed, nil
}

func resolveEnrollListenFlag(flag onceStringFlag, dataListen server.BindEndpoint, stored *server.Config, dataChanged bool) (server.BindEndpoint, error) {
	if flag.set && flag.value != "" {
		endpoint, err := parseEndpoint(flag.value)
		if err != nil {
			return server.BindEndpoint{}, fmt.Errorf("enroll-listen: %w", err)
		}
		return server.BindEndpoint{Address: endpoint.Addr(), Port: endpoint.Port()}, nil
	}
	if stored != nil && !dataChanged && !flag.set {
		return stored.Network.Enrollment.Listen, nil
	}
	return server.BindEndpoint{Address: dataListen.Address, Port: enrollment.DefaultEnrollmentPort}, nil
}

func resolveEnrollDial(flag onceStringFlag, dataDial server.DialEndpoint, stored *server.Config, dataChanged bool) (server.DialEndpoint, error) {
	if flag.set && flag.value != "" {
		parsed, err := parsePublishedEndpoint(flag.value)
		if err != nil {
			return server.DialEndpoint{}, fmt.Errorf("enroll-advertise: %w", err)
		}
		return parsed, nil
	}
	if stored != nil && !dataChanged && !flag.set {
		return stored.Network.Enrollment.Dial, nil
	}
	return server.DialEndpoint{Host: dataDial.Host, Port: enrollment.DefaultEnrollmentPort}, nil
}

func parsePublishedEndpoint(value string) (server.DialEndpoint, error) {
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return server.DialEndpoint{}, err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return server.DialEndpoint{}, fmt.Errorf("port must be a nonzero TCP port")
	}
	dialHost, err := server.ParseDialHost(host)
	if err != nil {
		return server.DialEndpoint{}, err
	}
	return server.DialEndpoint{Host: dialHost, Port: uint16(port)}, nil
}

func sameDialEndpointValue(left, right server.DialEndpoint) bool {
	return left.Port == right.Port && left.Host.Equal(right.Host)
}
