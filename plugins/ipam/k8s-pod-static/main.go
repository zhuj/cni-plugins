package main

import (
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"strings"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
)

const k8sPodName = "K8S_POD_NAME"

type NetConf struct {
	types.NetConf
	IPAM *IPAMConfig `json:"ipam"`
}

type IPAMConfig struct {
	Name string
	Type string                    `json:"type"`
	Pods map[string]*IPAMPodConfig `json:"pods"`
}

type IPAMPodConfig struct {
	Addresses []*Address     `json:"addresses,omitempty"`
	Routes    []*types.Route `json:"routes"`
	DNS       types.DNS      `json:"dns"`
}

type Address struct {
	AddressStr string `json:"address"`
	Gateway    net.IP `json:"gateway,omitempty"`
	Address    net.IPNet
	Version    string
}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("static"))
}

func cmdCheck(args *skel.CmdArgs) error {
	conf, err := loadConfig(args)
	if err != nil {
		return err
	}

	result, err := lookup(conf, args)
	if err != nil {
		return err
	}

	// Parse previous result.
	if conf.RawPrevResult == nil {
		return fmt.Errorf("required prevResult missing")
	}

	if err := version.ParsePrevResult(&conf.NetConf); err != nil {
		return err
	}

	prevResult, err := current.NewResultFromResult(conf.PrevResult)
	if err != nil {
		return err
	}

	if !reflect.DeepEqual(result, prevResult) {
		return fmt.Errorf("k8s-pod-static: Failed to match addr %+v on interface %v", result, args.IfName)
	}

	return nil
}

func cmdAdd(args *skel.CmdArgs) error {
	conf, err := loadConfig(args)
	if err != nil {
		return err
	}

	result, err := lookup(conf, args)
	if err != nil {
		return err
	}

	return types.PrintResult(result, conf.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	// Nothing required because of no resource allocation in static plugin.
	return nil
}

func loadConfig(args *skel.CmdArgs) (NetConf, error) {
	conf := NetConf{}
	if err := json.Unmarshal(args.StdinData, &conf); err != nil {
		return NetConf{}, fmt.Errorf("error parsing netconf: %v", err)
	}

	for _, podConf := range conf.IPAM.Pods {
		for _, addr := range podConf.Addresses {
			if len(addr.Address.IP) <= 0 {
				ip, cidr, err := net.ParseCIDR(addr.AddressStr)
				if err != nil {
					return NetConf{}, fmt.Errorf(
						"the 'address' field is expected to be in CIDR notation, got: '%s'",
						addr.AddressStr,
					)
				}
				addr.Address = *cidr
				addr.Address.IP = ip
			}
			if err := canonicalizeIP(&addr.Address.IP); err != nil {
				return NetConf{}, fmt.Errorf("invalid address %+v: %s", addr.Address, err)
			}
		}
	}

	conf.IPAM.Name = conf.Name
	return conf, nil
}

func canonicalizeIP(ip *net.IP) error {
	if ipv4 := ip.To4(); ipv4 != nil {
		*ip = ipv4
		return nil
	} else if ipv6 := ip.To16(); ipv6 != nil {
		*ip = ipv6
		return nil
	}
	return fmt.Errorf("IP %s not v4 nor v6", *ip)
}

func parseCNIArgs(cniArgs string) map[string]string {
	cniArgsParsed := map[string]string{}
	for _, argPair := range strings.Split(cniArgs, ";") {
		args := strings.SplitN(argPair, "=", 2)
		if len(args) > 1 {
			cniArgsParsed[args[0]] = args[1]
		}
	}
	return cniArgsParsed
}

func lookup(conf NetConf, args *skel.CmdArgs) (*current.Result, error) {
	cniArgsParsed := parseCNIArgs(args.Args)
	podName := cniArgsParsed[k8sPodName]
	if len(podName) <= 0 {
		return nil, fmt.Errorf("no k8s pod specified: %+v", cniArgsParsed)
	}

	podConf := conf.IPAM.Pods[podName]
	if podConf == nil {
		return nil, fmt.Errorf("no static config found for pod: %s", podName)
	}
	if len(podConf.Addresses) <= 0 {
		return nil, fmt.Errorf("no addressess configured for pod: %s, %+v", podName, podConf)
	}

	result := &current.Result{
		CNIVersion: current.ImplementedSpecVersion,
		DNS:        podConf.DNS,
		Routes:     podConf.Routes,
	}
	for _, v := range podConf.Addresses {
		if len(v.Address.IP) <= 0 {
			return nil, fmt.Errorf("no addressess configured for pod: %s, %+v", podName, podConf)
		}
		result.IPs = append(result.IPs, &current.IPConfig{
			Address: v.Address,
			Gateway: v.Gateway,
		})
	}
	return result, nil
}
