package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"github.com/gogf/gf/v2/container/garray"
	"github.com/gogf/gf/v2/encoding/gbinary"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gcache"
	"github.com/gogf/gf/v2/os/gctx"
	"github.com/gogf/gf/v2/util/gconv"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"randomproxy/gomitmproxy"
	"randomproxy/gomitmproxy/mitm"
)

var (
	DNSCache = gcache.New()
)

func main() {
	ctx := gctx.New()
	certConfig := g.Cfg().MustGetWithEnv(ctx, "CERT").Map()
	if len(certConfig) == 0 {
		log.Fatal("no cert config")
	}
	cert := gconv.String(certConfig["cert"])
	key := gconv.String(certConfig["key"])
	tlsCert, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		log.Fatal(err)
	}
	privateKey := tlsCert.PrivateKey.(*rsa.PrivateKey)

	x509c, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		log.Fatal(err)
	}

	mitmConfig, err := mitm.NewConfig(x509c, privateKey, nil)
	if err != nil {
		log.Fatal(err)
	}

	mitmConfig.SetValidity(time.Hour * 24 * 7) // generate certs valid for 7 days
	mitmConfig.SetOrganization("gomitmproxy")  // cert organization
	port := g.Cfg().MustGetWithEnv(ctx, "PORT").Int()
	proxy := gomitmproxy.NewProxy(gomitmproxy.Config{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				g.Log().Error(ctx, err.Error())
				return nil, err
			}
			_, isipv6, err := getIPAddress(ctx, host)
			if err != nil {
				g.Log().Error(ctx, err.Error())
				return nil, err
			}
			var IPS []interface{}
			if isipv6 {
				// g.Log().Debug(ctx, "serverIP", serverIP)
				IPS = g.Cfg().MustGet(ctx, "IP6S").Slice()
			} else {
				// g.Log().Debug(ctx, "serverIP", serverIP)
				IPS = g.Cfg().MustGet(ctx, "IPS").Slice()
			}
			if len(IPS) == 0 {
				IPS = g.Cfg().MustGet(ctx, "IPS").Slice()
			}

			IPA := garray.NewArrayFrom(IPS)
			IP, found := IPA.Rand()
			if !found {
				g.Log().Error(ctx, "no ip found")
				return nil, err
			}
			ip := gconv.String(IP)
			ipv6sub := g.Cfg().MustGet(ctx, "IP6SUB").String()
			if isipv6 && ipv6sub != "" {
				tempIP, _ := randomIPV6FromSubnet(ipv6sub)
				ip = tempIP.String()
			}
			g.Log().Debug(ctx, "ip", ip, "isipv6", isipv6, "ipv6sub", ipv6sub)
			dialer := &net.Dialer{
				LocalAddr: &net.TCPAddr{IP: net.ParseIP(ip)},
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}
			return dialer.DialContext(ctx, network, addr)
		},
		OnConnect: func(session *gomitmproxy.Session, proto string, addr string) (conn net.Conn) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				g.Log().Error(ctx, err.Error())
				return nil
			}
			_, isipv6, err := getIPAddress(ctx, host)
			if err != nil {
				g.Log().Error(ctx, err.Error())
				return
			}
			var IPS []interface{}
			if isipv6 {
				// g.Log().Debug(ctx, "serverIP", serverIP)
				IPS = g.Cfg().MustGet(ctx, "IP6S").Slice()
			} else {
				// g.Log().Debug(ctx, "serverIP", serverIP)
				IPS = g.Cfg().MustGet(ctx, "IPS").Slice()
			}
			if len(IPS) == 0 {
				IPS = g.Cfg().MustGet(ctx, "IPS").Slice()
			}

			IPA := garray.NewArrayFrom(IPS)
			IP, found := IPA.Rand()
			if !found {
				g.Log().Error(ctx, "no ip found")
				return
			}
			ip := gconv.String(IP)
			ipv6sub := g.Cfg().MustGet(ctx, "IP6SUB").String()
			if isipv6 && ipv6sub != "" {
				tempIP, _ := randomIPV6FromSubnet(ipv6sub)
				ip = tempIP.String()
			}
			g.Log().Debug(ctx, "ip", ip, "isipv6", isipv6, "ipv6sub", ipv6sub)
			dialer := &net.Dialer{
				LocalAddr: &net.TCPAddr{IP: net.ParseIP(ip)},
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}
			conn, err = dialer.Dial(proto, addr)
			if err != nil {
				g.Log().Error(ctx, err.Error())
				return nil
			}
			return conn
		},
		ListenAddr: &net.TCPAddr{
			IP:   net.IPv4(0, 0, 0, 0),
			Port: port,
		},
		MITMConfig: mitmConfig,
	})
	err = proxy.Start()
	if err != nil {
		log.Fatal(err)
	}

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	<-signalChannel

	// Clean up
	proxy.Close()
}

func randomIPV6FromSubnet(network string) (net.IP, error) {
	_, subnet, err := net.ParseCIDR(network)
	if err != nil {
		return nil, err
	}
	// 获取子网掩码位长度
	ones, _ := subnet.Mask.Size()
	// Get the prefix of the subnet.
	prefix := subnet.IP.To16()

	var perfixBits []gbinary.Bit
	// 将perfix转换为 0 1 字节切片
	for i := 0; i < len(prefix); i++ {
		prefixBytes := byte(prefix[i])
		bytesArray := []byte{prefixBytes}
		bits := gbinary.DecodeBytesToBits(bytesArray)
		// g.Dump(bits)
		perfixBits = append(perfixBits, bits...)
	}
	// g.Dump(perfixBits)
	// 将子网掩码位长度的后面的位数设置为随机数
	for i := ones; i < len(perfixBits); i++ {
		perfixBits[i] = gbinary.Bit(rand.Intn(2))
	}

	perfixBytes := gbinary.EncodeBitsToBytes(perfixBits)
	ipnew := net.IP(perfixBytes)

	return ipnew, nil
}

func getIPAddress(ctx g.Ctx, domain string) (ip string, ipv6 bool, err error) {
	var ipAddresses []string
	// 先从缓存中获取
	if v := DNSCache.MustGet(ctx, domain).Strings(); len(v) > 0 {
		ipAddresses = v
	} else {
		ipAddresses, err = net.LookupHost(domain)
		if err != nil {
			return "", false, err
		}
		DNSCache.Set(ctx, domain, ipAddresses, 5*time.Minute)
	}
	for _, ipAddress := range ipAddresses {
		// 如果是地址包含 : 说明是IPV6地址
		if strings.Contains(ipAddress, ":") {
			return ipAddress, true, nil
		}
	}
	return ipAddresses[0], false, nil
}
