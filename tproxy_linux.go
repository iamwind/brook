// Copyright (c) 2016-present Cloud <cloud@txthinking.com>
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of version 3 of the GNU General Public
// License as published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package brook

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	cache "github.com/patrickmn/go-cache"
	"github.com/txthinking/brook/limits"
	"github.com/txthinking/brook/tproxy"
	"github.com/txthinking/socks5"
)

// Tproxy.
type Tproxy struct {
	TCPAddr       *net.TCPAddr
	UDPAddr       *net.UDPAddr
	RemoteTCPAddr *net.TCPAddr
	RemoteUDPAddr *net.UDPAddr
	Password      []byte
	TCPListen     *net.TCPListener
	UDPConn       *net.UDPConn
	Cache         *cache.Cache
	TCPDeadline   int
	TCPTimeout    int
	UDPDeadline   int
}

// NewTproxy.
func NewTproxy(addr, remote, password string, tcpTimeout, tcpDeadline, udpDeadline int) (*Tproxy, error) {
	taddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	uaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	rtaddr, err := net.ResolveTCPAddr("tcp", remote)
	if err != nil {
		return nil, err
	}
	ruaddr, err := net.ResolveUDPAddr("udp", remote)
	if err != nil {
		return nil, err
	}
	cs := cache.New(cache.NoExpiration, cache.NoExpiration)
	if err := limits.Raise(); err != nil {
		log.Println("Try to raise system limits, got", err)
	}
	s := &Tproxy{
		Password:      []byte(password),
		TCPAddr:       taddr,
		UDPAddr:       uaddr,
		RemoteTCPAddr: rtaddr,
		RemoteUDPAddr: ruaddr,
		Cache:         cs,
		TCPTimeout:    tcpTimeout,
		TCPDeadline:   tcpDeadline,
		UDPDeadline:   udpDeadline,
	}
	return s, nil
}

func (s *Tproxy) RunAutoScripts() error {
	hc := &http.Client{
		Timeout: 9 * time.Second,
	}
	r, err := hc.Get("https://blackwhite.txthinking.com/white_cidr.list")
	if err != nil {
		return err
	}
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	r.Body.Close()
	data = bytes.TrimSpace(data)
	data = bytes.Replace(data, []byte{0x20}, []byte{}, -1)
	data = bytes.Replace(data, []byte{0x0d, 0x0a}, []byte{0x0a}, -1)
	cidrl := strings.Split(string(data), "\n")

	c := exec.Command("sh", "-c", "ip rule add fwmark 1 lookup 100")
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	c = exec.Command("sh", "-c", "ip route add local 0.0.0.0/0 dev lo table 100")
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	c = exec.Command("sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward")
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	c = exec.Command("sh", "-c", "echo 1 > /proc/sys/net/ipv6/conf/all/forwarding")
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	c = exec.Command("sh", "-c", "modprobe xt_socket")
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	c = exec.Command("sh", "-c", "modprobe xt_TPROXY")
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	c = exec.Command("sh", "-c", "iptables -t mangle -A PREROUTING -d 0.0.0.0/8 -j RETURN")
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	c = exec.Command("sh", "-c", "iptables -t mangle -A PREROUTING -d 10.0.0.0/8 -j RETURN")
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	c = exec.Command("sh", "-c", "iptables -t mangle -A PREROUTING -d 127.0.0.0/8 -j RETURN")
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	c = exec.Command("sh", "-c", "iptables -t mangle -A PREROUTING -d 169.254.0.0/16 -j RETURN")
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	c = exec.Command("sh", "-c", "iptables -t mangle -A PREROUTING -d 172.16.0.0/12 -j RETURN")
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	c = exec.Command("sh", "-c", "iptables -t mangle -A PREROUTING -d 192.168.0.0/16 -j RETURN")
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	c = exec.Command("sh", "-c", "iptables -t mangle -A PREROUTING -d 224.0.0.0/4 -j RETURN")
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	c = exec.Command("sh", "-c", "iptables -t mangle -A PREROUTING -d 240.0.0.0/4 -j RETURN")
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	for _, v := range cidrl {
		c = exec.Command("sh", "-c", "iptables -t mangle -A PREROUTING -d "+v+" -j RETURN")
		if out, err := c.CombinedOutput(); err != nil {
			return errors.New(string(out) + err.Error())
		}
	}
	c = exec.Command("sh", "-c", "iptables -t mangle -A PREROUTING -d "+s.RemoteTCPAddr.IP.String()+" -j RETURN")
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	c = exec.Command("sh", "-c", "iptables -t mangle -A PREROUTING -p tcp -m socket -j MARK --set-mark 1")
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	c = exec.Command("sh", "-c", "iptables -t mangle -A PREROUTING -p tcp -j TPROXY --tproxy-mark 0x1/0x1 --on-port "+strconv.Itoa(s.TCPAddr.Port))
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	c = exec.Command("sh", "-c", "iptables -t mangle -A PREROUTING -p udp -m socket -j MARK --set-mark 1")
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	c = exec.Command("sh", "-c", "iptables -t mangle -A PREROUTING -p udp -j TPROXY --tproxy-mark 0x1/0x1 --on-port "+strconv.Itoa(s.TCPAddr.Port))
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	return nil
}

func (s *Tproxy) ClearAutoScripts() error {
	c := exec.Command("sh", "-c", "ip rule del fwmark 1 lookup 100")
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	c = exec.Command("sh", "-c", "ip route del local 0.0.0.0/0 dev lo table 100")
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	c = exec.Command("sh", "-c", "iptables -t mangle -F")
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	c = exec.Command("sh", "-c", "iptables -t mangle -X")
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	return nil
}

// Run server.
func (s *Tproxy) ListenAndServe() error {
	errch := make(chan error)
	go func() {
		errch <- s.RunTCPServer()
	}()
	go func() {
		errch <- s.RunUDPServer()
	}()
	return <-errch
}

// RunTCPServer starts tcp server.
func (s *Tproxy) RunTCPServer() error {
	var err error
	s.TCPListen, err = tproxy.ListenTCP("tcp", s.TCPAddr)
	if err != nil {
		return err
	}
	defer s.TCPListen.Close()
	for {
		c, err := s.TCPListen.AcceptTCP()
		if err != nil {
			return err
		}

		addr, err := getTCPOriginalDstAddr(c)
		if err != nil {
			return err
		}
		
		fmt.Println(addr.String())
		
		go func(c *net.TCPConn) {
			defer c.Close()
			if s.TCPTimeout != 0 {
				if err := c.SetKeepAlivePeriod(time.Duration(s.TCPTimeout) * time.Second); err != nil {
					log.Println(err)
					return
				}
			}
			if s.TCPDeadline != 0 {
				if err := c.SetDeadline(time.Now().Add(time.Duration(s.TCPDeadline) * time.Second)); err != nil {
					log.Println(err)
					return
				}
			}
			if err := s.TCPHandle(c); err != nil {
				log.Println(err)
			}
		}(c)
	}
	return nil
}

// RunUDPServer starts udp server.
func (s *Tproxy) RunUDPServer() error {
	var err error
	s.UDPConn, err = tproxy.ListenUDP("udp", s.UDPAddr)
	if err != nil {
		return err
	}
	defer s.UDPConn.Close()
	for {
		b := make([]byte, 65535)
		n, saddr, daddr, err := tproxy.ReadFromUDP(s.UDPConn, b)
		if err != nil {
			fmt.Printf("RunUDPServer err:%v\n", err)
			return err
		}
		fmt.Printf("RunUDPServer %s->%s n=%v data:%v\n", saddr.String(), daddr.String(), n, b[0:n])
		if n == 0 {
			continue
		}
		go func(saddr, daddr *net.UDPAddr, b []byte) {			
			if err := s.UDPHandle(saddr, daddr, b); err != nil {
				log.Println(err)
				return
			}
		}(saddr, daddr, b[0:n])
	}
	return nil
}

// Shutdown server.
func (s *Tproxy) Shutdown() error {
	var err, err1 error
	if s.TCPListen != nil {
		err = s.TCPListen.Close()
	}
	if s.UDPConn != nil {
		err1 = s.UDPConn.Close()
	}
	if err != nil {
		return err
	}
	return err1
}

func getConntrackIPv6TCPOriginalDstAddr(localAddr string, remoteAddr string)(destAddrString string, err error){
	localhost, localport, _ := net.SplitHostPort(localAddr)
	remotehost, remoteport, _ := net.SplitHostPort(remoteAddr)
	//syslogger.Write([]byte(fmt.Sprintf("from %s:%v -> %s:%v", remotehost, remoteport, localhost, localport)))
	cmdString := fmt.Sprintf(fmt.Sprintf("conntrack -f ipv6 -q %s -r %s -p tcp --reply-port-dst %s --reply-port-src %s -L|awk '{print $6\"=\"$8}'|awk -F \"=\" '{print \"[\"$2\"]:\"$4}'",
		remotehost, localhost, remoteport, localport))
	//syslogger.Write([]byte(fmt.Sprintf("IPv6 cmdString: %s", cmdString)))		
	out, err := exec.Command("bash", "-c", cmdString).Output()
	if err != nil {
		fmt.Printf("getConntrackIPv6TCPOriginalDstAddr conntrack error: %v", err)
		return
	}
	//syslogger.Write([]byte(fmt.Sprintf("IPv6 OriginDstAddr: %s", string(out))))
			
	destAddrString = strings.Replace(string(out), "\n", "", -1)

	return
}

func getTCPOriginalDstAddr(conn *net.TCPConn) (addr net.Addr, err error) {

	fc, err := conn.File()
	if err != nil {
		//log.Logf("copy to file error")
		fmt.Printf("getTCPOriginalDstAddr() copy to file error")
		return
	} 

	//SO_ORIGINAL_DST=80
	//struct sockaddr_in {
	//	__kernel_sa_family_t  sin_family;     /* Address family               */
	//	__be16                sin_port;       /* Port number                  */
  	//	struct in_addr        sin_addr;       /* Internet address             */
  	//	/* Pad to size of `struct sockaddr'. */
	//	unsigned char         __pad[__SOCK_SIZE__ - sizeof(short int) -
    //                    sizeof(unsigned short int) - sizeof(struct in_addr)];
	//};
	//syscall.GetsockoptIPv6Mreq only support IPv4
	mreq, err := syscall.GetsockoptIPv6Mreq(int(fc.Fd()), syscall.IPPROTO_IP, 80)
	if err != nil {
		localAddr := conn.LocalAddr().String()
		remoteAddr := conn.RemoteAddr().String()
		destAddr, err1 := getConntrackIPv6TCPOriginalDstAddr(localAddr, remoteAddr)
		if err1 != nil {
			err = err1
			fmt.Printf("get IPv6 tcp conntrack destAddr error: %v", err)
			return 
		}
		addr, err = net.ResolveTCPAddr("tcp6", destAddr)
		if err != nil {
			fmt.Printf("IPv6 tcp error: %v", err)
			return
		}		
	} else {
		ip := net.IPv4(mreq.Multiaddr[4], mreq.Multiaddr[5], mreq.Multiaddr[6], mreq.Multiaddr[7])
		port := uint16(mreq.Multiaddr[2])<<8 + uint16(mreq.Multiaddr[3])
		addr, err = net.ResolveTCPAddr("tcp4", fmt.Sprintf("%s:%d", ip.String(), port))
		if err != nil {
			fmt.Printf("IPv4 tcp error: %v", err)
			return
		}
	}

	return
}

// TCPHandle handles request.
func (s *Tproxy) TCPHandle(c *net.TCPConn) error {
	tmp, err := tproxy.DialTCP("tcp", s.RemoteTCPAddr.String())
	if err != nil {
		return err
	}
	rc := tmp.(*net.TCPConn)
	defer rc.Close()
	if s.TCPTimeout != 0 {
		if err := rc.SetKeepAlivePeriod(time.Duration(s.TCPTimeout) * time.Second); err != nil {
			return err
		}
	}
	if s.TCPDeadline != 0 {
		if err := rc.SetDeadline(time.Now().Add(time.Duration(s.TCPDeadline) * time.Second)); err != nil {
			return err
		}
	}

	k, n, err := PrepareKey(s.Password)
	if err != nil {
		return err
	}
	if _, err := rc.Write(n); err != nil {
		return err
	}

	addr, err := getTCPOriginalDstAddr(c)
	if err != nil {
		return err
	}
	
	fmt.Printf(addr.String())
	a, address, port, err := socks5.ParseAddress(addr.String())
	if err != nil {
		return err
	}
	ra := make([]byte, 0, 7)
	ra = append(ra, a)
	ra = append(ra, address...)
	ra = append(ra, port...)
	n, _, err = WriteTo(rc, ra, k, n, true)
	if err != nil {
		return err
	}

	go func() {
		n := make([]byte, 12)
		if _, err := io.ReadFull(rc, n); err != nil {
			return
		}
		k, err := GetKey(s.Password, n)
		if err != nil {
			log.Println(err)
			return
		}
		var b []byte
		for {
			if s.TCPDeadline != 0 {
				if err := rc.SetDeadline(time.Now().Add(time.Duration(s.TCPDeadline) * time.Second)); err != nil {
					return
				}
			}
			b, n, err = ReadFrom(rc, k, n, false)
			if err != nil {
				return
			}
			if _, err := c.Write(b); err != nil {
				return
			}
		}
	}()

	var b [1024 * 2]byte
	for {
		if s.TCPDeadline != 0 {
			if err := c.SetDeadline(time.Now().Add(time.Duration(s.TCPDeadline) * time.Second)); err != nil {
				return nil
			}
		}
		i, err := c.Read(b[:])
		if err != nil {
			return nil
		}
		n, _, err = WriteTo(rc, b[0:i], k, n, false)
		if err != nil {
			return nil
		}
	}
	return nil
}

type TproxyUDPExchange struct {
	RemoteConn *net.UDPConn
	LocalConn  *net.UDPConn
}

func (s *Tproxy) UDPHandle(addr, daddr *net.UDPAddr, b []byte) error {
	fmt.Printf("UDPHandle addr=%s daddr=%s\n", addr.String(), daddr.String())
	a, address, port, err := socks5.ParseAddress(daddr.String())
	if err != nil {
		return err
	}
	ra := make([]byte, 0, 7)
	ra = append(ra, a)
	ra = append(ra, address...)
	ra = append(ra, port...)
	b = append(ra, b...)

	send := func(ue *TproxyUDPExchange, data []byte) error {
		cd, err := Encrypt(s.Password, data)
		if err != nil {
			return err
		}
		_, err = ue.RemoteConn.Write(cd)
		if err != nil {
			return err
		}
		return nil
	}

	var ue *TproxyUDPExchange
	iue, ok := s.Cache.Get(addr.String())
	if ok {
		ue = iue.(*TproxyUDPExchange)
		return send(ue, b)
	}

	rc, err := tproxy.DialUDP("udp", &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: 0,
	}, s.RemoteUDPAddr)
	if err != nil {
		return err
	}

	//var laddr *net.UDPAddr
	//laddr = &net.UDPAddr{
	//	IP:   net.ParseIP("172.31.255.254"),
	//	Port: 1080,
	//}
	//c, err := tproxy.DialUDP("udp", laddr, addr)
	//if err != nil {
	//	rc.Close()
	//	return errors.New(fmt.Sprintf("UDPHandle src: %s dst: %s %s", laddr.String(), addr.String(), err.Error()))
	//}
	ue = &TproxyUDPExchange{
		RemoteConn: rc,
		//LocalConn:  c,
	}
	if err := send(ue, b); err != nil {
		ue.RemoteConn.Close()
		//ue.LocalConn.Close()
		return err
	}
	s.Cache.Set(addr.String(), ue, cache.DefaultExpiration)
	go func(ue *TproxyUDPExchange) {
		defer func() {
			s.Cache.Delete(addr.String())
			ue.RemoteConn.Close()
			//ue.LocalConn.Close()
		}()
		var b [65535]byte
		for {
			if s.UDPDeadline != 0 {
				if err := ue.RemoteConn.SetDeadline(time.Now().Add(time.Duration(s.UDPDeadline) * time.Second)); err != nil {
					break
				}
			}
			n, err := ue.RemoteConn.Read(b[:])
			if err != nil {
				break
			}
			_, newaddr, newport, data, err := Decrypt(s.Password, b[0:n])
			if err != nil {
				break
			}
			
			var saddr *net.UDPAddr
			saddr = &net.UDPAddr{
				IP: net.IP{newaddr[0], newaddr[1], newaddr[2], newaddr[3]},
				Port: int(newport[0])<<8 + int(newport[1]),
			}
			
			fmt.Printf("UDPHandle send to %s get from %s data:%v\n", daddr, saddr, data)
			//fmt.Printf("UDPHandle ue.LocalConn=%s->%s data:%v\n", ue.LocalConn.LocalAddr().String(), ue.LocalConn.RemoteAddr().String(), data)
			//if _, err := ue.LocalConn.Write(data); err != nil {
			//	break
			//}
			if daddr.String() == saddr.String() {
				_, err = s.UDPConn.WriteToUDP(data, addr)
				if err != nil {
					fmt.Printf("UDPHandle return %s err:%v\n", addr.String(), err)
					return
				}
			} else {				
				c, err := tproxy.DialUDP("udp", saddr, addr)
				if err != nil {					
					fmt.Printf("UDPHandle DialUDP src: %s dst: %s err:%s\n", saddr.String(), addr.String(), err.Error())
					return
				}
				_, err = c.Write(data)
				if err != nil {
					fmt.Printf("UDPHandle Write src: %s dst: %s err:%s\n", saddr.String(), addr.String(), err.Error())
					return
				}
				c.Close()
			}
			fmt.Printf("UDPHandle return %s data:%v\n", addr.String(), data)
		}
	}(ue)
	return nil
}
