package netip

import (
	"errors"
	"math/big"
	"net"
)

// IPAddress is used to manipulate, convert and compare IPv4 or IPv6 addresses.
type IPAddress struct {
	net.IP
	CIDR int
}

type AddrCompareOperator int

const (
	LT AddrCompareOperator = iota
	LE
	GT
	GE
	NE
	EQ
)

type AddrCompareType int

const (
	Strict AddrCompareType = iota
	Value
)

type IPAddressType int

const (
	IPAddressIPv4 IPAddressType = iota
	IPAddressIPv6
)

const (
	IPV4_HOST_CIDR = 32
	IPV6_HOST_CIDR = 128
)

// Set the IP address from a.b.c.d byte notation
func (addr *IPAddress) SetIPv4(a byte, b byte, c byte, d byte) {
	addr.IP = net.IPv4(a, b, c, d)
	addr.CIDR = IPV4_HOST_CIDR
}

// Set the IP address from a.b.c.d byte notation + cidr
func (addr *IPAddress) SetIPv4WithCIDR(a, b, c, d byte, cidr int) {
	addr.IP = net.IPv4(a, b, c, d)
	addr.CIDR = cidr
}

// Set the IPv4 address from integer type
func (addr *IPAddress) IPv4FromInt(intAddress uint32) {
	addr.SetIPv4(byte((intAddress>>24)&0xFF), byte((intAddress>>16)&0xFF), byte((intAddress>>8)&0xFF), byte(intAddress&0xFF))
	addr.CIDR = IPV4_HOST_CIDR
}

// Set the IPv6 address from big integer
func (addr *IPAddress) IPv6FromInt(newInt *big.Int) error {
	if newInt.BitLen() > IPV6_HOST_CIDR {
		return errors.New("Exceeds 128 bits")
	}

	intBytes := newInt.Bytes()

	if len(intBytes) < 16 {
		intBytes = append(make([]byte, 16-len(intBytes)), intBytes...)
	}

	addr.IP = intBytes
	addr.CIDR = IPV6_HOST_CIDR

	return nil
}

// Set the IP address from string type
func (addr *IPAddress) FromString(ipAddress string) error {
	ipAddr, ipNet, err := net.ParseCIDR(ipAddress)

	if err != nil {
		ipAddr = net.ParseIP(ipAddress)
		if ipAddr == nil {
			return errors.New("Invalid address string")
		}

		addr.IP = ipAddr
		if addr.IsIPv4() == true {
			addr.CIDR = IPV4_HOST_CIDR
		} else {
			addr.CIDR = IPV6_HOST_CIDR
		}
	} else {
		cidrVal, _ := ipNet.Mask.Size()
		if cidrVal <= 0 {
			return errors.New("Invalid address string")
		}
		addr.IP = ipAddr
		addr.CIDR = cidrVal
	}

	return nil
}

// Returns true when address is an IPv4 address
func (addr *IPAddress) IsIPv4() bool {
	if addr.To4() != nil {
		return true
	}

	return false
}

// Returns true when address is strictly IPv6 address
func (addr *IPAddress) IsIPv6() bool {
	if len(addr.To4()) == 0 && len(addr.To16()) == net.IPv6len {
		return true
	}

	return false
}

func (addr *IPAddress) IsValidIPv4Subnet() bool {
	if addr.IsIPv4() == false {
		return false
	}

	addr.IP = addr.To4()
	netMask := net.CIDRMask(addr.CIDR, 32)
	if netMask == nil {
		return false
	}

	for i := 0; i < len(addr.IP); i++ {
		if addr.IP[i]&(^netMask[i]) != 0 {
			return false
		}
	}

	return true
}

// Check whether an address is IPv4 or IPv6.
func (addr *IPAddress) Type() IPAddressType {
	if addr.IsIPv6() == true {
		return IPAddressIPv6
	} else {
		return IPAddressIPv4
	}
}

// Compares IPv4 or IPv6 addresses according to the AddrCompareOperator operator
// If AddrCompareType equals Value we only compare address
// If AddrCompareType equals Strict we compare address + CIDR and type
func (addr *IPAddress) Compare(rhs IPAddress, compOps AddrCompareOperator, compMode AddrCompareType) bool {
	lhsTop := new(IPAddress)
	rhsTop := new(IPAddress)

	if (len(addr.IP) != len(rhs.IP)) && compMode == Strict {
		if compOps == NE {
			return true
		} else {
			return false
		}
	}

	if compMode == Strict { // Strict includes the CIDR in compare
		lhsTop = addr.End()
		rhsTop = rhs.End()
	} else {
		if len(addr.IP) == 0 {
			lhsTop = nil
		} else {
			lhsTop.IP = make(net.IP, len(addr.IP))
			copy(lhsTop.IP, addr.IP)
		}

		if len(rhs.IP) == 0 {
			rhsTop = nil
		} else {
			rhsTop.IP = make(net.IP, len(rhs.IP))
			copy(rhsTop.IP, rhs.IP)
		}
	}

	result := 0
	if lhsTop == nil && rhsTop != nil {
		result = -1
	} else if lhsTop != nil && rhsTop == nil {
		result = 1
	} else if lhsTop == nil && rhsTop == nil {
		result = 0
	} else {
		if len(rhsTop.IP) != len(lhsTop.IP) {
			if compOps == NE {
				return true
			} else {
				return false
			}
		}

		for i := 0; i < len(rhsTop.IP); i++ {
			if lhsTop.IP[i] < rhsTop.IP[i] {
				result = -1
				break
			} else if lhsTop.IP[i] > rhsTop.IP[i] {
				result = 1
				break
			}
		}
	}

	switch compOps {
	case LE:
		return result == -1 || result == 0
	case LT:
		return result == -1
	case GE:
		return result == 1 || result == 0
	case GT:
		return result == 1
	case EQ:
		return result == 0
	case NE:
		return result == -1 || result == 1
	default:
		return false
	}

	return false
}

// Check if current address is less than or equal to rhs address
// Compare is either Strict (Addr+Cidr+Type) or Value only
func (addr *IPAddress) LE(rhs IPAddress, compMode AddrCompareType) bool {
	return addr.Compare(rhs, LE, compMode)
}

// Check if current address is less than rhs address
func (addr *IPAddress) LT(rhs IPAddress, compMode AddrCompareType) bool {
	return addr.Compare(rhs, LT, compMode)
}

// Check if current address is greater than rhs address
func (addr *IPAddress) GT(rhs IPAddress, compMode AddrCompareType) bool {
	return addr.Compare(rhs, GT, compMode)
}

// Check if current address is greater than or equal to rhs address
func (addr *IPAddress) GE(rhs IPAddress, compMode AddrCompareType) bool {
	return addr.Compare(rhs, GE, compMode)
}

// Check if current ip address is equal to rhs address
func (addr *IPAddress) EQ(rhs IPAddress, compMode AddrCompareType) bool {
	return addr.Compare(rhs, EQ, compMode)
}

// Check if current IP address is not equal to rhs address
func (addr *IPAddress) NE(rhs IPAddress, compMode AddrCompareType) bool {
	return addr.Compare(rhs, NE, compMode)
}

// Convert the IPv4 address to an integer
func (addr *IPAddress) IPv4ToInt() (uint32, error) {
	if addr.IsIPv4() == true {
		i := 15
		if len(addr.IP) == net.IPv4len {
			i = 3
		}

		result := uint32(addr.IP[i]) + uint32(addr.IP[i-1])<<8 + uint32(addr.IP[i-2])<<16 + uint32(addr.IP[i-3])<<24
		return result, nil

	} else {
		return 0, errors.New("Not IPv4")
	}
}

// Convert IPv6 address to big.Int
func (addr *IPAddress) IPv6ToInt() (*big.Int, error) {
	if addr.IsIPv6() == true {
		ipInt := new(big.Int)
		ipInt.SetBytes(addr.IP)
		return ipInt, nil
	} else {
		return nil, errors.New("Not IPv6")
	}
}

// Bitwise AND between IP address and CIDR results in the network address
func (addr *IPAddress) ToNetworkAddress() *IPAddress {
	return addr.Start()
}

// Bitwise OR between network address and inverted CIDR results in broadcast address for IPv6 addresses
func (addr *IPAddress) ToBroadcastAddress() *IPAddress {
	if addr.IsIPv4() == false {
		return nil
	}

	return addr.End()
}

// End() returns the highest address in the IP + CIDR
func (addr *IPAddress) End() *IPAddress {
	var endAddr IPAddress
	var maskSize int

	if addr.IsIPv4() == true {
		endAddr.IP = make(net.IP, net.IPv4len)
		copy(endAddr.IP, addr.To4())
		endAddr.CIDR = IPV4_HOST_CIDR
		maskSize = 4
	} else if addr.IsIPv6() == true {
		maskSize = 16
		endAddr.IP = make(net.IP, len(addr.IP))
		copy(endAddr.IP, addr.IP)
		endAddr.CIDR = IPV6_HOST_CIDR
	} else {
		return nil
	}

	if addr.CIDR > 8*maskSize {
		return nil
	}

	mask := net.CIDRMask(addr.CIDR, 8*maskSize)

	for i := 0; i < maskSize; i++ {
		endAddr.IP[i] = endAddr.IP[i] | (mask[i] ^ 0xff)
	}

	return &endAddr
}

// Return the lowest IP address in the range
func (addr *IPAddress) Start() *IPAddress {
	var netAddr IPAddress
	var maskSize int

	if addr.IsIPv4() == true {
		netAddr.IP = make(net.IP, net.IPv4len)
		copy(netAddr.IP, addr.To4())
		netAddr.CIDR = IPV4_HOST_CIDR
		maskSize = 4
	} else if addr.IsIPv6() == true {
		maskSize = 16
		netAddr.IP = make(net.IP, len(addr.IP))
		copy(netAddr.IP, addr.IP)
		netAddr.CIDR = IPV6_HOST_CIDR
	} else {
		return nil
	}

	if addr.CIDR > 8*maskSize {
		return nil
	}

	netMask := net.CIDRMask(addr.CIDR, 8*maskSize)

	for i := 0; i < maskSize; i++ {
		netAddr.IP[i] = netAddr.IP[i] & netMask[i]
	}

	return &netAddr
}

func (addr *IPAddress) XOR(rhs IPAddress) *IPAddress {
	if addr.Type() != rhs.Type() {
		return nil
	}

	if addr.IsIPv4() == true && rhs.IsIPv4() == true {
		addr.IP = addr.To4()
		rhs.IP = rhs.To4()
	}

	for i := 0; i < len(addr.IP); i++ {
		addr.IP[i] = addr.IP[i] ^ rhs.IP[i]
	}

	return addr
}

func (addr *IPAddress) AND(rhs IPAddress) *IPAddress {
	if addr.Type() != rhs.Type() {
		return nil
	}

	if addr.IsIPv4() == true && rhs.IsIPv4() == true {
		addr.IP = addr.To4()
		rhs.IP = rhs.To4()
	}

	for i := 0; i < len(addr.IP); i++ {
		addr.IP[i] = addr.IP[i] & rhs.IP[i]
	}

	return addr
}

func (addr *IPAddress) OR(rhs IPAddress) *IPAddress {
	if addr.Type() != rhs.Type() {
		return nil
	}

	if addr.IsIPv4() == true && rhs.IsIPv4() == true {
		addr.IP = addr.To4()
		rhs.IP = rhs.To4()
	}

	for i := 0; i < len(addr.IP); i++ {
		addr.IP[i] = addr.IP[i] | rhs.IP[i]
	}

	return addr
}

func (addr *IPAddress) NOT() *IPAddress {
	if addr.IsIPv4() {
		addr.IP = addr.To4()
	}

	for i := 0; i < len(addr.IP); i++ {
		addr.IP[i] = addr.IP[i] ^ 0xff
	}

	return addr
}

// CIDRToMask converts the address CIDR to a.b.c.d mask (net.IPMask is []byte)
func (addr *IPAddress) CIDRToMask() *IPAddress {
	maskAddr := IPAddress{}
	var maskSize int

	if addr.Type() == IPAddressIPv4 {
		maskSize = net.IPv4len
		maskAddr.CIDR = IPV4_HOST_CIDR
	} else if addr.Type() == IPAddressIPv6 {
		maskSize = net.IPv6len
		maskAddr.CIDR = IPV6_HOST_CIDR
	} else {
		return nil
	}

	if addr.CIDR > 8*maskSize {
		return nil
	}

	mask := net.CIDRMask(addr.CIDR, 8*maskSize)
	maskAddr.IP = make(net.IP, len(mask))
	copy(maskAddr.IP, mask)
	return &maskAddr
}

// CIDRFromMask converts IP portion as a.b.c.d... mask to CIDR notation
func (addr *IPAddress) CIDRFromMask(ipMask IPAddress) (int, error) {
	mask := make(net.IPMask, len(ipMask.IP))
	copy(mask, ipMask.IP)

	ones, l := mask.Size()

	if l == 8*net.IPv4len && addr.Type() == IPAddressIPv4 {
		addr.CIDR = ones
	} else if l == 8*net.IPv6len && addr.Type() == IPAddressIPv6 {
		addr.CIDR = ones
	} else {
		return 0, errors.New("Incorrect mask length")
	}

	return ones, nil
}

// Add integer to IP address
func (addr *IPAddress) Add(value int) error {
	if addr.IsIPv4() == true {
		if val, err := addr.IPv4ToInt(); err == nil {
			addr.IPv4FromInt(uint32(value) + val)
			return nil
		}
	} else if addr.IsIPv6() == true {
		if val, err := addr.IPv6ToInt(); err == nil {
			result := val.Add(val, big.NewInt(int64(value)))
			return addr.IPv6FromInt(result)
		}
	}

	return errors.New("Invalid type error")
}

// Subtract integer from IP address
func (addr *IPAddress) Subtract(value int) error {
	if addr.IsIPv4() == true {
		if val, err := addr.IPv4ToInt(); err == nil {
			addr.IPv4FromInt(uint32(value) - val)
			return nil
		}
	} else if addr.IsIPv6() == true {
		if val, err := addr.IPv6ToInt(); err == nil {
			result := val.Sub(val, big.NewInt(int64(value)))
			return addr.IPv6FromInt(result)
		}
	}

	return errors.New("Invalid type")
}

// Within reports whether the IP range is strict/equal within another IP range
func (addr *IPAddress) Within(rhs IPAddress, comparetype AddrCompareType) bool {
	lhsEnd := addr.End()
	lhsStart := addr.Start()
	rhsEnd := rhs.End()
	rhsStart := rhs.Start()

	if lhsEnd == nil || rhsEnd == nil || rhsStart == nil || lhsStart == nil {
		return false
	}

	isEqual := lhsStart.GE(*rhsStart, Value) && lhsEnd.LE(*rhsEnd, Value)
	isStrict := lhsStart.GT(*rhsStart, Value) && lhsEnd.LT(*rhsEnd, Value)

	if comparetype == Value {
		return isEqual
	} else {
		return isStrict
	}
}

// Contains reports whether the IP range contains another IP range either strictly/equally
func (addr *IPAddress) Contains(rhs IPAddress, compareType AddrCompareType) bool {
	lhsEnd := addr.End()
	lhsStart := addr.Start()
	rhsEnd := rhs.End()
	rhsStart := rhs.Start()

	if lhsEnd == nil || rhsEnd == nil || lhsStart == nil || rhsStart == nil {
		return false
	}

	isEqual := lhsStart.LE(*rhsStart, Value) && lhsEnd.GE(*rhsEnd, Value)
	isStrict := lhsStart.LT(*rhsStart, Value) && lhsEnd.GT(*rhsEnd, Value)

	if compareType == Value {
		return isEqual
	} else {
		return isStrict
	}
}
