package ipaddr

import (
	"errors"
	"fmt"
	"math/big"
	"net"
)

type IPAddress struct {
	net.IP
	CIDR int
}

// CompareOperator specifies supported compare operators
type CompareOperator int

const (
	LT CompareOperator = iota
	LE
	GT
	GE
	NE
	EQ
)

// CompareMode specifies whether CIDR value
// is included in address comparison ops.
type CompareMode int

const (
	// Compare Strict mode uses greatest IP within CIDR
	// address range for comparison ops.
	Strict CompareMode = iota

	// Compare Value compares IP address value and ignores CIDR
	// address range.
	Value
)

// IPAddressType represents IPv4 or IPv6 type
type IPAddressType int

const (
	IPAddressIPv4 IPAddressType = iota
	IPAddressIPv6
)

const (
	IPV4_HOST_CIDR = 32
	IPV6_HOST_CIDR = 128
)

// IPv4 set single IPv4 from bytes.
func (addr *IPAddress) IPv4(a byte, b byte, c byte, d byte) {
	addr.IP = net.IPv4(a, b, c, d)
	addr.CIDR = IPV4_HOST_CIDR
}

// IPv4WithCIDR set single IPv4 from bytes with cidr value.
func (addr *IPAddress) IPv4WithCIDR(a, b, c, d byte, cidr int) {
	addr.IP = net.IPv4(a, b, c, d)
	addr.CIDR = cidr
}

// IPv4FromInt sets IPv4 from uint32
func (addr *IPAddress) IPv4FromInt(intAddress uint32) {
	addr.IPv4(byte((intAddress>>24)&0xFF),
		byte((intAddress>>16)&0xFF),
		byte((intAddress>>8)&0xFF),
		byte(intAddress&0xFF))
	addr.CIDR = IPV4_HOST_CIDR
}

// IPv4FromInt set IPv6 from integer value
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

// FromString set both IPv4 and IPv6 from string value with
// optional CIDR format.
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
		if cidrVal < 0 {
			return errors.New("Invalid address string")
		}
		addr.IP = ipAddr
		addr.CIDR = cidrVal
	}
	return nil
}

func (addr *IPAddress) IsIPv4() bool {
	if addr.To4() != nil {
		return true
	}
	return false
}

func (addr *IPAddress) IsIPv6() bool {
	if len(addr.To4()) == 0 && len(addr.To16()) == net.IPv6len {
		return true
	}
	return false
}

// IsIPv4Subnet checks whether IPv4 address specifies a subnet range
func (addr *IPAddress) IsIPv4Subnet() bool {
	if !addr.IsIPv4() {
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

func (addr *IPAddress) Type() IPAddressType {
	if addr.IsIPv6() {
		return IPAddressIPv6
	}
	return IPAddressIPv4
}

// Compare IPv4 or IPv6 addresses according to the CompareOperator operator
func (addr *IPAddress) Compare(rhs IPAddress, compOps CompareOperator, compMode CompareMode) bool {
	var (
		lhsTop = new(IPAddress)
		rhsTop = new(IPAddress)
	)

	if (len(addr.IP) != len(rhs.IP)) && compMode == Strict {
		if compOps == NE {
			return true
		} else {
			return false
		}
	}

	if compMode == Strict {
		lhsTop = addr.End()
		rhsTop = rhs.End()
	} else {
		if len(addr.IP) != 0 {
			lhsTop.IP = make(net.IP, len(addr.IP))
			copy(lhsTop.IP, addr.IP)
		} else {
			lhsTop = nil
		}

		if len(rhs.IP) != 0 {
			rhsTop.IP = make(net.IP, len(rhs.IP))
			copy(rhsTop.IP, rhs.IP)
		} else {
			rhsTop = nil
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

// LE checks if less than or equal to address
func (addr *IPAddress) LE(rhs IPAddress, compMode CompareMode) bool {
	return addr.Compare(rhs, LE, compMode)
}

// LT checks if less than address
func (addr *IPAddress) LT(rhs IPAddress, compMode CompareMode) bool {
	return addr.Compare(rhs, LT, compMode)
}

// GT checks if greater than address
func (addr *IPAddress) GT(rhs IPAddress, compMode CompareMode) bool {
	return addr.Compare(rhs, GT, compMode)
}

// GE checks if greater than or equal to address
func (addr *IPAddress) GE(rhs IPAddress, compMode CompareMode) bool {
	return addr.Compare(rhs, GE, compMode)
}

// EQ check if equal to address
func (addr *IPAddress) EQ(rhs IPAddress, compMode CompareMode) bool {
	return addr.Compare(rhs, EQ, compMode)
}

// NE check if not equal to address
func (addr *IPAddress) NE(rhs IPAddress, compMode CompareMode) bool {
	return addr.Compare(rhs, NE, compMode)
}

// IPv4ToInt returns ipv4 addr converted to uint32
func (addr *IPAddress) IPv4ToInt() (uint32, error) {
	var (
		octetIdx int
		ipInt    uint32
	)

	if !addr.IsIPv4() {
		return 0, fmt.Errorf("failed to convert to uint32")
	}

	// net.IP stores 4 byte IPv4 in either 4 byte slice or
	// last 4 bytes of a 16 byte slice.
	if len(addr.IP) == net.IPv4len {
		octetIdx = 3
	} else {
		octetIdx = 15
	}

	ipInt = uint32(addr.IP[octetIdx])
	ipInt += uint32(addr.IP[octetIdx-1]) << 8
	ipInt += uint32(addr.IP[octetIdx-2]) << 16
	ipInt += uint32(addr.IP[octetIdx-3]) << 24
	return ipInt, nil
}

// IPv6ToInt returns ipv6 addr converted to *big.Int (uint128)
func (addr *IPAddress) IPv6ToInt() (*big.Int, error) {
	if !addr.IsIPv6() {
		return nil, fmt.Errorf("failed to convert to *big.int")
	}

	ipInt := new(big.Int)
	ipInt.SetBytes(addr.IP)
	return ipInt, nil
}

func (addr *IPAddress) ToNetworkAddress() (*IPAddress, bool) {
	if start := addr.Start(); start != nil {
		return start, true
	}
	return nil, false
}

func (addr *IPAddress) ToBroadcastAddress() (*IPAddress, bool) {
	var end = addr.End()
	if end != nil && addr.IsIPv4() {
		return end, true
	}
	return nil, false
}

// End returns the highest address in the IP CIDR range.
func (addr *IPAddress) End() *IPAddress {
	var (
		endAddr  IPAddress
		maskSize int
	)

	switch addr.Type() {
	case IPAddressIPv4:
		maskSize = 4
		endAddr.CIDR = IPV4_HOST_CIDR
		endAddr.IP = make(net.IP, net.IPv4len)
		copy(endAddr.IP, addr.To4())
	case IPAddressIPv6:
		maskSize = 16
		endAddr.CIDR = IPV6_HOST_CIDR
		endAddr.IP = make(net.IP, len(addr.IP))
		copy(endAddr.IP, addr.IP)
	default:
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

// Start returns the lowest address in IP CIDR range.
func (addr *IPAddress) Start() *IPAddress {
	var (
		startAddr IPAddress
		maskSize  int
	)

	switch addr.Type() {
	case IPAddressIPv4:
		maskSize = 4
		startAddr.CIDR = IPV4_HOST_CIDR
		startAddr.IP = make(net.IP, net.IPv4len)
		copy(startAddr.IP, addr.To4())
	case IPAddressIPv6:
		maskSize = 16
		startAddr.CIDR = IPV6_HOST_CIDR
		startAddr.IP = make(net.IP, len(addr.IP))
		copy(startAddr.IP, addr.IP)
	default:
		return nil
	}

	if addr.CIDR > 8*maskSize {
		return nil
	}

	netMask := net.CIDRMask(addr.CIDR, 8*maskSize)
	for i := 0; i < maskSize; i++ {
		startAddr.IP[i] = startAddr.IP[i] & netMask[i]
	}
	return &startAddr
}

func (addr *IPAddress) XOR(rhs IPAddress) *IPAddress {
	if addr.Type() != rhs.Type() {
		return nil
	}

	if addr.IsIPv4() && rhs.IsIPv4() {
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

	if addr.IsIPv4() && rhs.IsIPv4() {
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

	if addr.IsIPv4() && rhs.IsIPv4() {
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

func (addr *IPAddress) Add(value uint32) *IPAddress {
	switch addr.Type() {
	case IPAddressIPv6:
		newVal, _ := addr.IPv6ToInt()
		newVal.Add(newVal, big.NewInt(int64(value)))
		addr.IPv6FromInt(newVal)
	case IPAddressIPv4:
		newVal, _ := addr.IPv4ToInt()
		if (value + newVal) < value {
			return nil
		}
		addr.IPv4FromInt(value + newVal)
	default:
		return nil
	}
	return addr
}

func (addr *IPAddress) Subtract(value uint32) *IPAddress {
	switch addr.Type() {
	case IPAddressIPv6:
		newVal, _ := addr.IPv6ToInt()
		newVal.Sub(newVal, big.NewInt(int64(value)))
		addr.IPv6FromInt(newVal)
	case IPAddressIPv4:
		newVal, _ := addr.IPv4ToInt()
		if (newVal - value) > newVal {
			return nil
		}
		addr.IPv4FromInt(newVal - value)
	default:
		return nil
	}
	return addr
}

// Range calculates the start and end of addr ip range
func (addr *IPAddress) Range() (*IPAddress, *IPAddress, error) {
	if addr.End() == nil || addr.Start() == nil {
		return nil, nil, fmt.Errorf("nil start/end subnet range")
	}
	return addr.Start(), addr.End(), nil
}

// Overlaps checks if addr and ip range overlap -- [addr, rh]
func (addr *IPAddress) Overlaps(rh IPAddress) bool {
	lhStart, lhEnd, err1 := addr.Range()
	rhStart, rhEnd, err2 := rh.Range()

	if err1 != nil || err2 != nil {
		return false
	}
	return lhStart.GE(*rhStart, Value) && lhEnd.LE(*rhEnd, Value) ||
		lhStart.LE(*rhStart, Value) && lhEnd.GE(*rhEnd, Value)
}

// Within reports whether the IP range is within another IP range - (addr, rh)
func (addr *IPAddress) Within(rh IPAddress) bool {
	lhStart, lhEnd, err1 := addr.Range()
	rhStart, rhEnd, err2 := rh.Range()

	if err1 != nil || err2 != nil {
		return false
	}
	return lhStart.GT(*rhStart, Value) && lhEnd.LT(*rhEnd, Value)
}

// Contains reports whether the IP range contains another IP range - (addr, rh)
func (addr *IPAddress) Contains(rh IPAddress) bool {
	lhStart, lhEnd, err1 := addr.Range()
	rhStart, rhEnd, err2 := rh.Range()

	if err1 != nil || err2 != nil {
		return false
	}
	return lhStart.LT(*rhStart, Value) && lhEnd.GT(*rhEnd, Value)
}
