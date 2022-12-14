package ipaddr

import (
	"fmt"
	"math"
	"math/big"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIPv4Create(t *testing.T) {
	validIPv4Bytes := []struct {
		in   []byte
		cidr int
	}{
		{[]byte{0, 0, 0, 0}, 0},
		{[]byte{100, 100, 100, 100}, 0},
		{[]byte{255, 255, 255, 255}, 0},
		{[]byte{255, 255, 255, 255}, 32},
	}

	for _, test := range validIPv4Bytes {
		t.Run(fmt.Sprintf("IPv4(): %d-%d", test.in, test.cidr), func(t *testing.T) {
			var (
				IP      IPAddress
				IPwCIDR IPAddress
			)

			IP.IPv4(test.in[0], test.in[1], test.in[2], test.in[3])

			// Check that NewIPv4 CIDR represents a single ipv4 address.
			assert.Equal(t, IPV4_HOST_CIDR, IP.CIDR)

			// Check that ip type bytes match input ip byte array.
			assert.Equal(t, test.in, []byte(IP.To4()))

			// Check that ip is a valid IPv4 address.
			assert.True(t, IP.IsIPv4())

			// Check that ip is not a valid IPv6 address.
			assert.False(t, IP.IsIPv6())

			IPwCIDR.IPv4WithCIDR(test.in[0], test.in[1], test.in[2], test.in[3], test.cidr)

			// Check that CIDR is set.
			assert.Equal(t, test.cidr, IPwCIDR.CIDR)

			// Check that ip type bytes match input ip byte array.
			assert.Equal(t, test.in, []byte(IPwCIDR.To4()))

			// Check that ip is a valid IPv4 address.
			assert.True(t, IPwCIDR.IsIPv4())

			// Check IP+CIDR is valid IPv4 subnet.
			assert.True(t, IP.IsIPv4Subnet())
		})
	}

	invalidIPv4Subnet := []struct {
		in   []byte
		cidr int
	}{
		{[]byte{0, 0, 0, 0}, 33},
	}

	for _, test := range invalidIPv4Subnet {
		var IP IPAddress
		IP.IPv4WithCIDR(test.in[0], test.in[1], test.in[2], test.in[3], test.cidr)

		// Check that CIDR component represents an invalid subnet.
		assert.False(t, IP.IsIPv4Subnet())

		// Check that IP component is valid.
		assert.True(t, IP.IsIPv4())
	}

	// Check that from string works for both IP/CIDR
	validIPv4FromString := []struct {
		in   string
		out  []byte
		cidr int
	}{
		{`0.0.0.0`, []byte{0, 0, 0, 0}, 32},
		{`0.0.0.0/0`, []byte{0, 0, 0, 0}, 0},
		{`0.0.0.0/32`, []byte{0, 0, 0, 0}, 32},
		{`127.0.0.1`, []byte{127, 0, 0, 1}, 32},
		{`255.255.255.255/16`, []byte{255, 255, 255, 255}, 16},
	}

	for _, test := range validIPv4FromString {
		var IP IPAddress
		err := IP.FromString(test.in)
		assert.Nil(t, err, test.in)

		// Check that ip type bytes match input ip byte array.
		assert.Equal(t, test.out, []byte(IP.To4()), test.in)

		// Check that CIDR is set correctly.
		assert.Equal(t, test.cidr, IP.CIDR, test.in)
	}

	invalidIPv4FromString := []struct {
		in   string
		out  []byte
		cidr int
	}{
		{`0`, nil, 0},
		{`\16`, nil, 0},
		{`0.0.0.`, nil, 0},
		{`bla`, nil, 0},
		{`256.255.255.255`, nil, 0},
		{`127.0.0.1/33`, nil, 0},
	}

	for _, test := range invalidIPv4FromString {
		var IP IPAddress
		err := IP.FromString(test.in)
		assert.NotNil(t, err, test.in)

		// Check that ip type bytes match input ip byte array.
		assert.Equal(t, test.out, []byte(IP.To4()), test.in)

		// Check that CIDR is set correctly.
		assert.Equal(t, test.cidr, IP.CIDR, test.in)
	}

	// Check that from integer and to integer works for both IP/CIDR
	validIPv4Int := []struct {
		in  uint32
		out []byte
	}{
		{0, []byte{0, 0, 0, 0}},
		{math.MaxUint32, []byte{255, 255, 255, 255}},
		{555555555, []byte{33, 29, 26, 227}},
	}

	for _, test := range validIPv4Int {
		var IP IPAddress
		IP.IPv4FromInt(test.in)

		// Check that ip type bytes match input ip byte array.
		assert.Equal(t, test.out, []byte(IP.To4()), test.in)

		// Check that converting ip back to int is equal to previous input
		n, err := IP.IPv4ToInt()
		assert.Nil(t, err)
		assert.Equal(t, test.in, n)
	}
}

func TestIPv6Create(t *testing.T) {
	validFromString := []struct {
		in   string
		cidr int
	}{
		{"2001:db8:abcd:8000::/52", 52},
		{"2001:db8:abcd:8000::/0", 0},
		{"2001:db8:abcd:8000::/128", 128},
		{"2001:db8:abcd:8000::", 128},
		{"2001:0db8:0000:0000:0000:ff00:0042:8329", 128},
		{"2001:db8:0:0:0:ff00:42:8329", 128},
		{"2001:db8::ff00:42:8329", 128},
		{"::0db8:0000:0000:0000:ff00:0042:8329", 128},
	}

	for _, test := range validFromString {
		var IP IPAddress
		err := IP.FromString(test.in)
		assert.Nil(t, err, test.in)

		out := net.ParseIP(strings.Split(test.in, "/")[0])

		// Check that ip type bytes match input ip byte array.
		assert.Equal(t, []byte(out), []byte(IP.To16()), test.in)

		// Check that IPv6 and not IPv4
		assert.True(t, IP.IsIPv6())
		assert.False(t, IP.IsIPv4())

		// Check that CIDR is set correctly.
		assert.Equal(t, test.cidr, IP.CIDR, test.in)

		// Check that ip to integer is equal to IP value expected
		ipInt, err := IP.IPv6ToInt()
		assert.Nil(t, err)

		expected := big.NewInt(0)
		expected.SetBytes([]byte(out))
		assert.Equal(t, 0, expected.Cmp(ipInt), test.in)
	}

	invalidFromString := []struct {
		in   string
		cidr int
	}{
		{"", 0},
		{"/32", 0},
		{":::0000:0000:0000:ff00:0042:8329", 0},
		{":ffff:0db8:0000:0000:0000:ff00:0042:8329:fff", 0},
		{"2001:db8::ff00:42:8329%%", 0},
	}

	for _, test := range invalidFromString {
		var IP IPAddress
		err := IP.FromString(test.in)
		assert.NotNil(t, err, test.in)
		assert.Equal(t, test.cidr, IP.CIDR, test.in)
		assert.Equal(t, []byte(nil), []byte(IP.IP), test.in)
	}
}

func TestIPCompare(t *testing.T) {
	compare := func(lh, rh string, ops []CompareOperator, cmp CompareMode, out bool) {
		var lhIP, rhIP IPAddress

		assert.Nil(t, lhIP.FromString(lh))
		assert.Nil(t, rhIP.FromString(rh))

		msg := fmt.Sprintf("%s - %s", lhIP.String(), rhIP.String())
		for _, op := range ops {
			switch op {
			case LT:
				assert.Equal(t, out, lhIP.LT(rhIP, cmp), msg)
			case LE:
				assert.Equal(t, out, lhIP.LE(rhIP, cmp), msg)
			case GT:
				assert.Equal(t, out, lhIP.GT(rhIP, cmp), msg)
			case GE:
				assert.Equal(t, out, lhIP.GE(rhIP, cmp), msg)
			case NE:
				assert.Equal(t, out, lhIP.NE(rhIP, cmp), msg)
			case EQ:
				assert.Equal(t, out, lhIP.EQ(rhIP, cmp), msg)
			}
		}
	}

	// Check IPv4 compare operations.
	cmpTests := []struct {
		lh  string
		rh  string
		ops []CompareOperator
		res bool
	}{
		{"126.0.0.1", "127.0.0.1", []CompareOperator{LT, LE, NE}, true},
		{"126.0.0.1", "127.0.0.1", []CompareOperator{GT, GE, EQ}, false},
		{"127.0.0.1", "127.0.0.1", []CompareOperator{LE, EQ, GE}, true},
		{"127.0.0.1", "127.0.0.1", []CompareOperator{LT, NE, GT}, false},
		{"127.0.0.1", "126.0.0.1", []CompareOperator{GE, GT, NE}, true},
		{"73.63.175.1/32", "73.63.175.1/32", []CompareOperator{EQ}, true},
	}

	for _, test := range cmpTests {
		for _, mode := range []CompareMode{Value, Strict} {
			compare(test.lh, test.rh, test.ops, mode, test.res)
		}
	}

	cmpRange := []struct {
		lh  string
		rh  string
		ops []CompareOperator
		res bool
	}{
		{"73.63.175.1/25", "73.63.175.1/20", []CompareOperator{LT, LE, NE}, true},
		{"73.63.175.1/25", "73.63.175.1/20", []CompareOperator{GE, EQ, GT}, false},
		{"73.63.175.1/32", "73.63.175.1/32", []CompareOperator{EQ}, true},
	}

	for _, test := range cmpRange {
		compare(test.lh, test.rh, test.ops, Strict, test.res)
	}

	// Check IPv6 compare operations
	cmpIP6Tests := []struct {
		lh  string
		rh  string
		ops []CompareOperator
		res bool
	}{
		{"2001:db8:85a3::8a2e:370:7334",
			"2001:db8:85a3::8a2e:370:7335",
			[]CompareOperator{LT, LE, NE}, true,
		},
		{
			"2001:db8:85a3::8a2e:370:7334",
			"2001:db8:85a3::8a2e:370:7335",
			[]CompareOperator{GT, GE, EQ}, false,
		},
		{
			"2001:db8:85a3::8a2e:370:7335",
			"2001:db8:85a3::8a2e:370:7335",
			[]CompareOperator{LE, EQ, GE}, true,
		},
		{
			"2001:db8:85a3::8a2e:370:7335",
			"2001:db8:85a3::8a2e:370:7335",
			[]CompareOperator{LT, NE, GT}, false,
		},
		{
			"2001:db8:85a3::8a2e:370:7335",
			"2001:db8:85a3::8a2e:370:7334",
			[]CompareOperator{GE, GT, NE}, true,
		},
	}

	for _, test := range cmpIP6Tests {
		for _, mode := range []CompareMode{Value, Strict} {
			compare(test.lh, test.rh, test.ops, mode, test.res)
		}
	}

	compare("2001:db8:85a3::8a2e:370:7334/64",
		"2001:db8:85a3::8a2e:370:7334/50",
		[]CompareOperator{LT, LE, NE}, Strict, true)

	compare("2001:db8:85a3::8a2e:370:7334/64",
		"2001:db8:85a3::8a2e:370:7334/50",
		[]CompareOperator{GE, EQ, GT}, Strict, false)

	compare("2001:db8:85a3::8a2e:370:7334/128", "2001:db8:85a3::8a2e:370:7334/128",
		[]CompareOperator{EQ}, Strict, true)

	// Check range, contains and within operations.
	testRange := []struct {
		ip    string
		lower string
		upper string
		res   bool
	}{
		{"73.65.175.1/25", "73.65.175.0", "73.65.175.127", true},
		{"2001:db8:85a3::8a2e:370:7334/50",
			"2001:db8:85a3::",
			"2001:db8:85a3:3fff:ffff:ffff:ffff:ffff",
			true,
		},
	}

	for _, test := range testRange {
		var ip IPAddress

		assert.Nil(t, ip.FromString(test.ip))
		l, u, err := ip.Range()

		if test.res == false {
			assert.Nil(t, l)
			assert.Nil(t, u)
			assert.NotNil(t, err)
			continue
		}

		assert.Nil(t, err)
		assert.NotNil(t, l)
		assert.NotNil(t, u)

		assert.Equal(t, test.lower, l.String())
		assert.Equal(t, test.upper, u.String())

		assert.Equal(t, test.lower, ip.ToNetworkAddress().String())
	}

	// Check calculating subnet broadcast address
	var ip IPAddress
	assert.Nil(t, ip.FromString("73.65.175.1/25"))
	assert.Equal(t, "73.65.175.127", ip.ToBroadcastAddress().String())

	// check address within and contained in subnet
	testOverlap := []struct {
		ipRange     string
		withinRange string
		overlap     bool
	}{
		{"127.0.0.1/25", "127.0.0.5/30", true},
		{"127.0.0.1/25", "127.1.0.5/30", false},
		{"2001:db8:85a3::8a2e:370:7334/50", "2001:db8:85a3::8a2e:370:7334/127", true},
		{"2001:db8:85a3::8a2e:370:7334/50", "3001:db8:85a3::8a2e:370:7334/127", false},
	}

	for _, test := range testOverlap {
		var ip, withinRange IPAddress
		assert.Nil(t, ip.FromString(test.ipRange))
		assert.Nil(t, withinRange.FromString(test.withinRange))

		assert.Equal(t, test.overlap, ip.Overlaps(withinRange))
		assert.Equal(t, test.overlap, ip.Contains(withinRange))
		assert.Equal(t, test.overlap, withinRange.Within(ip))
	}
}

func TestBoolean(t *testing.T) {
	t.Run("bool ops", func(t *testing.T) {
		var IP, orIP, andIP, xorIP IPAddress

		// check NOT
		_ = IP.FromString("255.255.255.255")
		_ = IP.NOT()
		res, _ := IP.IPv4ToInt()
		assert.Equal(t, uint32(0), res)
		assert.Equal(t, "0.0.0.0", IP.String())

		// check OR
		orIP.IPv4FromInt(uint32(500))
		_ = IP.OR(orIP)
		assert.Equal(t, "0.0.1.244", IP.String())

		// check AND
		andIP.IPv4FromInt(uint32(3000))
		_ = IP.AND(andIP)
		assert.Equal(t, "0.0.1.176", IP.String())

		// check XOR
		xorIP.IPv4FromInt(uint32(3000))
		_ = IP.XOR(xorIP)
		assert.Equal(t, "0.0.10.8", IP.String())
	})
}

func TestAddSub(t *testing.T) {
	t.Run("add/sub", func(t *testing.T) {
		var IP IPAddress
		IP.IPv4FromInt(500)
		IP.Add(1)
		res, _ := IP.IPv4ToInt()
		assert.Equal(t, uint32(501), res)
		IP.Subtract(2)
		res, _ = IP.IPv4ToInt()
		assert.Equal(t, uint32(499), res)
	})
}
