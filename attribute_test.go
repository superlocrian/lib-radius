package radius

import (
	"bytes"
	"encoding/binary"
	"math"
	"net"
	"testing"
)

func TestAttrString_Encode(t *testing.T) {

	var err error
	var strAttr *Attribute
	if strAttr, err = NewAttribute(Attr_UserName); err != nil {
		t.Error(err)
	}

	bytesValues := [][]byte{
		[]byte("gfgfgf что то по русски"),
	}
	for _, b := range bytesValues {
		strAttr.Value = b
		err := strAttr.Encode()
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(strAttr.Wire[2:], b) {
			t.Errorf("Expected: %v got: %v", b, strAttr.Wire[2:])
		}
	}

	stringValues := []string{
		"a",
		"строка еще строка",
	}
	for _, s := range stringValues {
		strAttr.Value = s
		err := strAttr.Encode()
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(strAttr.Wire[2:], []byte(s)) {
			t.Errorf("Expected: %v got: %v", []byte(s), strAttr.Wire[2:])
		}
	}

	strAttr.Value = struct{}{}
	if err = strAttr.Encode(); err == nil {
		t.Errorf("Expected: err got: %v", strAttr.Wire)
	}
}

func TestAttrString_Decode(t *testing.T) {

	var err error
	var strAttr *Attribute
	if strAttr, err = NewAttribute(Attr_UserName); err != nil {
		t.Error(err)
	}
	strAttr.Value = "стринг"
	if err = strAttr.Encode(); err != nil {
		t.Error(err)
	}
	strAttr.Type = 0
	strAttr.Value = nil

	if err = strAttr.Decode(); err != nil {
		t.Error(err)
	}

	if strAttr.Type != Attr_UserName {
		t.Errorf("Expected %d go %d", Attr_UserName, strAttr.Type)
	}

	if strAttr.Value.(string) != "стринг" {
		t.Errorf("Expected стринг go %s", strAttr.Value.(string))
	}
}

func TestAttrAddress_Encode(t *testing.T) {

	var (
		addr *Attribute
		err  error
	)
	if addr, err = NewAttribute(Attr_FramedIPAddress); err != nil {
		t.Error(err)
	}
	addr.Value = math.MaxUint32 + 10
	if err := addr.Encode(); err == nil {
		t.Errorf("Expected: err got: %v", addr.Wire)
	}
	addr.Value = net.ParseIP("127.0.0.1")
	err = addr.Encode()
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(addr.Wire[2:], []byte(net.ParseIP("127.0.0.1").To4())) {
		t.Errorf("Expected: %v got: %v", net.IP(net.ParseIP("127.0.0.1")), addr.Wire[2:])
	}

	wrongIpStr := "30.168.1.255.1"
	addr.Value = net.ParseIP(wrongIpStr)
	err = addr.Encode()
	if err == nil {
		t.Errorf("Expected: err got: %v", addr.Wire)
	}

}

func TestAttrAddress_Decode(t *testing.T) {
	var (
		addr *Attribute
		err  error
	)
	if addr, err = NewAttribute(Attr_FramedIPAddress); err != nil {
		t.Error(err)
	}
	addr.Wire = []byte{12, 6, 127, 0, 0, 1}
	if err := addr.Decode(); err != nil {
		t.Error(err)
	}

	if addr.Value.(net.IP).String() != "127.0.0.1" {
		t.Errorf("Expected 127.0.0.1 got %v", addr.Value)
	}

	if addr.Type != 12 {
		t.Errorf("Expected 12 got %d", addr.Type)
	}
}

func TestAttrInteger_Encode(t *testing.T) {
	var (
		ai  *Attribute
		err error
	)
	if ai, err = NewAttribute(Attr_NASPort); err != nil {
		t.Error(err)
	}
	ai.Value = uint32(math.MaxUint32)
	if err := ai.Encode(); err != nil {
		t.Error(err)
	}

	ai.Value = "hfhfytytyty"
	err = ai.Encode()
	if err == nil {
		t.Errorf("Expected: err got: %v", ai.Wire)
	}

}

func TestAttrInteger_Decode(t *testing.T) {
	var (
		ai  *Attribute
		err error
	)
	if ai, err = NewAttribute(Attr_NASPort); err != nil {
		t.Error(err)
	}
	raw := make([]byte, 4)

	binary.BigEndian.PutUint32(raw, uint32(math.MaxUint32))
	ai.Wire = append(ai.Wire, 1, byte(len(raw))+2)
	ai.Wire = append(ai.Wire, raw...)

	if err := ai.Decode(); err != nil {
		t.Error(err)
	}

	if ai.Value.(uint32) != math.MaxUint32 {
		t.Errorf("Expected %d got %d", math.MaxUint32, ai.Value.(uint32))
	}

}

func TestAttrVendorSpec_Encode(t *testing.T) {

	var (
		a   *Attribute
		err error
	)
	if a, err = NewAttribute(Attr_VendorSpecific); err != nil {
		t.Error(err)
	}
	a.Value = uint32(9)
	a.AddAVPair(252, []byte("test test"))
	a.AddAVPair(252, []byte("test test 2"))

	if err := a.Encode(); err != nil {
		t.Error(err)
	}
	if a.Wire[5] != 9 {
		t.Errorf("Expected 9 got %d ", a.Wire[5])
	}
}

func TestAttrVendorSpec_Decode(t *testing.T) {
	d := []byte{26, 30, 0, 0, 0, 9, 252, 11, 116, 101, 115, 116, 32, 116, 101, 115, 116, 252, 13, 116, 101, 115, 116, 32, 116, 101, 115, 116, 32, 50}

	var (
		a   *Attribute
		err error
	)
	if a, err = NewAttribute(Attr_VendorSpecific); err != nil {
		t.Error(err)
	}
	a.Wire = d
	if err := a.Decode(); err != nil {
		t.Error(err)
	}

	if string(a.Pairs[1].Value) != "test test 2" {
		t.Errorf("Expected string 'test test 2' got %v", a.Pairs[1].Value)
	}

}
