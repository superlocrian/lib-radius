package radius

import (
	"net"
	"testing"
)

func TestAttribute_ValueString(t *testing.T) {

	var err error
	var strAttr *Attribute
	if strAttr, err = NewAttribute(Attr_UserName); err != nil {
		t.Error(err)
	}

	val := "11-22-33-44-55-66"

	strAttr.Value = []byte(val)
	err = strAttr.Encode()
	if err != nil {
		t.Error(err)
	}

	strAttr.Type = 0
	strAttr.Value = nil

	err = strAttr.Decode()
	if err != nil {
		t.Error(err)
	}

	var strValue string
	err = strAttr.ValueString(&strValue)
	if err != nil {
		t.Error(err)
	}

	if val != strValue {
		t.Errorf("expected %s  got %s", val, strValue)
	}

	var intVal uint32
	err = strAttr.ValueUint32(&intVal)
	if err == nil {
		t.Errorf("expected nil got %v", err)
	}
}

func TestAttribute_ValueUint32(t *testing.T) {
	var err error
	var attr *Attribute
	if attr, err = NewAttribute(Attr_SessionTimeout); err != nil {
		t.Error(err)
	}

	val := uint32(600)

	attr.Value = val
	err = attr.Encode()
	if err != nil {
		t.Error(err)
	}

	attr.Type = 0
	attr.Value = nil

	err = attr.Decode()
	if err != nil {
		t.Error(err)
	}

	var value uint32
	err = attr.ValueUint32(&value)
	if err != nil {
		t.Error(err)
	}

	if val != value {
		t.Errorf("expected %d  got %d", val, value)
	}

}

func TestAttribute_ValueIP(t *testing.T) {
	var err error
	var attr *Attribute
	if attr, err = NewAttribute(Attr_FramedIPAddress); err != nil {
		t.Error(err)
	}

	attr.Value = net.ParseIP("127.0.0.1")
	err = attr.Encode()
	if err != nil {
		t.Error(err)
	}

	attr.Type = 0
	attr.Value = nil

	err = attr.Decode()
	if err != nil {
		t.Error(err)
	}

	var value net.IP
	err = attr.ValueIP(&value)
	if err != nil {
		t.Error(err)
	}

	if value == nil {
		t.Fatalf("expected net.IP got nil ")
	}

	if value.String() != "127.0.0.1" {
		t.Errorf("expected %s  got %s", "127.0.0.1", value)
	}

}
