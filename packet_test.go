package radius

import (
	"fmt"
	"net"
	"testing"
)

func TestNewPacket(t *testing.T) {

	_ = NewPacket(Code_AccessRequest, []byte("iuui"))
	//fmt.Println(p)
}

func TestPacket_Encode(t *testing.T) {

	t.Run("AccessRequest", func(t *testing.T) {

		p := NewPacket(Code_AccessRequest, []byte("ctrhtn"))

		userName, _ := NewAttribute(Attr_UserName)
		userName.Value = "11-22-33-44-55-66"
		p.AddAttr(userName)

		nasIp, _ := NewAttribute(Attr_NASIPAddress)
		nasIp.Value = net.ParseIP("192.168.46.191")
		p.AddAttr(nasIp)

		nasID, _ := NewAttribute(Attr_NASIdentifier)
		nasID.Value = "nas identifier"
		p.AddAttr(nasID)

		//NAS-Port
		nasPort, _ := NewAttribute(Attr_NASPort)
		nasPort.Value = uint32(1812)
		p.AddAttr(nasPort)

		csi, _ := NewAttribute(Attr_CallingStationId)
		csi.Value = "11-22-33-44-55-66"
		p.AddAttr(csi)

		vsa, _ := NewAttribute(Attr_VendorSpecific)
		vsa.Value = uint32(9)
		vsa.AddAVPair(252, []byte("av para 1"))
		vsa.AddAVPair(252, []byte("av para 2"))
		p.AddAttr(vsa)

		if err := p.Encode(); err != nil {
			t.Error(err)
		}

	})

}

func TestPacket_Decode(t *testing.T) {
	testBuff := []byte{
		2, 231, 0, 129, 156, 127, 132, 244, 243, 241, 72, 209, 202, 102, 15, 86, 34, 122,
		101, 124, 27, 6, 0, 0, 2, 88, 26, 70, 0, 0, 0, 9, 1, 64, 117, 114, 108, 45, 114, 101, 100, 105, 114, 101,
		99, 116, 61, 104, 116, 116, 112, 58, 47, 47, 97, 117, 116, 104, 46, 119, 105, 45, 102, 105, 46, 114, 117,
		47, 105, 100, 101, 110, 116, 105, 102, 105, 99, 97, 116, 105, 111, 110, 63, 115, 101, 103, 109, 101,
		110, 116, 61, 109, 101, 116, 114, 111, 26, 33, 0, 0, 0, 9, 1, 27, 11, 7, 114, 108, 45, 114, 101, 100, 105,
		114, 101, 99, 116, 45, 97, 99, 108, 61, 80, 114, 101, 45, 65, 117, 116, 104, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}

	reply := new(Packet)
	reply.Wire = testBuff
	err := reply.Decode()
	if err != nil {
		t.Fatal(err)
	}
}

func TestPacket_DecodeLengthNotMath(t *testing.T) {
	testBuff := []byte{
		2, 231, 0, 127, 156, 127, 132, 244, 243, 241, 72, 209, 202, 102, 15, 86, 34, 122,
		101, 124, 27, 6, 0, 0, 2, 88, 26, 70, 0, 0, 0, 9, 1, 64, 117, 114, 108, 45, 114, 101, 100, 105, 114, 101,
		99, 116, 61, 104, 116, 116, 112, 58, 47, 47, 97, 117, 116, 104, 46, 119, 105, 45, 102, 105, 46, 114, 117,
		47, 105, 100, 101, 110, 116, 105, 102, 105, 99, 97, 116, 105, 111, 110, 63, 115, 101, 103, 109, 101,
		110, 116, 61, 109, 101, 116, 114, 111, 26, 33, 0, 0, 0, 9, 1, 27, 11, 7, 114, 108, 45, 114, 101, 100, 105,
		114, 101, 99, 116, 45, 97, 99, 108, 61, 80, 114, 101, 45, 65, 117, 116, 104, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}

	reply := new(Packet)
	reply.Wire = testBuff
	err := reply.Decode()
	if err != nil {
		t.Fatal(err)
	}
	if !reply.DecodeLengthNotMatch() {
		t.Error(fmt.Errorf("expected true got false"))
	}
}

func TestPacket_CheckAccountingRequestAuthenticator(t *testing.T) {
	testBuff := []byte{
		4, 60, 0, 74, 1, 188, 96, 154, 3, 120, 86, 80, 104, 203, 63, 98, 173, 82, 116, 195, 1, 7, 97, 100, 109, 105, 110, 44, 35, 53, 98, 48, 101, 102, 50, 53,
		51, 47, 49, 48, 58, 48, 53, 58, 99, 97, 58, 98, 101, 58, 101, 50, 58, 97, 48, 47, 49, 52, 50, 49, 53, 57, 55, 6, 91, 14, 242, 83, 40, 6, 0, 0, 0, 1}

	req := new(Packet)
	req.Wire = testBuff
	err := req.Decode()
	if err != nil {
		t.Fatal(err)
	}
	ok, err := req.CheckAccountingRequestAuthenticator([]byte("ctrhtn"))
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error(fmt.Errorf("CheckAccountingRequestAuthenticator: expected true got false"))
	}
}

func TestPacket_MakeAccountingResponseAuthenticator(t *testing.T) {

	testBuff := []byte{
		4, 60, 0, 74, 1, 188, 96, 154, 3, 120, 86, 80, 104, 203, 63, 98, 173, 82, 116, 195, 1, 7, 97, 100, 109, 105, 110, 44, 35, 53, 98, 48, 101, 102, 50, 53,
		51, 47, 49, 48, 58, 48, 53, 58, 99, 97, 58, 98, 101, 58, 101, 50, 58, 97, 48, 47, 49, 52, 50, 49, 53, 57, 55, 6, 91, 14, 242, 83, 40, 6, 0, 0, 0, 1}

	req := new(Packet)
	req.Wire = testBuff
	err := req.Decode()
	if err != nil {
		t.Fatal(err)
	}
	ok, err := req.CheckAccountingRequestAuthenticator([]byte("ctrhtn"))
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error(fmt.Errorf("CheckAccountingRequestAuthenticator: expected true got false"))
	}

	p := NewPacket(Code_AccountingResponse, []byte("ctrhtn"))

	vsa, _ := NewAttribute(Attr_VendorSpecific)
	vsa.Value = uint32(9)
	vsa.AddAVPair(252, []byte("av para 1"))
	p.AddAttr(vsa)
	vsa, _ = NewAttribute(Attr_VendorSpecific)
	vsa.Value = uint32(9)
	vsa.AddAVPair(251, []byte("av para 2"))
	p.AddAttr(vsa)

	p.MakeResponseAuthenticator()

	if err := p.Encode(); err != nil {
		t.Error(err)
	}

	//todo проверить правильно лы мы на самом деле создали аутентификатор))))))

}
