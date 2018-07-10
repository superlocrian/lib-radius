package radius

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

var packetName map[PacketType]string

func init() {
	packetName = make(map[PacketType]string)
	packetName[Code_AccessRequest] = "Access-Request"
	packetName[Code_AccessAccept] = "Access-Accept"
	packetName[Code_AccessReject] = "Access-Reject"
	packetName[Code_AccountingRequest] = "Accounting-Request"
	packetName[Code_AccountingResponse] = "Accounting-Response"
	packetName[Code_AccessChallenge] = "Access-Challenge"
	packetName[Code_StatusServer] = "Status-Server"
	packetName[Code_StatusClient] = "Status-Client"
	packetName[Code_DisconnectRequest] = "Disconnect-Request"
	packetName[Code_DisconnectACK] = "Disconnect-ACK"
	packetName[Code_DisconnectNAK] = "Disconnect-NAK"
	packetName[Code_CoARequest] = "CoA-Request"
	packetName[Code_CoAACK] = "CoA-ACK"
	packetName[Code_CoANAK] = "CoA-NAK"

}

type PacketType byte

func (p PacketType) String() string {
	if name, ok := packetName[p]; ok {
		return fmt.Sprintf("%s(%d)", name, p)
	}
	return ""
}

type Packet struct {
	Type          PacketType
	Identifier    byte
	Authenticator [16]byte
	//заполняется для ответного(берется Authenticator из пакета запроса),
	// требуется для формирования аутентификатора ответа
	RequestAuthenticator [16]byte
	Secret               []byte

	Wire       []byte
	Attributes []*Attribute

	attrsBuff bytes.Buffer

	//Длина пакета из поля при получении для декодирования
	length uint16
	//Фактическая длина пакета получившаяся при декодировании
	lengthDecoded uint16
}

func NewPacket(pt PacketType, secret []byte) *Packet {

	var buff [1]byte
	if _, err := rand.Read(buff[:]); err != nil {
		return nil
	}

	packet := &Packet{
		Type:       pt,
		Identifier: buff[0],
		Secret:     secret,
	}

	return packet
}

func (p *Packet) encodeAttributes() (err error) {
	if p.attrsBuff.Len() == 0 {
		for _, attr := range p.Attributes {
			if err = attr.Encode(); err != nil {
				err = errors.New(fmt.Sprintf("packet encode: %v", err))
				return
			}
			p.attrsBuff.Write(attr.Wire)
		}
	}
	return
}

func (p *Packet) Encode() error {

	if err := p.encodeAttributes(); err != nil {
		return errors.New(fmt.Sprintf("packet encode: %v", err))
	}

	var buffer bytes.Buffer
	if len(p.Secret) == 0 {
		return fmt.Errorf("need secret to make authenticator ")
	}

	pktLen := 20 + p.attrsBuff.Len()
	if pktLen > MaxPacketLength {
		return errors.New("encoded packet is too long")
	}

	if err := buffer.WriteByte(byte(p.Type)); err != nil {
		return fmt.Errorf("Packet.Encode: %v", err)
	}
	if err := buffer.WriteByte(byte(p.Identifier)); err != nil {
		return fmt.Errorf("Packet.Encode: %v", err)
	}
	if err := binary.Write(&buffer, binary.BigEndian, uint16(pktLen)); err != nil {
		return fmt.Errorf("Packet.Encode: %v", err)
	}

	p.makeAuthenticator()

	buffer.Write(p.Authenticator[:])
	buffer.ReadFrom(&p.attrsBuff)

	p.Wire = buffer.Bytes()

	return nil
}

func (p *Packet) makeAuthenticator() error {
	switch p.Type {
	case Code_AccessRequest, Code_StatusServer:
		if err := p.MakeAccessRequestAuthenticator(); err != nil {
			return fmt.Errorf("MakeAccessRequestAuthenticator: %v", err)
		}
		break
	case Code_AccountingResponse, Code_AccessAccept, Code_AccessReject, Code_AccessChallenge,
		Code_DisconnectACK, Code_DisconnectNAK, Code_CoAACK, Code_CoANAK:
		if err := p.MakeResponseAuthenticator(); err != nil {
			return fmt.Errorf("MakeResponseAuthenticator: %v", err)
		}
		break

	case Code_AccountingRequest, Code_CoARequest, Code_DisconnectRequest:
		//todo make authenticator
		if err := p.MakeAccountingRequestAuthenticator(); err != nil {
			return err
		}
		break
	default:
		return errors.New("unknown Packet code")
	}
	return nil
}

func (p *Packet) Decode() error {

	if len(p.Wire) < 3 {
		return errors.New("too short packet")
	}
	p.Type = PacketType(p.Wire[0])
	p.Identifier = p.Wire[1]

	p.length = binary.BigEndian.Uint16(p.Wire[2:4])
	p.lengthDecoded += 4
	if p.length < 20 || p.length > MaxPacketLength {
		return errors.New("radius: invalid packet length")
	}
	n := copy(p.Authenticator[:], p.Wire[4:20])
	p.lengthDecoded += uint16(n)

	p.attrsBuff.Write(p.Wire[20:])

	lengthOfAttrBuf := p.attrsBuff.Len()
	attrsBuff := p.attrsBuff.Bytes()

	for lengthOfAttrBuf > 0 {

		if lengthOfAttrBuf < 2 {
			return errors.New(fmt.Sprintf("attribute must be at least 2 bytes long, but it's length is %d\n", lengthOfAttrBuf))
		}

		attrLength := int(attrsBuff[1])
		if attrLength == 0 {
			break
		}
		if attrLength < 2 {
			return errors.New(fmt.Sprintf("attribute length < 2 (length:%d)", attrLength))
		}

		if attrLength > 253 {
			return errors.New(fmt.Sprintf("attribute length > 253 (length:%d)", attrLength))
		}

		if attrLength > lengthOfAttrBuf {
			return errors.New(fmt.Sprintf("attribute length > packet size (%d > %d)", attrLength, lengthOfAttrBuf))
		}

		a := new(Attribute)
		a.Wire = attrsBuff[:attrLength]
		var err error

		var ok bool
		a.Type = AttributeType(attrsBuff[0])
		ai, ok := attrTypeToInfo[a.Type]
		if !ok {
			a.Encoder = DefaultEncoder
			if logger != nil {
				logger.Warnf("can't decode attribute, type: %s ", a.Type.String())
			}
		} else {
			a.Encoder = ai.Encoder
		}
		p.AddAttr(a)
		if err = a.Decode(); err != nil {
			return err
		}
		p.lengthDecoded += uint16(len(a.Wire))
		attrsBuff = attrsBuff[attrLength:]
		lengthOfAttrBuf = len(attrsBuff)
	}
	return nil
}

func (p *Packet) DecodeLengthNotMatch() bool {
	return p.length != p.lengthDecoded
}

func (p *Packet) AddAttr(attr *Attribute) {
	p.Attributes = append(p.Attributes, attr)
}

func (p *Packet) AddAttribute(t AttributeType, value interface{}) (err error) {
	var attr *Attribute
	if attr, err = NewAttribute(t); err != nil {
		return err
	}
	attr.Value = value
	p.AddAttr(attr)
	return nil
}
func (p Packet) Length() uint16 {
	return p.length
}
func (p Packet) LengthDecoded() uint16 {
	return p.lengthDecoded
}

func (p *Packet) StringMultiLine() string {
	str := fmt.Sprintf("######## PACKET ######## \nType: %s \nId: %d \nAuthentificator: %x\nSecret: %s\n",
		p.Type, p.Identifier, string(p.Authenticator[:]), p.Secret)

	if len(p.Attributes) > 0 {
		str += "Attributes:"
		for _, a := range p.Attributes {
			if a.Type == Attr_UserPassword {
				str += fmt.Sprintf("\n\tType: %s Value: %x", a.Type, a.Value)
			} else {
				str += fmt.Sprintf("\n\tType: %s Value: %+v", a.Type, a.Value)
			}

			if a.Type == Attr_VendorSpecific {
				str += fmt.Sprintf("\n\t\t  VSA:")
				for _, pair := range a.Pairs {
					str += fmt.Sprintf("VendorId: %d VendorType: %d Value: %q", a.Value, pair.VendorType, pair.Value)
				}
			}

		}
		str += fmt.Sprintf("\n\n")
	}

	return str

}
func (p *Packet) String() string {
	str := fmt.Sprintf("PACKET Type: %s, Id: %d, Authentificator: %x, Secret: %s ",
		p.Type, p.Identifier, string(p.Authenticator[:]), p.Secret)

	if len(p.Attributes) > 0 {
		str += "Attributes: "
		for _, a := range p.Attributes {
			if a.Type == Attr_UserPassword {
				str += fmt.Sprintf("| %s : %x ", a.Type, a.Value)
			} else {
				str += fmt.Sprintf("| %s : %+v ", a.Type, a.Value)
			}

			if a.Type == Attr_VendorSpecific {
				str += fmt.Sprintf(" VSA: ")
				for _, pair := range a.Pairs {
					str += fmt.Sprintf("VId: %d VType: %d Val: %q ", a.Value, pair.VendorType, pair.Value)
				}
			}
		}
	}

	return str

}

func (p *Packet) Attr(t AttributeType) *Attribute {
	var attr *Attribute
	for _, a := range p.Attributes {
		if a.Type == t {
			attr = a
		}
	}
	return attr
}

func (p *Packet) Attrs(t AttributeType) []*Attribute {
	var out []*Attribute
	for _, a := range p.Attributes {
		if a.Type == t {
			out = append(out, a)
		}
	}
	return out
}

func (p *Packet) CheckAccountingRequestAuthenticator(secret []byte) (res bool, err error) {

	var buffer bytes.Buffer
	buffer.Grow(int(p.length))

	buffer.WriteByte(byte(p.Type))
	buffer.WriteByte(p.Identifier)
	binary.Write(&buffer, binary.BigEndian, p.length)
	nul := [16]byte{}
	buffer.Write(nul[:])
	for _, attr := range p.Attributes {
		buffer.Write(attr.Wire)
	}
	buffer.Write(secret)
	hash := md5.New()
	hash.Write(buffer.Bytes())
	sum := [16]byte{}
	hash.Sum(sum[0:0])
	compareTwoSlices := func(a, b []byte) bool {
		if a == nil && b == nil {
			return true
		}
		if a == nil || b == nil {
			return false
		}
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}

	return compareTwoSlices(p.Authenticator[:], sum[:]), nil
}

/*

Response Authenticator

The Authenticator field in an Accounting-Response packet is called
the Response Authenticator, and contains a one-way MD5 hash
calculated over a stream of octets consisting of the Accounting-
Response Code, Identifier, Length, the Request Authenticator field
from the Accounting-Request packet being replied to, and the
response attributes if any, followed by the shared secret.  The
resulting 16 octet MD5 hash value is stored in the Authenticator
field of the Accounting-Response packet.

вызывается у пакета который был сформирован (не декодирован)

*/
func (p *Packet) MakeResponseAuthenticator() error {

	var buffer bytes.Buffer
	if len(p.Secret) == 0 {
		return fmt.Errorf("need secret to make authenticator ")
	}

	if err := buffer.WriteByte(byte(p.Type)); err != nil {
		return err
	}
	if err := buffer.WriteByte(byte(p.Identifier)); err != nil {
		return err
	}

	pktLen := 20 + p.attrsBuff.Len()
	if err := binary.Write(&buffer, binary.BigEndian, uint16(pktLen)); err != nil {
		return err
	}

	if _, err := buffer.Write(p.RequestAuthenticator[:]); err != nil {
		return err
	}
	if _, err := buffer.Write(p.attrsBuff.Bytes()); err != nil {
		return err
	}
	if _, err := buffer.Write(p.Secret); err != nil {
		return err
	}

	hash := md5.New()
	if _, err := hash.Write(buffer.Bytes()); err != nil {
		return err
	}
	copy(p.Authenticator[:], hash.Sum([]byte{}))

	return nil

}

func (p *Packet) MakeAccessRequestAuthenticator() error {
	var buff [16]byte
	if _, err := rand.Read(buff[:]); err != nil {
		return nil
	}
	copy(p.Authenticator[:], buff[:])
	return nil
}

func (p *Packet) MakeAccountingRequestAuthenticator() error {
	if len(p.Secret) == 0 {
		return fmt.Errorf("need secret to make authenticator ")
	}

	var buffer bytes.Buffer
	if err := buffer.WriteByte(byte(p.Type)); err != nil {
		return err
	}
	if err := buffer.WriteByte(byte(p.Identifier)); err != nil {
		return err
	}
	pktLen := 20 + p.attrsBuff.Len()
	if err := binary.Write(&buffer, binary.BigEndian, uint16(pktLen)); err != nil {
		return err
	}

	for i := 0; i < 16; i++ {
		if err := buffer.WriteByte(byte(0)); err != nil {
			return err
		}
	}

	if _, err := buffer.Write(p.attrsBuff.Bytes()); err != nil {
		return err
	}
	if _, err := buffer.Write(p.Secret); err != nil {
		return err
	}

	hash := md5.New()
	if _, err := hash.Write(buffer.Bytes()); err != nil {
		return err
	}
	copy(p.Authenticator[:], hash.Sum([]byte{}))

	return nil

}
