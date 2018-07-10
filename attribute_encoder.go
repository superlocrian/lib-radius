package radius

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

type EncoderInterface interface {
	Encode(a *Attribute) error
	Decode(a *Attribute) error
}

/*
	Использовать в тех случаях если это не поддерживаемы атрибут
	записывает в значение байты
*/
type EncoderDefault struct {
}

func (e *EncoderDefault) Encode(a *Attribute) error {
	return fmt.Errorf("can't encode default (unknown) attribute")
}
func (e *EncoderDefault) Decode(a *Attribute) error {
	a.Type = AttributeType(a.Wire[0])
	a.Value = a.Wire[2:]
	return nil
}

type EncoderString struct{}

func (e *EncoderString) Encode(a *Attribute) error {

	var b bytes.Buffer
	var wire []byte
	if err := b.WriteByte(byte(a.Type)); err != nil {
		return err
	}

	switch a.Value.(type) {
	case []byte:
		wire = a.Value.([]byte)
	case string:
		wire = []byte(a.Value.(string))

	default:
		return fmt.Errorf("text Attribute must be string or []byte")
	}
	if len(wire) > 253 {
		return fmt.Errorf("encoded Attribute is too long")
	}
	if err := b.WriteByte(byte(len(wire)) + 2); err != nil {
		return err
	}
	if _, err := b.Write(wire); err != nil {
		return err
	}

	a.Wire = b.Bytes()

	return nil
}

func (e *EncoderString) Decode(a *Attribute) error {
	a.Type = AttributeType(a.Wire[0])
	a.Value = string(a.Wire[2:])
	return nil
}

type EncoderAddress struct{}

func (e *EncoderAddress) Encode(a *Attribute) error {

	var b bytes.Buffer
	var wire []byte
	if err := b.WriteByte(byte(a.Type)); err != nil {
		return err
	}

	if ip, ok := a.Value.(net.IP); !ok {
		return errors.New("address Attribute must be net.IP")
	} else if ip = ip.To4(); ip == nil {
		return errors.New("address Attribute must be an IPv4 net.IP")
	} else {
		wire = []byte(ip)
	}
	if len(wire) > 253 {
		return errors.New("encoded Attribute is too long")
	}

	if err := b.WriteByte(byte(len(wire)) + 2); err != nil {
		return err
	}
	if _, err := b.Write(wire); err != nil {
		return err
	}

	a.Wire = b.Bytes()
	return nil
}

func (e *EncoderAddress) Decode(a *Attribute) error {
	a.Type = AttributeType(a.Wire[0])
	a.Value = net.IP(string(a.Wire[2:]))
	if len(a.Value.(net.IP)) != net.IPv4len {
		return errors.New("address Attribute has invalid size")
	}
	return nil
}

type EncoderUint32 struct{}

func (e *EncoderUint32) Decode(a *Attribute) error {
	a.Type = AttributeType(a.Wire[0])
	a.Value = binary.BigEndian.Uint32(a.Wire[2:])
	return nil
}

func (e *EncoderUint32) Encode(a *Attribute) error {
	var b bytes.Buffer
	var wire = make([]byte, 4)
	if err := b.WriteByte(byte(a.Type)); err != nil {
		return err
	}

	if integer, ok := a.Value.(uint32); !ok {
		return errors.New("integer Attribute must be uint32")
	} else {
		binary.BigEndian.PutUint32(wire, integer)
	}
	if len(wire) > 253 {
		return errors.New("encoded Attribute is too long")
	}
	if err := b.WriteByte(byte(len(wire)) + 2); err != nil {
		return err
	}
	if _, err := b.Write(wire); err != nil {
		return err
	}

	a.Wire = b.Bytes()

	return nil
}

type VSA struct {
	VendorType uint8
	Value      []byte
}
type EncoderVendorSpec struct{}

func (e *EncoderVendorSpec) Encode(a *Attribute) error {

	var b, pb bytes.Buffer

	if err := b.WriteByte(byte(a.Type)); err != nil {
		return err
	}

	for _, vsa := range a.Pairs {
		pb.Write([]byte{vsa.VendorType, byte(len(vsa.Value) + 2)})
		// Append Attribute value pair
		pb.Write(vsa.Value)
	}

	//type-1 + len-1 + vendorId-4 + length of encoded pairs
	attrLen := pb.Len() + 6
	if attrLen > 253 {
		return errors.New("encoded vsa Attribute is too long")
	}
	if err := b.WriteByte(byte(attrLen)); err != nil {
		return err
	}

	//Value contains VendorId
	if integer, ok := a.Value.(uint32); !ok {
		return errors.New("vendor id must be uint32")
	} else {
		vendorId := make([]byte, 4)
		binary.BigEndian.PutUint32(vendorId, integer)
		b.Write(vendorId)
	}

	if _, err := b.Write(pb.Bytes()); err != nil {
		return err
	}

	a.Wire = b.Bytes()
	return nil
}
func (e *EncoderVendorSpec) Decode(a *Attribute) error {
	a.Pairs = nil
	if len(a.Wire) < 7 {
		return fmt.Errorf("too short VSA: %d bytes", len(a.Wire))
	}
	a.Type = AttributeType(a.Wire[0])
	a.Value = binary.BigEndian.Uint32([]byte{a.Wire[2], a.Wire[3], a.Wire[4], a.Wire[5]})
	offset := 6
	for len(a.Wire[offset:]) > 0 {
		vsa := new(VSA)
		vsa.VendorType = uint8(a.Wire[offset])
		var vsaLength int
		vsaLength = int(a.Wire[offset+1])
		vsa.Value = a.Wire[offset+2 : offset+vsaLength]
		a.Pairs = append(a.Pairs, vsa)
		offset += vsaLength
	}
	return nil
}

type EncoderTunnel struct{}

func (e *EncoderTunnel) Encode(a *Attribute) error {
	//todo implement in need
	return nil
}
func (e *EncoderTunnel) Decode(a *Attribute) error {
	a.Type = AttributeType(a.Wire[0])
	a.Tag = a.Wire[2]
	a.Value = a.Wire[3:]
	return nil
}
