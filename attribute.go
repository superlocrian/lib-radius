package radius

import (
	"errors"
	"fmt"
	"net"
)

var DefaultEncoder EncoderInterface

func init() {
	DefaultEncoder = &EncoderDefault{}
}

type AttributeType byte

func (a AttributeType) Name() string {
	if ai, ok := attrTypeToInfo[a]; ok {
		return ai.Name
	}
	return ""
}
func (a AttributeType) String() string {
	out := ""
	if ai, ok := attrTypeToInfo[a]; ok {
		out = fmt.Sprintf("%s(%d)", ai.Name, a)
	} else {
		out = fmt.Sprintf("unknown(%d)", a)
	}
	return out
}

type AttributeValue uint32
type Attribute struct {
	Type AttributeType
	Wire []byte
	// Tag from tunnel rfc 2868
	Tag     uint8
	Value   interface{}
	Pairs   []*VSA
	Encoder EncoderInterface
}

func (a Attribute) SetWire(b []byte) {
	a.Wire = b
}

func (a *Attribute) AddAVPair(vendorType uint8, value []byte) error {
	a.Pairs = append(a.Pairs, &VSA{VendorType: vendorType, Value: value})
	return nil
}

func (a *Attribute) Encode() error {
	if nil == a.Encoder {
		return errors.New("can't start encode: empty Encoder ")
	}
	return a.Encoder.Encode(a)
}

func (a *Attribute) Decode() error {
	if nil == a.Encoder {
		return errors.New("can't start decode: empty Encoder ")
	}
	return a.Encoder.Decode(a)
}

func MustNewAttribute(attributeType AttributeType, value interface{}) (a *Attribute) {
	var err error
	if a, err = NewAttribute(attributeType); err != nil || a == nil {
		return nil
	}
	a.Value = value

	return
}

func NewAttribute(attributeType AttributeType) (*Attribute, error) {
	attr := new(Attribute)
	var ok bool
	attr.Type = attributeType
	ai, ok := attrTypeToInfo[attr.Type]
	if !ok {
		return nil, fmt.Errorf("can't determine encoder by attribute type: %d", attr.Type)
	}
	attr.Encoder = ai.Encoder
	return attr, nil
}

//func (a AttrVendorSpec) String() string {
//	str := fmt.Sprintf("AttrType: %d, vendorId: %d, pairs: \n", a.Type, a.Value.(uint32))
//	for _, p := range a.Pairs {
//		str += fmt.Sprintf("\tVendorType: %d Value: %s\n", p.VendorType, p.Value)
//	}
//	return str
//}
//

func (a *Attribute) ValueString(v *string) error {
	var ok bool
	if *v, ok = a.Value.(string); !ok {
		return fmt.Errorf("can't cast value of attribute %s as string", a.Type)
	}
	return nil
}

func (a *Attribute) ValueUint32(v *uint32) error {
	var ok bool
	if *v, ok = a.Value.(uint32); !ok {
		return fmt.Errorf("can't cast value of attribute %s as uint32", a.Type)
	}
	return nil
}

func (a *Attribute) ValueIP(v *net.IP) error {
	var ok bool
	if *v, ok = a.Value.(net.IP); !ok {
		return fmt.Errorf("can't cast value of attribute %s as net.IP", a.Type)
	}
	return nil
}
