package radius

const (
	//rfc 2865
	Code_AccessRequest      PacketType = 1
	Code_AccessAccept       PacketType = 2
	Code_AccessReject       PacketType = 3
	Code_AccountingRequest  PacketType = 4
	Code_AccountingResponse PacketType = 5
	Code_AccessChallenge    PacketType = 11
	Code_StatusServer       PacketType = 12
	Code_StatusClient       PacketType = 13

	Code_Reserved PacketType = 255

	MaxPacketLength = 4096
	MinPacketLength = 20

	//attributes
	Attr_UserName          AttributeType = 1
	Attr_UserPassword      AttributeType = 2
	Attr_CHAPPassword      AttributeType = 3
	Attr_NASIPAddress      AttributeType = 4
	Attr_NASPort           AttributeType = 5
	Attr_ServiceType       AttributeType = 6
	Attr_FramedProtocol    AttributeType = 7
	Attr_FramedIPAddress   AttributeType = 8
	Attr_FramedIPNetmask   AttributeType = 9
	Attr_FramedRouting     AttributeType = 10
	Attr_FilterId          AttributeType = 11
	Attr_FramedMTU         AttributeType = 12
	Attr_FramedCompression AttributeType = 13
	Attr_LoginIPHost       AttributeType = 14
	Attr_LoginService      AttributeType = 15
	Attr_LoginTCPPort      AttributeType = 16
	//(unassigned)				AttributeType =  17
	Attr_ReplyMessage   AttributeType = 18
	Attr_CallbackNumber AttributeType = 19
	Attr_CallbackId     AttributeType = 20
	//(unassigned)				AttributeType =  21
	Attr_FramedRoute            AttributeType = 22
	Attr_FramedIPXNetwork       AttributeType = 23
	Attr_State                  AttributeType = 24
	Attr_Class                  AttributeType = 25
	Attr_VendorSpecific         AttributeType = 26
	Attr_SessionTimeout         AttributeType = 27
	Attr_IdleTimeout            AttributeType = 28
	Attr_TerminationAction      AttributeType = 29
	Attr_CalledStationId        AttributeType = 30
	Attr_CallingStationId       AttributeType = 31
	Attr_NASIdentifier          AttributeType = 32
	Attr_ProxyState             AttributeType = 33
	Attr_LoginLATService        AttributeType = 34
	Attr_LoginLATNode           AttributeType = 35
	Attr_LoginLATGroup          AttributeType = 36
	Attr_FramedAppleTalkLink    AttributeType = 37
	Attr_FramedAppleTalkNetwork AttributeType = 38
	Attr_FramedAppleTalkZone    AttributeType = 39
	//(reserved for accounting)	AttributeType =  40-59

	Attr_CHAPChallenge AttributeType = 60
	Attr_NASPortType   AttributeType = 61
	Attr_PortLimit     AttributeType = 62
	Attr_LoginLATPort  AttributeType = 63
)
