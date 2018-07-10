package radius

const (
	Attr_AcctStatusType     AttributeType = 40
	Attr_AcctDelayTime      AttributeType = 41
	Attr_AcctInputOctets    AttributeType = 42
	Attr_AcctOutputOctets   AttributeType = 43
	Attr_AcctSessionId      AttributeType = 44
	Attr_AcctAuthentic      AttributeType = 45
	Attr_AcctSessionTime    AttributeType = 46
	Attr_AcctInputPackets   AttributeType = 47
	Attr_AcctOutputPackets  AttributeType = 48
	Attr_AcctTerminateCause AttributeType = 49
	Attr_AcctMultiSessionId AttributeType = 50
	Attr_AcctLinkCount      AttributeType = 51

	//values
	Attr_AcctStatusType_Value_Start         AttributeValue = 1
	Attr_AcctStatusType_Value_Stop          AttributeValue = 2
	Attr_AcctStatusType_Value_InterimUpdate AttributeValue = 3
	Attr_AcctStatusType_Value_AccountingOn  AttributeValue = 7
	Attr_AcctStatusType_Value_AccountingOff AttributeValue = 8

//9-14   Reserved for Tunnel Accounting
//15     Reserved for Failed
)
