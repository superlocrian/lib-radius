package radius

type attrInfo struct {
	Encoder EncoderInterface
	Name    string
}

var attrTypeToInfo map[AttributeType]attrInfo

func init() {

	strEncoder := &EncoderString{}
	addrEncoder := &EncoderAddress{}
	uint32Encoder := &EncoderUint32{}
	vendorSpecEncoder := &EncoderVendorSpec{}
	tunnelEncoder := &EncoderTunnel{}

	attrTypeToInfo = make(map[AttributeType]attrInfo)
	attrTypeToInfo[Attr_VendorSpecific] = attrInfo{vendorSpecEncoder, "Vendor-Specific"}

	//string attrs
	attrTypeToInfo[Attr_UserName] = attrInfo{strEncoder, "User-Name"}
	attrTypeToInfo[Attr_UserPassword] = attrInfo{strEncoder, "User-Password"}
	attrTypeToInfo[Attr_CHAPPassword] = attrInfo{strEncoder, "CHAP-Password"}
	attrTypeToInfo[Attr_FilterId] = attrInfo{strEncoder, "Filter-Id"}
	attrTypeToInfo[Attr_ReplyMessage] = attrInfo{strEncoder, "Reply-Message"}
	attrTypeToInfo[Attr_CallbackNumber] = attrInfo{strEncoder, "Callback-Number"}
	attrTypeToInfo[Attr_CallbackId] = attrInfo{strEncoder, "Callback-Id"}
	attrTypeToInfo[Attr_FramedRoute] = attrInfo{strEncoder, ""}
	attrTypeToInfo[Attr_State] = attrInfo{strEncoder, "State"}
	attrTypeToInfo[Attr_Class] = attrInfo{strEncoder, "Class"}
	attrTypeToInfo[Attr_CalledStationId] = attrInfo{strEncoder, "Called-Station-Id"}
	attrTypeToInfo[Attr_CallingStationId] = attrInfo{strEncoder, "Calling-Station-Id"}
	attrTypeToInfo[Attr_NASIdentifier] = attrInfo{strEncoder, "NAS-Identifier"}
	attrTypeToInfo[Attr_ProxyState] = attrInfo{strEncoder, "Proxy-State"}
	attrTypeToInfo[Attr_LoginLATService] = attrInfo{strEncoder, "Login-LAT-Service"}
	attrTypeToInfo[Attr_LoginLATNode] = attrInfo{strEncoder, "Login-LAT-Node"}
	attrTypeToInfo[Attr_LoginLATGroup] = attrInfo{strEncoder, "Login-LAT-Group"}
	attrTypeToInfo[Attr_FramedAppleTalkZone] = attrInfo{strEncoder, "Framed-AppleTalk-Zone"}
	attrTypeToInfo[Attr_CHAPChallenge] = attrInfo{strEncoder, "CHAP-Challenge"}
	attrTypeToInfo[Attr_LoginLATPort] = attrInfo{strEncoder, "Login-LAT-Port"}
	attrTypeToInfo[Attr_AcctMultiSessionId] = attrInfo{strEncoder, "Acct-Multi-Session-Id"}
	attrTypeToInfo[Attr_AcctSessionId] = attrInfo{strEncoder, "Acct-Session-Id"}
	attrTypeToInfo[Attr_ConnectInfo] = attrInfo{strEncoder, "Connect-Info"}
	attrTypeToInfo[Attr_NASPortId] = attrInfo{strEncoder, "NAS-Port-Id"}

	//address attrs
	attrTypeToInfo[Attr_NASIPAddress] = attrInfo{addrEncoder, "NAS-IP-Address"}
	attrTypeToInfo[Attr_FramedIPAddress] = attrInfo{addrEncoder, "Framed-IP-Address"}
	attrTypeToInfo[Attr_FramedIPNetmask] = attrInfo{addrEncoder, "Framed-IP-Netmask"}
	attrTypeToInfo[Attr_LoginIPHost] = attrInfo{addrEncoder, "Login-IP-Host"}

	//int attrs
	attrTypeToInfo[Attr_NASPort] = attrInfo{uint32Encoder, "NAS-Port"}
	attrTypeToInfo[Attr_ServiceType] = attrInfo{uint32Encoder, "Service-Type"}
	attrTypeToInfo[Attr_FramedProtocol] = attrInfo{uint32Encoder, "Framed-Protocol"}
	attrTypeToInfo[Attr_FramedRouting] = attrInfo{uint32Encoder, "Framed-Routing"}
	attrTypeToInfo[Attr_FramedMTU] = attrInfo{uint32Encoder, "Framed-MTU"}
	attrTypeToInfo[Attr_FramedCompression] = attrInfo{uint32Encoder, "Framed-Compression"}
	attrTypeToInfo[Attr_LoginService] = attrInfo{uint32Encoder, "Login-Service"}
	attrTypeToInfo[Attr_LoginTCPPort] = attrInfo{uint32Encoder, "Login-TCP-Port"}
	attrTypeToInfo[Attr_FramedIPXNetwork] = attrInfo{uint32Encoder, "Framed-IP-X-Network"}
	attrTypeToInfo[Attr_SessionTimeout] = attrInfo{uint32Encoder, "Session-Timeout"}
	attrTypeToInfo[Attr_IdleTimeout] = attrInfo{uint32Encoder, "Idle-Timeout"}
	attrTypeToInfo[Attr_TerminationAction] = attrInfo{uint32Encoder, "Termination-Action"}
	attrTypeToInfo[Attr_FramedAppleTalkLink] = attrInfo{uint32Encoder, "Framed-AppleTalk-Link"}
	attrTypeToInfo[Attr_FramedAppleTalkNetwork] = attrInfo{uint32Encoder, "Framed-AppleTalk-Network"}
	attrTypeToInfo[Attr_NASPortType] = attrInfo{uint32Encoder, "NAS-Port-Type"}
	attrTypeToInfo[Attr_PortLimit] = attrInfo{uint32Encoder, "Port-Limit"}

	attrTypeToInfo[Attr_AcctStatusType] = attrInfo{uint32Encoder, "Acct-Status-Type"}
	attrTypeToInfo[Attr_AcctDelayTime] = attrInfo{uint32Encoder, "Acct-Delay-Time"}
	attrTypeToInfo[Attr_AcctInputOctets] = attrInfo{uint32Encoder, "Acct-Input-Octets"}
	attrTypeToInfo[Attr_AcctOutputOctets] = attrInfo{uint32Encoder, "Acct-Output-Octets"}

	attrTypeToInfo[Attr_AcctAuthentic] = attrInfo{uint32Encoder, "Acct-Authentic"}
	attrTypeToInfo[Attr_AcctSessionTime] = attrInfo{uint32Encoder, "Acct-Session-Time"}
	attrTypeToInfo[Attr_AcctInputPackets] = attrInfo{uint32Encoder, "Acct-Input-Packets"}
	attrTypeToInfo[Attr_AcctOutputPackets] = attrInfo{uint32Encoder, "Acct-Output-Packets"}
	attrTypeToInfo[Attr_AcctTerminateCause] = attrInfo{uint32Encoder, "Acct-Terminate-Cause"}
	attrTypeToInfo[Attr_AcctLinkCount] = attrInfo{uint32Encoder, "Acct-Link-Count"}

	attrTypeToInfo[Attr_AcctInputGigawords] = attrInfo{uint32Encoder, "Acct-Input-Gigawords"}
	attrTypeToInfo[Attr_AcctOutputGigawords] = attrInfo{uint32Encoder, "Acct-Output-Gigawords"}
	attrTypeToInfo[Attr_ErrorCause] = attrInfo{uint32Encoder, "Error-Cause"}

	//rfc 2867
	attrTypeToInfo[Attr_AcctTunnelConnection] = attrInfo{strEncoder, "Acct-Tunnel-Connection"}
	attrTypeToInfo[Attr_AcctTunnelPacketsLost] = attrInfo{uint32Encoder, "Acct-Tunnel-Packets-Lost"}

	//rfc 2868
	attrTypeToInfo[Attr_TunnelType] = attrInfo{tunnelEncoder, "Tunnel-Type"}
	attrTypeToInfo[Attr_TunnelMediumType] = attrInfo{tunnelEncoder, "Tunnel-Medium-Type"}
	attrTypeToInfo[Attr_TunnelClientEndpoint] = attrInfo{tunnelEncoder, "Tunnel-Client-Endpoint"}
	attrTypeToInfo[Attr_TunnelServerEndpoint] = attrInfo{tunnelEncoder, "Tunnel-Server-Endpoint"}
	attrTypeToInfo[Attr_TunnelPassword] = attrInfo{tunnelEncoder, "Tunnel-Password"}
	attrTypeToInfo[Attr_TunnelPrivateGroupID] = attrInfo{tunnelEncoder, "Tunnel-Private-Group-ID"}
	attrTypeToInfo[Attr_TunnelAssignmentID] = attrInfo{tunnelEncoder, "Tunnel-Assignment-ID"}
	attrTypeToInfo[Attr_TunnelPreference] = attrInfo{tunnelEncoder, "Tunnel-Preference"}

	attrTypeToInfo[Attr_EventTimestamp] = attrInfo{uint32Encoder, "Event-Timestamp"}

	attrTypeToInfo[Attr_ErrorCause] = attrInfo{uint32Encoder, "Error-Cause"}

	//rfc 5090
	attrTypeToInfo[Attr_DigestResponse] = attrInfo{strEncoder, "Digest-Response"}
	attrTypeToInfo[Attr_DigestRealm] = attrInfo{strEncoder, "Digest-Realm"}
	attrTypeToInfo[Attr_DigestNonce] = attrInfo{strEncoder, "Digest-Nonce"}
	attrTypeToInfo[Attr_DigestResponseAuth] = attrInfo{strEncoder, "Digest-Response-Auth"}
	attrTypeToInfo[Attr_DigestNextnonce] = attrInfo{strEncoder, "Digest-Nextnonce"}
	attrTypeToInfo[Attr_DigestMethod] = attrInfo{strEncoder, "Digest-Method"}
	attrTypeToInfo[Attr_DigestURI] = attrInfo{strEncoder, "Digest-URI"}
	attrTypeToInfo[Attr_DigestQop] = attrInfo{strEncoder, "Digest-Qop"}
	attrTypeToInfo[Attr_DigestAlgorithm] = attrInfo{strEncoder, "Digest-Algorithm"}
	attrTypeToInfo[Attr_DigestEntityBodyHash] = attrInfo{strEncoder, "Digest-Entity-Body-Hash"}
	attrTypeToInfo[Attr_DigestCNonce] = attrInfo{strEncoder, "Digest-CNonce"}
	attrTypeToInfo[Attr_DigestNonceCount] = attrInfo{strEncoder, "Digest-Nonce-Count"}
	attrTypeToInfo[Attr_DigestUsername] = attrInfo{strEncoder, "Digest-Username"}
	attrTypeToInfo[Attr_DigestOpaque] = attrInfo{strEncoder, "Digest-Opaque"}
	attrTypeToInfo[Attr_DigestAuthParam] = attrInfo{strEncoder, "Digest-Auth-Param"}
	attrTypeToInfo[Attr_DigestAKAAuts] = attrInfo{strEncoder, "Digest-AKA-Auts"}
	attrTypeToInfo[Attr_DigestDomain] = attrInfo{strEncoder, "Digest-Domain"}
	attrTypeToInfo[Attr_DigestStale] = attrInfo{strEncoder, "Digest-Stale"}
	attrTypeToInfo[Attr_DigestHA1] = attrInfo{strEncoder, "Digest-HA1"}
	attrTypeToInfo[Attr_SIPAOR] = attrInfo{strEncoder, "SIP-AOR"}

}
