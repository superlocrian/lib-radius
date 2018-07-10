package radius

const (
	Attr_DigestResponse       AttributeType = 103 // Digest-Response
	Attr_DigestRealm          AttributeType = 104 // Digest-Realm
	Attr_DigestNonce          AttributeType = 105 // Digest-Nonce
	Attr_DigestResponseAuth   AttributeType = 106 // Digest-Response-Auth [1][2]
	Attr_DigestNextnonce      AttributeType = 107 // Digest-Nextnonce
	Attr_DigestMethod         AttributeType = 108 // Digest-Method
	Attr_DigestURI            AttributeType = 109 // Digest-URI
	Attr_DigestQop            AttributeType = 110 // Digest-Qop
	Attr_DigestAlgorithm      AttributeType = 111 // Digest-Algorithm [3]
	Attr_DigestEntityBodyHash AttributeType = 112 // Digest-Entity-Body-Hash
	Attr_DigestCNonce         AttributeType = 113 // Digest-CNonce
	Attr_DigestNonceCount     AttributeType = 114 // Digest-Nonce-Count
	Attr_DigestUsername       AttributeType = 115 // Digest-Username
	Attr_DigestOpaque         AttributeType = 116 // Digest-Opaque
	Attr_DigestAuthParam      AttributeType = 117 // Digest-Auth-Param
	Attr_DigestAKAAuts        AttributeType = 118 // Digest-AKA-Auts
	Attr_DigestDomain         AttributeType = 119 // Digest-Domain
	Attr_DigestStale          AttributeType = 120 // Digest-Stale
	Attr_DigestHA1            AttributeType = 121 // Digest-HA1 [1][2]
	Attr_SIPAOR               AttributeType = 122 // SIP-AOR
)
