package layers

type EthernetType uint16

const (
	// EthernetTypeLLC is not an actual ethernet type.  It is instead a
	// placeholder we use in Ethernet frames that use the 802.3 standard of
	// srcmac|dstmac|length|LLC instead of srcmac|dstmac|ethertype.
	EthernetTypeLLC                         EthernetType = 0
	EthernetTypeIPv4                        EthernetType = 0x0800
	EthernetTypeARP                         EthernetType = 0x0806
	EthernetTypeIPv6                        EthernetType = 0x86DD
	EthernetTypeCiscoDiscovery              EthernetType = 0x2000
	EthernetTypeNortelDiscovery             EthernetType = 0x01a2
	EthernetTypeTransparentEthernetBridging EthernetType = 0x6558
	EthernetTypeDot1Q                       EthernetType = 0x8100
	EthernetTypePPP                         EthernetType = 0x880b
	EthernetTypePPPoEDiscovery              EthernetType = 0x8863
	EthernetTypePPPoESession                EthernetType = 0x8864
	EthernetTypeMPLSUnicast                 EthernetType = 0x8847
	EthernetTypeMPLSMulticast               EthernetType = 0x8848
	EthernetTypeEAPOL                       EthernetType = 0x888e
	EthernetTypeQinQ                        EthernetType = 0x88a8
	EthernetTypeLinkLayerDiscovery          EthernetType = 0x88cc
	EthernetTypeEthernetCTP                 EthernetType = 0x9000
)
