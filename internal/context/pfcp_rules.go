package context

import (
	"github.com/free5gc/pfcp/pfcpType"
)

const (
	RULE_INITIAL RuleState = 0
	RULE_CREATE  RuleState = 1
	RULE_UPDATE  RuleState = 2
	RULE_REMOVE  RuleState = 3
)

type RuleState uint8

// Packet Detection Rule. Table 7.5.2.2-1
type PDR struct {
	PDRID uint16

	Precedence         uint32
	PDI                PDI
	OuterHeaderRemoval *pfcpType.OuterHeaderRemoval

	FAR *FAR
	URR *URR
	QER []*QER

	State RuleState
}

// Packet Detection. 7.5.2.2-2
type PDI struct {
	SourceInterface               pfcpType.SourceInterface
	LocalFTeid                    *pfcpType.FTEID
	NetworkInstance               *pfcpType.NetworkInstance
	UEIPAddress                   *pfcpType.UEIPAddress
	SDFFilter                     *pfcpType.SDFFilter
	EthernetPDUSessionInformation *pfcpType.EthernetPDUSessionInformation
	EthernetPacketFiliter         *EthernetPacketFilter
	ApplicationID                 string
}

// Ethernet Packet Filter 7.5.2.2-3
type EthernetPacketFilter struct {
	EthernetFilterID         *pfcpType.EthernetFilterID         `tlv:"138"`
	EthernetFilterProperties *pfcpType.EthernetFilterProperties `tlv:"139"`
	MACAddress               *pfcpType.MACAddress               `tlv:"133"`
	Ethertype                *pfcpType.Ethertype                `tlv:"136"`
	CTAG                     *pfcpType.CTAG                     `tlv:"134"`
	STAG                     *pfcpType.STAG                     `tlv:"135"`
	SDFFilter                *pfcpType.SDFFilter                `tlv:"23"`
}

// Forwarding Action Rule. 7.5.2.3-1
type FAR struct {
	FARID uint32

	ApplyAction          pfcpType.ApplyAction
	ForwardingParameters *ForwardingParameters

	BAR   *BAR
	State RuleState
}

// Forwarding Parameters. 7.5.2.3-2
type ForwardingParameters struct {
	DestinationInterface pfcpType.DestinationInterface
	NetworkInstance      *pfcpType.NetworkInstance
	OuterHeaderCreation  *pfcpType.OuterHeaderCreation
	ForwardingPolicyID   string
}

// Buffering Action Rule 7.5.2.6-1
type BAR struct {
	BARID uint8

	DownlinkDataNotificationDelay  pfcpType.DownlinkDataNotificationDelay
	SuggestedBufferingPacketsCount pfcpType.SuggestedBufferingPacketsCount

	State RuleState
}

// QoS Enhancement Rule
type QER struct {
	QERID uint32

	QFI pfcpType.QFI

	GateStatus *pfcpType.GateStatus
	MBR        *pfcpType.MBR
	GBR        *pfcpType.GBR

	State RuleState
}

// Usage Report Rule
type URR struct{}
