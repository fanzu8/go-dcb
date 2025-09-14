package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"github.com/mdlayher/netlink"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

var log *logrus.Logger

func init() {
	log = logrus.New()
	log.SetFormatter(&logrus.TextFormatter{
		DisableColors:   true,
		ForceQuote:      true,
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02T15:04:05.000000000Z07:00", // rfc3339NanoFixed
		DisableSorting:  false,
	})
	log.SetOutput(os.Stdout)
	log.SetLevel(logrus.InfoLevel)
	log.SetReportCaller(true)
}

const (
	// https://github.com/torvalds/linux/blob/v5.10/include/uapi/linux/dcbnl.h#L293
	DCB_CMD_IEEE_GET = 21

	// https://github.com/torvalds/linux/blob/v5.10/include/uapi/linux/dcbnl.h#L372
	DCB_ATTR_IFNAME        = 1
	DCB_ATTR_IEEE_PFC      = 2
	DCB_ATTR_IEEE_PEER_PFC = 5
	DCB_ATTR_IEEE          = 13

	// https://github.com/torvalds/linux/blob/v5.10/include/uapi/linux/dcbnl.h#L27
	/* IEEE 802.1Qaz std supported values */
	IEEE_8021QAZ_MAX_TCS = 8
)

// https://github.com/torvalds/linux/blob/v5.10/include/uapi/linux/dcbnl.h#L157
type ieeePFC struct { // struct ieee_pfc
	PFCCap      uint8
	PFCEn       uint8
	MBC         uint8
	Delay       uint16
	_pad        [3]uint8
	Requests    [IEEE_8021QAZ_MAX_TCS]uint64 // count of the sent pfc frames
	Indications [IEEE_8021QAZ_MAX_TCS]uint64 // count of the received pfc frames
}

// https://github.com/torvalds/linux/blob/v5.10/include/uapi/linux/dcbnl.h#L264
type dcbMsg struct { // struct dcbmsg
	family uint8
	cmd    uint8
	_pad   uint16
}

func (m *dcbMsg) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, m); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("usage: %s <ifname>\n", os.Args[0])
		os.Exit(1)
	}
	ifname := os.Args[1]

	c, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		log.Fatalf("netlink dial: %v", err)
	}
	defer c.Close()

	dcbmsg := &dcbMsg{
		family: unix.AF_UNSPEC,
		cmd:    uint8(DCB_CMD_IEEE_GET),
	}
	dcbmsgb, err := dcbmsg.MarshalBinary()
	if err != nil {
		log.Fatalf("marshal dcbmsg: %v", err)
	}

	ae := netlink.NewAttributeEncoder()
	ae.String(DCB_ATTR_IFNAME, ifname)
	attrs, err := ae.Encode()
	if err != nil {
		log.Fatalf("encode attributes: %v", err)
	}

	req := netlink.Message{
		Header: netlink.Header{
			Type:  unix.RTM_GETDCB,
			Flags: netlink.Request | netlink.Acknowledge,
		},
		Data: append(dcbmsgb, attrs...),
	}

	msgs, err := c.Execute(req)
	if err != nil {
		var opErr *netlink.OpError
		if errors.As(err, &opErr) {
			if errors.Is(opErr.Err, unix.ENODEV) ||
				// virtual iface, such as bond, lo etc.
				errors.Is(opErr.Err, unix.EOPNOTSUPP) {
				log.Warnf("ifname: %v, get ieee pfc: %v", ifname, opErr.Error())
			}
		}
		log.Fatalf("ifname: %v, get ieee pfc: %v", ifname, err)
	}

	for _, m := range msgs {
		if len(m.Data) <= len(dcbmsgb) {
			log.Infof("invalid dcbmsg length: %d", len(m.Data))
			continue
		}

		ad, err := netlink.NewAttributeDecoder(m.Data[len(dcbmsgb):])
		if err != nil {
			log.Fatalf("decode top-level attributes: %v", err)
		}
		for ad.Next() {
			switch ad.Type() {
			case DCB_ATTR_IFNAME:
				fmt.Printf("ifname: %s\n", ad.String())
			case DCB_ATTR_IEEE:
				ad.Nested(func(nad *netlink.AttributeDecoder) error {
					for nad.Next() {
						switch nad.Type() {
						case DCB_ATTR_IEEE_PFC:
							ieeepfc, err := parseIEEEPFC(nad.Bytes())
							if err != nil {
								log.Fatalf("parse ieee pfc: %v", err)
							}
							fmt.Printf("ieee pfc: %+v\n", ieeepfc)
						case DCB_ATTR_IEEE_PEER_PFC:
							// TODO: support peer pfc
						}
					}
					return nil
				})
			}
		}
	}
}

func parseIEEEPFC(b []byte) (*ieeePFC, error) {
	pad := 3
	if len(b) < 1+1+1+2+pad+IEEE_8021QAZ_MAX_TCS*8*2 {
		return nil, fmt.Errorf("invalid struct ieee_pfc length %d", len(b))
	}

	p := &ieeePFC{
		PFCCap: b[0],
		PFCEn:  b[1],
		MBC:    b[2],
		Delay:  binary.BigEndian.Uint16(b[3:5]),
	}

	off := 1 + 1 + 1 + 2 + pad
	for i := 0; i < IEEE_8021QAZ_MAX_TCS; i++ {
		p.Requests[i] = binary.BigEndian.Uint64(b[off : off+8])
		off += 8
	}
	for i := 0; i < IEEE_8021QAZ_MAX_TCS; i++ {
		p.Indications[i] = binary.BigEndian.Uint64(b[off : off+8])
		off += 8
	}

	return p, nil
}

