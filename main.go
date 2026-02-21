package main

import (
    "encoding/binary"
    "flag"
    "log"
    "net"
    "sync"
    "time"
)

const (
    protocolVersion    = 1
    fixedHeaderSize    = 16
    securityHeaderSize = 12
    authTagSize        = 16
)

const (
    pktAudio       = 0x01
    pktPttOn       = 0x02
    pktPttOff      = 0x03
    pktKeepalive   = 0x04
    pktJoin        = 0x05
    pktLeave       = 0x06
    pktTalkGrant   = 0x07
    pktTalkRelease = 0x08
    pktTalkDeny    = 0x09
    pktKeyExchange = 0x0A
    pktCodecConfig = 0x0B
    pktFec         = 0x0C
)

type packetHeader struct {
    Version   uint8
    Type      uint8
    HeaderLen uint16
    ChannelId uint32
    SenderId  uint32
    Seq       uint16
    Flags     uint16
}

type securityHeader struct {
    Nonce uint64
    KeyId uint32
}

type parsedPacket struct {
    Header  packetHeader
    Sec     securityHeader
    Payload []byte
    Tag     []byte
    Raw     []byte
}

type peer struct {
    addr     *net.UDPAddr
    lastSeen time.Time
}

type channel struct {
    peers       map[uint32]*peer
    currentTalk uint32
}

type server struct {
    mu       sync.Mutex
    channels map[uint32]*channel
    conn     *net.UDPConn
    noCrypto bool
    logPackets bool
    logAudio   bool
}

func newServer(conn *net.UDPConn, noCrypto bool, logPackets bool, logAudio bool) *server {
    return &server{
        channels: make(map[uint32]*channel),
        conn:     conn,
        noCrypto: noCrypto,
        logPackets: logPackets,
        logAudio: logAudio,
    }
}

func (s *server) run() {
    buf := make([]byte, 2048)
    for {
        n, addr, err := s.conn.ReadFromUDP(buf)
        if err != nil {
            log.Printf("read error: %v", err)
            continue
        }

        data := make([]byte, n)
        copy(data, buf[:n])

        pkt, ok := parsePacket(data, s.noCrypto)
        if !ok {
            continue
        }

        if s.logPackets {
            s.logPacket(pkt, addr, n)
        }

        s.handlePacket(pkt, addr)
    }
}

func (s *server) handlePacket(pkt parsedPacket, addr *net.UDPAddr) {
    if pkt.Header.Version != protocolVersion {
        return
    }

    s.mu.Lock()
    ch := s.getOrCreateChannel(pkt.Header.ChannelId)
    s.upsertPeer(ch, pkt.Header.SenderId, addr)
    s.mu.Unlock()

    switch pkt.Header.Type {
    case pktJoin:
        log.Printf("join ch=%d sender=%d from=%s", pkt.Header.ChannelId, pkt.Header.SenderId, addr.String())
        s.broadcastExcept(pkt.Header.ChannelId, pkt.Header.SenderId, pkt.Raw)
        s.sendTo(pkt.Header.ChannelId, pkt.Header.SenderId, pkt.Raw)
    case pktLeave:
        log.Printf("leave ch=%d sender=%d from=%s", pkt.Header.ChannelId, pkt.Header.SenderId, addr.String())
        s.removePeer(pkt.Header.ChannelId, pkt.Header.SenderId)
        s.broadcastExcept(pkt.Header.ChannelId, pkt.Header.SenderId, pkt.Raw)
        s.releaseTalkIfNeeded(pkt.Header.ChannelId, pkt.Header.SenderId)
    case pktPttOn:
        log.Printf("ptt_on ch=%d sender=%d from=%s", pkt.Header.ChannelId, pkt.Header.SenderId, addr.String())
        s.handlePttOn(pkt.Header.ChannelId, pkt.Header.SenderId)
    case pktPttOff:
        log.Printf("ptt_off ch=%d sender=%d from=%s", pkt.Header.ChannelId, pkt.Header.SenderId, addr.String())
        s.handlePttOff(pkt.Header.ChannelId, pkt.Header.SenderId)
    case pktAudio:
        if s.isTalker(pkt.Header.ChannelId, pkt.Header.SenderId) {
            s.broadcastExcept(pkt.Header.ChannelId, pkt.Header.SenderId, pkt.Raw)
        }
    default:
        s.broadcastExcept(pkt.Header.ChannelId, pkt.Header.SenderId, pkt.Raw)
    }
}

func (s *server) getOrCreateChannel(channelId uint32) *channel {
    ch, ok := s.channels[channelId]
    if !ok {
        ch = &channel{peers: make(map[uint32]*peer)}
        s.channels[channelId] = ch
    }
    return ch
}

func (s *server) upsertPeer(ch *channel, senderId uint32, addr *net.UDPAddr) {
    p, ok := ch.peers[senderId]
    if !ok {
        p = &peer{addr: addr}
        ch.peers[senderId] = p
    }
    p.addr = addr
    p.lastSeen = time.Now()
}

func (s *server) removePeer(channelId uint32, senderId uint32) {
    s.mu.Lock()
    defer s.mu.Unlock()

    ch := s.channels[channelId]
    if ch == nil {
        return
    }
    delete(ch.peers, senderId)
    if len(ch.peers) == 0 {
        delete(s.channels, channelId)
    }
}

func (s *server) isTalker(channelId uint32, senderId uint32) bool {
    s.mu.Lock()
    defer s.mu.Unlock()

    ch := s.channels[channelId]
    if ch == nil {
        return false
    }
    return ch.currentTalk == senderId
}

func (s *server) handlePttOn(channelId uint32, senderId uint32) {
    s.mu.Lock()
    ch := s.channels[channelId]
    if ch == nil {
        s.mu.Unlock()
        return
    }

    if ch.currentTalk == 0 || ch.currentTalk == senderId {
        ch.currentTalk = senderId
        s.mu.Unlock()
        log.Printf("talk_grant ch=%d talker=%d", channelId, senderId)
        s.broadcast(channelId, buildTalkPacket(pktTalkGrant, channelId, senderId, s.noCrypto))
        return
    }
    s.mu.Unlock()
    log.Printf("talk_deny ch=%d requester=%d current=%d", channelId, senderId, ch.currentTalk)
    s.sendTo(channelId, senderId, buildTalkPacket(pktTalkDeny, channelId, ch.currentTalk, s.noCrypto))
}

func (s *server) handlePttOff(channelId uint32, senderId uint32) {
    s.mu.Lock()
    ch := s.channels[channelId]
    if ch == nil || ch.currentTalk != senderId {
        s.mu.Unlock()
        return
    }

    ch.currentTalk = 0
    s.mu.Unlock()
    log.Printf("talk_release ch=%d talker=%d", channelId, senderId)
    s.broadcast(channelId, buildTalkPacket(pktTalkRelease, channelId, senderId, s.noCrypto))
}

func (s *server) releaseTalkIfNeeded(channelId uint32, senderId uint32) {
    s.mu.Lock()
    ch := s.channels[channelId]
    if ch == nil || ch.currentTalk != senderId {
        s.mu.Unlock()
        return
    }

    ch.currentTalk = 0
    s.mu.Unlock()
    log.Printf("talk_release ch=%d talker=%d (timeout)", channelId, senderId)
    s.broadcast(channelId, buildTalkPacket(pktTalkRelease, channelId, senderId, s.noCrypto))
}

func (s *server) broadcast(channelId uint32, data []byte) {
    s.mu.Lock()
    ch := s.channels[channelId]
    if ch == nil {
        s.mu.Unlock()
        return
    }

    peers := make([]*peer, 0, len(ch.peers))
    for _, p := range ch.peers {
        peers = append(peers, p)
    }
    s.mu.Unlock()

    for _, p := range peers {
        s.conn.WriteToUDP(data, p.addr)
    }
}

func (s *server) broadcastExcept(channelId uint32, senderId uint32, data []byte) {
    s.mu.Lock()
    ch := s.channels[channelId]
    if ch == nil {
        s.mu.Unlock()
        return
    }

    peers := make([]*peer, 0, len(ch.peers))
    for id, p := range ch.peers {
        if id == senderId {
            continue
        }
        peers = append(peers, p)
    }
    s.mu.Unlock()

    for _, p := range peers {
        s.conn.WriteToUDP(data, p.addr)
    }
}

func (s *server) sendTo(channelId uint32, senderId uint32, data []byte) {
    s.mu.Lock()
    ch := s.channels[channelId]
    if ch == nil {
        s.mu.Unlock()
        return
    }

    p := ch.peers[senderId]
    s.mu.Unlock()

    if p != nil {
        s.conn.WriteToUDP(data, p.addr)
    }
}

func (s *server) cleanupLoop(timeout time.Duration) {
    ticker := time.NewTicker(timeout / 2)
    defer ticker.Stop()

    for range ticker.C {
        now := time.Now()

        s.mu.Lock()
        for channelId, ch := range s.channels {
            for id, p := range ch.peers {
                if now.Sub(p.lastSeen) > timeout {
                    delete(ch.peers, id)
                    if ch.currentTalk == id {
                        ch.currentTalk = 0
                        s.mu.Unlock()
                        s.broadcast(channelId, buildTalkPacket(pktTalkRelease, channelId, id, s.noCrypto))
                        s.mu.Lock()
                    }
                }
            }
            if len(ch.peers) == 0 {
                delete(s.channels, channelId)
            }
        }
        s.mu.Unlock()
    }
}

func (s *server) logPacket(pkt parsedPacket, addr *net.UDPAddr, size int) {
    if pkt.Header.Type == pktAudio && !s.logAudio {
        return
    }
    log.Printf("rx type=%s ch=%d sender=%d seq=%d hlen=%d key=%d nonce=%d from=%s size=%d",
        pktTypeName(pkt.Header.Type),
        pkt.Header.ChannelId,
        pkt.Header.SenderId,
        pkt.Header.Seq,
        pkt.Header.HeaderLen,
        pkt.Sec.KeyId,
        pkt.Sec.Nonce,
        addr.String(),
        size)
}

func pktTypeName(t uint8) string {
    switch t {
    case pktAudio:
        return "audio"
    case pktPttOn:
        return "ptt_on"
    case pktPttOff:
        return "ptt_off"
    case pktKeepalive:
        return "keepalive"
    case pktJoin:
        return "join"
    case pktLeave:
        return "leave"
    case pktTalkGrant:
        return "talk_grant"
    case pktTalkRelease:
        return "talk_release"
    case pktTalkDeny:
        return "talk_deny"
    case pktKeyExchange:
        return "key_exchange"
    case pktCodecConfig:
        return "codec_config"
    case pktFec:
        return "fec"
    default:
        return "unknown"
    }
}

func parsePacket(data []byte, noCrypto bool) (parsedPacket, bool) {
    if len(data) < fixedHeaderSize {
        return parsedPacket{}, false
    }

    header := packetHeader{}
    header.Version = data[0]
    header.Type = data[1]
    header.HeaderLen = binary.BigEndian.Uint16(data[2:4])
    header.ChannelId = binary.BigEndian.Uint32(data[4:8])
    header.SenderId = binary.BigEndian.Uint32(data[8:12])
    header.Seq = binary.BigEndian.Uint16(data[12:14])
    header.Flags = binary.BigEndian.Uint16(data[14:16])

    if len(data) >= fixedHeaderSize+securityHeaderSize+authTagSize &&
        header.HeaderLen >= fixedHeaderSize+securityHeaderSize {
        sec := securityHeader{}
        sec.Nonce = binary.BigEndian.Uint64(data[16:24])
        sec.KeyId = binary.BigEndian.Uint32(data[24:28])

        payloadOffset := fixedHeaderSize + securityHeaderSize
        payloadLen := len(data) - payloadOffset - authTagSize
        if payloadLen < 0 {
            return parsedPacket{}, false
        }

        payload := make([]byte, payloadLen)
        copy(payload, data[payloadOffset:payloadOffset+payloadLen])

        tag := make([]byte, authTagSize)
        copy(tag, data[payloadOffset+payloadLen:])

        return parsedPacket{
            Header:  header,
            Sec:     sec,
            Payload: payload,
            Tag:     tag,
            Raw:     data,
        }, true
    }

    if !noCrypto {
        return parsedPacket{}, false
    }

    payloadOffset := fixedHeaderSize
    payloadLen := len(data) - payloadOffset
    if payloadLen < 0 {
        return parsedPacket{}, false
    }

    payload := make([]byte, payloadLen)
    copy(payload, data[payloadOffset:])

    return parsedPacket{
        Header:  header,
        Payload: payload,
        Tag:     nil,
        Raw:     data,
    }, true
}

func buildTalkPacket(pktType uint8, channelId uint32, talkerId uint32, noCrypto bool) []byte {
    payload := make([]byte, 4)
    binary.BigEndian.PutUint32(payload, talkerId)

    header := make([]byte, fixedHeaderSize)
    header[0] = protocolVersion
    header[1] = pktType
    headerLen := fixedHeaderSize
    if !noCrypto {
        headerLen = fixedHeaderSize + securityHeaderSize
    }
    binary.BigEndian.PutUint16(header[2:4], uint16(headerLen))
    binary.BigEndian.PutUint32(header[4:8], channelId)
    binary.BigEndian.PutUint32(header[8:12], talkerId)
    binary.BigEndian.PutUint16(header[12:14], 0)
    binary.BigEndian.PutUint16(header[14:16], 0)

    if noCrypto {
        packet := make([]byte, 0, len(header)+len(payload))
        packet = append(packet, header...)
        packet = append(packet, payload...)
        return packet
    }

    sec := make([]byte, securityHeaderSize)
    tag := make([]byte, authTagSize)

    packet := make([]byte, 0, len(header)+len(sec)+len(payload)+len(tag))
    packet = append(packet, header...)
    packet = append(packet, sec...)
    packet = append(packet, payload...)
    packet = append(packet, tag...)
    return packet
}

func main() {
    port := flag.Int("port", 50000, "UDP listen port")
    timeout := flag.Duration("timeout", 30*time.Second, "peer timeout")
    noCrypto := flag.Bool("no-crypto", false, "accept/send packets without security header/tag")
    logPackets := flag.Bool("log-packets", false, "log received packets")
    logAudio := flag.Bool("log-audio", false, "log audio packets too (requires -log-packets)")
    flag.Parse()

    addr := &net.UDPAddr{Port: *port}
    conn, err := net.ListenUDP("udp", addr)
    if err != nil {
        log.Fatalf("listen error: %v", err)
    }
    defer conn.Close()

    mode := "encrypted"
    if *noCrypto {
        mode = "no-crypto"
    }
    log.Printf("IncomUdon relay listening on udp :%d (%s)", *port, mode)

    if *logAudio {
        *logPackets = true
    }
    srv := newServer(conn, *noCrypto, *logPackets, *logAudio)
    go srv.cleanupLoop(*timeout)
    srv.run()
}
