package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var httpAPI = windows.NewLazySystemDLL("httpapi.dll")
var httpInitialize = httpAPI.NewProc("HttpInitialize")
var httpTerminate = httpAPI.NewProc("HttpTerminate")
var httpQuery = httpAPI.NewProc("HttpQueryServiceConfiguration")
var httpUpdate = httpAPI.NewProc("HttpUpdateServiceConfiguration")

type httpSNIKey struct {
	Address [128]byte
	Host    *uint16
}
type httpSSLParam struct {
	HashLen   uint32
	Hash      *byte
	AppID     [16]byte
	Store     *uint16
	CheckMode uint32
	Freshness uint32
	Timeout   uint32
	CTLID     *uint16
	CTLStore  *uint16
	Flags     uint32
}
type httpSNISet struct {
	Key   httpSNIKey
	Param httpSSLParam
}
type httpSNIQuery struct {
	Type  uint32
	Key   httpSNIKey
	Token uint32
}
type httpIPQuery struct {
	Type    uint32
	Address unsafe.Pointer
	Token   uint32
}
type httpIPSet struct {
	Address *[128]byte
	Param   httpSSLParam
}

func initHTTPConfig() error {
	code, _, _ := httpInitialize.Call(2, 2, 0)
	if code != 0 {
		return fmt.Errorf("HttpInitialize: %w", syscall.Errno(code))
	}
	return nil
}

func queryHTTPConfig(id uintptr, query unsafe.Pointer, size uintptr) ([]byte, error) {
	var required uint32
	code, _, _ := httpQuery.Call(0, id, uintptr(query), size, 0, 0, uintptr(unsafe.Pointer(&required)), 0)
	if code != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
		return nil, fmt.Errorf("HttpQueryServiceConfiguration: %w", syscall.Errno(code))
	}
	buf := make([]byte, required)
	code, _, _ = httpQuery.Call(0, id, uintptr(query), size, uintptr(unsafe.Pointer(&buf[0])), uintptr(required), uintptr(unsafe.Pointer(&required)), 0)
	if code != 0 {
		return nil, fmt.Errorf("HttpQueryServiceConfiguration: %w", syscall.Errno(code))
	}
	return buf, nil
}

func stringValue(p *uint16) *string {
	if p == nil {
		return nil
	}
	s := windows.UTF16PtrToString(p)
	return &s
}

func readSNI(host string, port uint16) (iisRecord, error) {
	name, err := windows.UTF16PtrFromString(host)
	if err != nil {
		return iisRecord{}, err
	}
	q := httpSNIQuery{Key: httpSNIKey{Host: name}}
	// 与 spike 一致：HTTP.sys SNI key 使用 AF_INET 的通配地址。
	q.Key.Address[0] = windows.AF_INET
	binary.BigEndian.PutUint16(q.Key.Address[2:4], port)
	buf, err := queryHTTPConfig(5, unsafe.Pointer(&q), unsafe.Sizeof(q))
	runtime.KeepAlive(name)
	if err != nil {
		return iisRecord{}, err
	}
	s := (*httpSNISet)(unsafe.Pointer(&buf[0]))
	p := s.Param
	r := iisRecord{Address: s.Key.Address, Hostname: windows.UTF16PtrToString(s.Key.Host), Hash: append([]byte(nil), unsafe.Slice(p.Hash, p.HashLen)...), Store: stringValue(p.Store), AppID: p.AppID, CheckMode: p.CheckMode, Freshness: p.Freshness, Timeout: p.Timeout, CTLID: stringValue(p.CTLID), CTLStore: stringValue(p.CTLStore), DefaultFlags: p.Flags}
	runtime.KeepAlive(buf)
	return r, nil
}

func updateSNI(r iisRecord) error {
	host, err := windows.UTF16PtrFromString(r.Hostname)
	if err != nil {
		return err
	}
	ptr := func(s *string) (*uint16, error) {
		if s == nil {
			return nil, nil
		}
		return windows.UTF16PtrFromString(*s)
	}
	store, err := ptr(r.Store)
	if err != nil {
		return err
	}
	ctlID, err := ptr(r.CTLID)
	if err != nil {
		return err
	}
	ctlStore, err := ptr(r.CTLStore)
	if err != nil {
		return err
	}
	s := httpSNISet{Key: httpSNIKey{Address: r.Address, Host: host}, Param: httpSSLParam{HashLen: uint32(len(r.Hash)), Hash: unsafe.SliceData(r.Hash), AppID: r.AppID, Store: store, CheckMode: r.CheckMode, Freshness: r.Freshness, Timeout: r.Timeout, CTLID: ctlID, CTLStore: ctlStore, Flags: r.DefaultFlags}}
	code, _, _ := httpUpdate.Call(0, 5, uintptr(unsafe.Pointer(&s)), unsafe.Sizeof(s), 0)
	runtime.KeepAlive(s)
	runtime.KeepAlive(r)
	if code != 0 {
		return fmt.Errorf("HttpUpdateServiceConfiguration: %w", syscall.Errno(code))
	}
	return nil
}

func readIPMappings() ([]iisIPMapping, error) {
	out := []iisIPMapping{}
	for token := uint32(0); ; token++ {
		q := httpIPQuery{Type: 1, Token: token}
		buf, err := queryHTTPConfig(1, unsafe.Pointer(&q), unsafe.Sizeof(q))
		if err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
				return out, nil
			}
			return nil, err
		}
		s := (*httpIPSet)(unsafe.Pointer(&buf[0]))
		addr := s.Address
		port := binary.BigEndian.Uint16(addr[2:4])
		var ip net.IP
		switch binary.LittleEndian.Uint16(addr[:2]) {
		case windows.AF_INET:
			ip = append(net.IP(nil), addr[4:8]...)
		case windows.AF_INET6:
			ip = append(net.IP(nil), addr[8:24]...)
		default:
			return nil, fmt.Errorf("unsupported HTTP.sys socket family")
		}
		out = append(out, iisIPMapping{IP: ip, Port: port})
		runtime.KeepAlive(buf)
	}
}
