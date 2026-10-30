package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func openMachineStore(name string, readOnly bool) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	flags := uint32(windows.CERT_SYSTEM_STORE_LOCAL_MACHINE | windows.CERT_STORE_OPEN_EXISTING_FLAG)
	if readOnly {
		flags |= windows.CERT_STORE_READONLY_FLAG
	}
	h, err := windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM_W, 0, 0, flags, uintptr(unsafe.Pointer(p)))
	runtime.KeepAlive(p)
	return h, err
}

func certificateDER(ctx *windows.CertContext) (*x509.Certificate, error) {
	return x509.ParseCertificate(append([]byte(nil), unsafe.Slice(ctx.EncodedCert, ctx.Length)...))
}

func certificateKey(ctx *windows.CertContext) error {
	var key windows.Handle
	var spec uint32
	var free bool
	err := windows.CryptAcquireCertificatePrivateKey(ctx, windows.CRYPT_ACQUIRE_CACHE_FLAG|windows.CRYPT_ACQUIRE_NO_HEALING|windows.CRYPT_ACQUIRE_SILENT_FLAG|windows.CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG, nil, &key, &spec, &free)
	if err != nil {
		return err
	}
	if free {
		if spec == 0xffffffff {
			code, _, _ := windows.NewLazySystemDLL("ncrypt.dll").NewProc("NCryptFreeObject").Call(uintptr(key))
			if code != 0 {
				return fmt.Errorf("NCryptFreeObject: 0x%x", code)
			}
		} else if err := windows.CryptReleaseContext(key, 0); err != nil {
			return err
		}
	}
	return nil
}

func storedCertificate(store string, hash []byte) (*x509.Certificate, error) {
	h, err := openMachineStore(store, true)
	if err != nil {
		return nil, err
	}
	defer windows.CertCloseStore(h, 0)
	blob := windows.CryptHashBlob{Size: uint32(len(hash)), Data: unsafe.SliceData(hash)}
	ctx, err := windows.CertFindCertificateInStore(h, windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING, 0, windows.CERT_FIND_SHA1_HASH, unsafe.Pointer(&blob), nil)
	if err != nil {
		return nil, err
	}
	defer windows.CertFreeCertificateContext(ctx)
	if err := certificateKey(ctx); err != nil {
		return nil, fmt.Errorf("certificate private key unavailable: %w", err)
	}
	return certificateDER(ctx)
}

func iisCertificateResult(cert *x509.Certificate, store string, changed bool) *iisResult {
	h1 := sha1.Sum(cert.Raw)
	h256 := sha256.Sum256(cert.Raw)
	return &iisResult{ThumbprintSha1: hex.EncodeToString(h1[:]), FingerprintSha256: hex.EncodeToString(h256[:]), CertificateStore: store, Changed: changed}
}

func iisCertificateSummary(cert *x509.Certificate) *certSummary {
	names := cert.DNSNames
	if len(names) == 0 {
		names = []string{}
		if cert.Subject.CommonName != "" {
			names = append(names, cert.Subject.CommonName)
		}
	}
	return &certSummary{SubjectAltNames: names, Issuer: issuerName(cert), NotAfter: cert.NotAfter.UTC(), FingerprintSha256: iisCertificateResult(cert, "", false).FingerprintSha256}
}

func importIISCertificate(t iisTask, store string) (*x509.Certificate, error) {
	raw, err := base64.StdEncoding.DecodeString(t.PFXBase64)
	if err != nil || len(raw) == 0 {
		return nil, errors.New("invalid PFX base64")
	}
	password, err := windows.UTF16PtrFromString(t.PFXPassword)
	if err != nil {
		return nil, errors.New("invalid PFX password")
	}
	blob := windows.CryptDataBlob{Size: uint32(len(raw)), Data: &raw[0]}
	// 不设置 EXPORTABLE 或 NO_PERSIST_KEY：机器私钥持久化且不可导出。
	imported, err := windows.PFXImportCertStore(&blob, password, windows.CRYPT_MACHINE_KEYSET)
	runtime.KeepAlive(raw)
	runtime.KeepAlive(password)
	if err != nil {
		return nil, fmt.Errorf("PFXImportCertStore: %w", err)
	}
	defer windows.CertCloseStore(imported, 0)
	dest, err := openMachineStore(store, false)
	if err != nil {
		return nil, err
	}
	defer windows.CertCloseStore(dest, 0)
	ca, err := openMachineStore("CA", false)
	if err != nil {
		return nil, err
	}
	defer windows.CertCloseStore(ca, 0)
	var leaf *x509.Certificate
	var ctx *windows.CertContext
	for {
		ctx, err = windows.CertEnumCertificatesInStore(imported, ctx)
		if err != nil {
			if errors.Is(err, syscall.Errno(windows.CRYPT_E_NOT_FOUND)) {
				break
			}
			return nil, err
		}
		cert, e := certificateDER(ctx)
		if e != nil {
			windows.CertFreeCertificateContext(ctx)
			return nil, e
		}
		fingerprint := iisCertificateResult(cert, store, true)
		if fingerprint.FingerprintSha256 == t.FingerprintSha256 {
			if e = certificateKey(ctx); e == nil {
				// 同一公开证书若已导入，保留其已有可用私钥；缺失时才加入。
				hash, _ := hex.DecodeString(fingerprint.ThumbprintSha1)
				if existing, findErr := storedCertificate(store, hash); findErr == nil {
					leaf = existing
				} else {
					e = windows.CertAddCertificateContextToStore(dest, ctx, windows.CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES, nil)
					if e == nil {
						leaf, e = storedCertificate(store, hash)
					}
				}
			}
		} else {
			e = windows.CertAddCertificateContextToStore(ca, ctx, windows.CERT_STORE_ADD_USE_EXISTING, nil)
		}
		if e != nil {
			windows.CertFreeCertificateContext(ctx)
			return nil, e
		}
	}
	if leaf == nil {
		return nil, errors.New("PFX does not contain the expected leaf certificate with a usable private key")
	}
	return leaf, nil
}
