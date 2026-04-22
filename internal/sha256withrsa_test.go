package internal

import (
	"fmt"
	"testing"
)

func TestSHA256WithRSA(t *testing.T) {
	output, err := SHA256WithRSA(RSAKEY, "hello world")
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	fmt.Println(output)
}

const PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu8SjWZKwLmR06FsUQIDv
nZ3jwjAWdbive2dF8vMtc3yVE5Yb3CdWRb0RTE1fohumgwkGqq4iu3K8WnQty/Rz
B6Cdd//0dsjMPGunVfBxPDMKDvQVzfhcKQvW4ebPngd0A+sH73M5X8yhBTyiwXWK
zKYMAInqXXXcsH3XN0/qDrCkfQQkb/KnebhWjhsjG5vGTgu8Oaa4a1C2yAP8Wi5A
Yw1Wk6tYSrtxqGmYfnjSlrR9gY+fuCvxBVRbQzz0bkSyAex1vtzQUT11lWEU+rhr
Un6tcP63jBGWUN7++vh1Wzb0yPjxK2WrT3VOAjtzlP+B06ebPcFJ0ng29zxBUsJA
CQIDAQAB
-----END PUBLIC KEY-----
`

const RSAKEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAu8SjWZKwLmR06FsUQIDvnZ3jwjAWdbive2dF8vMtc3yVE5Yb
3CdWRb0RTE1fohumgwkGqq4iu3K8WnQty/RzB6Cdd//0dsjMPGunVfBxPDMKDvQV
zfhcKQvW4ebPngd0A+sH73M5X8yhBTyiwXWKzKYMAInqXXXcsH3XN0/qDrCkfQQk
b/KnebhWjhsjG5vGTgu8Oaa4a1C2yAP8Wi5AYw1Wk6tYSrtxqGmYfnjSlrR9gY+f
uCvxBVRbQzz0bkSyAex1vtzQUT11lWEU+rhrUn6tcP63jBGWUN7++vh1Wzb0yPjx
K2WrT3VOAjtzlP+B06ebPcFJ0ng29zxBUsJACQIDAQABAoIBAAbSXRDrCGWXFrw+
Wt0BEjOKwfSTJK3AOPflx5/M//C7LPtaL8bu0u6TsOYxxXCxSnpmQIzA6NggkgFD
SUqopek4B6CNdwc9wlXLn3e61ZJXVF04tvYVuNtw56yrYw2dvbRKvK4RZJs7Zvo2
ur8GkzVeLv9yA0bD+nGbEM+coqdH6bKtVUUlKduk++siQcANeyaAql1JvY7eyibK
vCPbgxsdQZljhEbuY+5oTU4vdVz61QYdNakCE1mghPhCoZSz8W2Pjy3+bRDHIdVk
Vc2KVyqR8yr6qWVW/9T0c5M6jz1jYsueEQzG8h6cUHEK6GYPPKlq48+dDZZhKoMv
z1JSlNECgYEA4BPtDzYZTrbEcRHXM+PRdilqcr38ojRna8EQ46bOKcHg9zrM3jRJ
wUKpM098mL3ir+FP2B5ValYxCvNCElCaBxEHE4ypES+pOcrBf5JHZYVs+B9NWDso
2YEBhLCbVi9EUKQ1xKRS2RseqhRC9tTMdlfB5ppDkN6/aCfGFg6ovf0CgYEA1oSA
/mF5+mGqgjvX5DfD8pq0VP4SgM55XVmknaL2ZvxPPTHT3lqJ5TXhiqelSuUpwJ9B
obsyalTWREtKyT5LtyTUGeJ3XnNg/URsRtNoBc+Hk3VoOElyqhvZjNFkRmvaiZYZ
3nyJiCwe1T3tJoZk2wfTgrI8VHvdsrXWc0nqgf0CgYB7STtS9TbzYgevFlvLRvtG
Af95ZiKLtD16wdzjBDHGM8/s9sMlNqul02F4w7EP8Nm6X0Mo63efbBDLr4+YuBQm
8y1riiazN//pti7EW91AdCrCUaaidtpA4YPOV8T/pD34CIE00hxrK0qx1TgKyoY8
Toh2skWefY/eZJPOKv6YmQKBgQCvvwbfYYTJeNJ0uAp70qQaUlyDdVQ7au1LaXHQ
I/6zCOryO6xUcuCehLIvIoHtBipawR7IHdGEA9U3RmgSz5LAjM+oFT2uh+BiHniG
3hRPDmMIkBu+YY4rh32IPNRmTV5RckPnXyheA6ePFJkCAwEF4TeLz/JVVNWg4BC9
i0UxEQKBgHovI+xx3QuexIMEPOQOpTh6zrUUdAhP0feKzfh0BAFOPH2mQhtjCHjm
ruqmrVTqHhqfNEskf/R0IWkJemeoCan3nEVeuYNs/pz84SVbx7GgYl3b26femynw
KlNNWyM/f++6rTHrLYLhmPqOQ3SHvJRqvi/jiiH0tpcHt2fszNT+
-----END RSA PRIVATE KEY-----
`

const PRIVATEKEY = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7xKNZkrAuZHTo
WxRAgO+dnePCMBZ1uK97Z0Xy8y1zfJUTlhvcJ1ZFvRFMTV+iG6aDCQaqriK7crxa
dC3L9HMHoJ13//R2yMw8a6dV8HE8MwoO9BXN+FwpC9bh5s+eB3QD6wfvczlfzKEF
PKLBdYrMpgwAiepdddywfdc3T+oOsKR9BCRv8qd5uFaOGyMbm8ZOC7w5prhrULbI
A/xaLkBjDVaTq1hKu3GoaZh+eNKWtH2Bj5+4K/EFVFtDPPRuRLIB7HW+3NBRPXWV
YRT6uGtSfq1w/reMEZZQ3v76+HVbNvTI+PErZatPdU4CO3OU/4HTp5s9wUnSeDb3
PEFSwkAJAgMBAAECggEABtJdEOsIZZcWvD5a3QESM4rB9JMkrcA49+XHn8z/8Lss
+1ovxu7S7pOw5jHFcLFKemZAjMDo2CCSAUNJSqil6TgHoI13Bz3CVcufd7rVkldU
XTi29hW423DnrKtjDZ29tEq8rhFkmztm+ja6vwaTNV4u/3IDRsP6cZsQz5yip0fp
sq1VRSUp26T76yJBwA17JoCqXUm9jt7KJsq8I9uDGx1BmWOERu5j7mhNTi91XPrV
Bh01qQITWaCE+EKhlLPxbY+PLf5tEMch1WRVzYpXKpHzKvqpZVb/1PRzkzqPPWNi
y54RDMbyHpxQcQroZg88qWrjz50NlmEqgy/PUlKU0QKBgQDgE+0PNhlOtsRxEdcz
49F2KWpyvfyiNGdrwRDjps4pweD3OszeNEnBQqkzT3yYveKv4U/YHlVqVjEK80IS
UJoHEQcTjKkRL6k5ysF/kkdlhWz4H01YOyjZgQGEsJtWL0RQpDXEpFLZGx6qFEL2
1Mx2V8HmmkOQ3r9oJ8YWDqi9/QKBgQDWhID+YXn6YaqCO9fkN8PymrRU/hKAznld
WaSdovZm/E89MdPeWonlNeGKp6VK5SnAn0GhuzJqVNZES0rJPku3JNQZ4ndec2D9
RGxG02gFz4eTdWg4SXKqG9mM0WRGa9qJlhnefImILB7VPe0mhmTbB9OCsjxUe92y
tdZzSeqB/QKBgHtJO1L1NvNiB68WW8tG+0YB/3lmIou0PXrB3OMEMcYzz+z2wyU2
q6XTYXjDsQ/w2bpfQyjrd59sEMuvj5i4FCbzLWuKJrM3/+m2LsRb3UB0KsJRpqJ2
2kDhg85XxP+kPfgIgTTSHGsrSrHVOArKhjxOiHayRZ59j95kk84q/piZAoGBAK+/
Bt9hhMl40nS4CnvSpBpSXIN1VDtq7UtpcdAj/rMI6vI7rFRy4J6Esi8ige0GKlrB
Hsgd0YQD1TdGaBLPksCMz6gVPa6H4GIeeIbeFE8OYwiQG75hjiuHfYg81GZNXlFy
Q+dfKF4Dp48UmQIDAQXhN4vP8lVU1aDgEL2LRTERAoGAei8j7HHdC57EgwQ85A6l
OHrOtRR0CE/R94rN+HQEAU48faZCG2MIeOau6qatVOoeGp80SyR/9HQhaQl6Z6gJ
qfecRV65g2z+nPzhJVvHsaBiXdvbp96bKfAqU01bIz9/77qtMestguGY+o5DdIe8
lGq+L+OKIfS2lwe3Z+zM1P4=
-----END PRIVATE KEY-----
`

// # Untuk generate RSA 2048 bit silakan cek https://www.openssl.org/docs/man3.1/man1/genrsa.html
// openssl genrsa -out rsakey.pem 2048 # generate 2048 bit RSA private key

// # konversi ke format PKCS8 (Format support Java) https://www.openssl.org/docs/man3.1/man1/openssl-pkcs8.html
// # Generate private key (dipakai oleh Merchant sendiri, jangan kirim ke siapapun)
// openssl pkcs8 -topk8 -nocrypt -inform PEM -in rsakey.pem -outform PEM -out private-key.pem

// # generate public key untuk dikasih ke Paylabs
// openssl rsa -inform PEM -in rsakey.pem -pubout -outform PEM -out public-key.pem

// # Shortcut
// openssl genrsa -out rsakey.pem 2048 ; \
// openssl pkcs8 -topk8 -nocrypt -inform PEM -in rsakey.pem -outform PEM -out private-key.pem ; \
// openssl rsa -inform PEM -in rsakey.pem -pubout -outform PEM -out public-key.pem
