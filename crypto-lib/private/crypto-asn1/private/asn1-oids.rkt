;; Copyright 2023-2025 Harald Glab-Plhak
;; 
;; This library is free software: you can redistribute it and/or modify
;; it under the terms of the GNU Lesser General Public License as published
;; by the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.
;; us
;; This library is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU Lesser General Public License for more details.
;; 
;; You should have received a copy of the GNU Lesser General Public License
;; along with this library.  If not, see <http://www.gnu.org/licenses/>.

#lang racket/base
(require asn1          
         )
         
(provide (all-defined-out))

;; Common prefixes
(define rsadsi (OID (iso 1) (member-body 2) (us 840) (rsadsi 113549)))
(define pkcs-1 (build-OID rsadsi (pkcs 1) 1))
(define pkcs-3 (build-OID rsadsi (pkcs 1) 3))
(define pkcs-5 (build-OID rsadsi (pkcs 1) 5))
(define pkcs-9 (build-OID rsadsi (pkcs 1) 9))



  
;; signed attributes OIDS
(define id-smime-capabilities (build-OID rsadsi (pkcs 1) 9 15))
;;{iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1)
;;pkcs-9(9) 15}
;;dsigned attributes Object ID's incomplete
(define id-content-type (build-OID rsadsi (pkcs 1) 9 3))
(define id-message-digest (build-OID rsadsi (pkcs 1) 9 4))
(define id-signing-time (build-OID rsadsi (pkcs 1) 9 5))
(define id-counter-signature (build-OID rsadsi (pkcs 1) 9 6))

;; id's for names
;;=========================================================================================
;;Some general definitions
;;=========================================================================================
(define id-at (OID (joint-iso-ccitt 2) (ds 5) 4))
(define id-at-name (build-OID id-at 41))
(define id-at-surname (build-OID id-at 4))
(define id-at-givenName (build-OID id-at 42))
(define id-at-initials (build-OID id-at 43))
(define id-at-generationQualifier (build-OID id-at 44))
(define id-at-commonName (build-OID id-at 3))
(define id-at-localityName (build-OID id-at 7))
(define id-at-stateOrProvinceName (build-OID id-at 8))
(define id-at-organizationName (build-OID id-at 10))
(define id-at-organizationalUnitName (build-OID id-at 11))
(define id-at-title (build-OID id-at 12))
(define id-at-dnQualifier (build-OID id-at 46))
(define id-at-countryName (build-OID id-at 6))
(define id-at-serialNumber (build-OID id-at 5))
(define id-at-pseudonym (build-OID id-at 65))
(define id-domainComponent (OID 0 9 2342 19200300 100 1 25))

(define id-emailAddress (build-OID pkcs-9 1))

;; the OIDs for cms signatures
;;=======================================================================================
(define id-cms-contentInfo (build-OID rsadsi  1 9 16 1 6))

(define id-cms-akey-package (build-OID (list 2 16 840 1 101 2 1 2 78 5)))

(define id-cms-data (build-OID rsadsi (pkcs 1) 7 1))

(define id-cms-signed-data (build-OID rsadsi (pkcs 1) 7 2))

(define id-cms-enveloped-data (build-OID rsadsi (pkcs 1) 7 3))

(define id-cms-digest-data (build-OID rsadsi (pkcs 1) 7 5))

(define id-cms-encrypted-data (build-OID rsadsi (pkcs 1) 7 6))

(define id-cms-auth-data (build-OID rsadsi (pkcs 1) 9 16 1 2))

(define id-cms-auth-enveloped-data (build-OID rsadsi (pkcs 1) 9 16 1 23))

(define id-cms-auth-compressed-data (build-OID rsadsi (pkcs 1) 9 16 1 9))



;; Algorithms
;;================================================================================================
(define certicom (OID (iso 1) (identified-organization 3) (certicom 132)))
(define ansi-X9-62 (OID (iso 1) (member-body 2) (us 840) (ansi-X9-62 10045)))
(define id-pkix
  (OID (iso 1) (identified-organization 3) (dod 6) (internet 1) (security 5)
       (mechanisms 5) (pkix 7)))

(define iso-member-body (OID (iso 1) (member-body 2)))
(define id-tc26  (build-OID iso-member-body 643 7 1))
(define id-cryptopro (build-OID iso-member-body 643 2 2))
(define id-tc-algorithms (build-OID id-tc26 1))
(define id-tc-digest (build-OID id-tc-algorithms 2))
(define id-des-algorithm (OID 1 3 14 3 2))



(define id-pe (build-OID id-pkix 1))
(define id-qt (build-OID id-pkix 2))
(define id-kp (build-OID id-pkix 3))
(define id-ad (build-OID id-pkix 48))
(define id-qt-cps (build-OID id-qt 1))
(define id-qt-unotice (build-OID id-qt 2))
(define id-ad-ocsp (build-OID id-ad 1))
(define id-ad-caIssuers (build-OID id-ad 2))
(define id-ad-timeStamping (build-OID id-ad 3))
(define id-ad-caRepository (build-OID id-ad 5))

(define nistAlgorithms
  (OID (joint-iso-itu-t 2) (country 16) (us 840) (organization 1)
       (gov 101) (csor 3) (nistAlgorithms 4)))

;; from PKIX-Algs-2009 (1.3.6.1.5.5.7.0.56)

(define rsaEncryption (build-OID pkcs-1 1))
(define id-dsa
  (OID (iso 1) (member-body 2) (us 840) (x9-57 10040) (x9algorithm 4) 1))
(define dhpublicnumber
  (OID (iso 1) (member-body 2) (us 840) (ansi-x942 10046) (number-type 2) 1))
(define id-ecPublicKey (build-OID ansi-X9-62 (keyType 2) 1))
(define id-ecDH (build-OID certicom (schemes 1) (ecdh 12)))
(define id-ecMQV (build-OID certicom (schemes 1) (ecmqv 13)))
(define aes (build-OID nistAlgorithms 1))
(define id-aes128-ECB (build-OID aes 1))
(define id-aes128-CBC (build-OID aes 2))
(define id-aes128-OFB (build-OID aes 3))
(define id-aes128-CFB (build-OID aes 4))
(define id-aes128-wrap (build-OID aes 5))
(define id-aes128-GCM (build-OID aes 6))
(define id-aes128-CCM (build-OID aes 7))
(define id-aes128-wrap-pad (build-OID aes 8))
(define id-aes192-ECB (build-OID aes 21))
(define id-aes192-CBC (build-OID aes 22))
(define id-aes192-OFB (build-OID aes 23))
(define id-aes192-CFB (build-OID aes 24))
(define id-aes192-wrap (build-OID aes 25))
(define id-aes192-GCM (build-OID aes 26))
(define id-aes192-CCM (build-OID aes 27))
(define id-aes192-wrap-pad (build-OID aes 28))
(define id-aes256-ECB (build-OID aes 41) )
(define id-aes256-CBC (build-OID aes 42)  )
(define id-aes256-OFB (build-OID aes 43) )
(define id-aes256-CFB (build-OID aes 44))
(define id-aes256-wrap (build-OID aes 45))
(define id-aes256-GCM (build-OID aes 46))
(define id-aes256-CCM (build-OID aes 47))
(define id-aes256-wrap-pad (build-OID aes 48))

(define hashAlgs (build-OID nistAlgorithms 2))

(define id-sha256 (build-OID hashAlgs 1))
(define id-sha384 (build-OID hashAlgs 2))
(define id-sha512 (build-OID hashAlgs 3))
(define id-sha224 (build-OID hashAlgs 4))
(define id-sha512-224 (build-OID hashAlgs 5))
(define id-sha512-256 (build-OID hashAlgs 6))
(define id-sha3-224 (build-OID hashAlgs 7))
(define id-sha3-256 (build-OID hashAlgs 8))
(define id-sha3-384 (build-OID hashAlgs 9))
(define id-sha3-512 (build-OID hashAlgs 10))
(define id-shake128 (build-OID hashAlgs 11))
(define id-shake256 (build-OID hashAlgs 12))
(define id-shake128-len (build-OID hashAlgs 17))
(define id-shake256-len (build-OID hashAlgs 18))

(define id-hmacWithSHA3-224 (build-OID hashAlgs 13))
(define id-hmacWithSHA3-256 (build-OID hashAlgs 14))
(define id-hmacWithSHA3-384 (build-OID hashAlgs 15))
(define id-hmacWithSHA3-512 (build-OID hashAlgs 16))

(define sigAlgs (build-OID nistAlgorithms 3))

(define id-dsa-with-sha224 (build-OID sigAlgs 1))
(define id-dsa-with-sha256 (build-OID sigAlgs 2))
(define id-dsa-with-sha384 (build-OID sigAlgs 3))
(define id-dsa-with-sha512 (build-OID sigAlgs 4))

(define id-dsa-with-sha3-224 (build-OID sigAlgs 5))
(define id-dsa-with-sha3-256 (build-OID sigAlgs 6))
(define id-dsa-with-sha3-384 (build-OID sigAlgs 7))
(define id-dsa-with-sha3-512 (build-OID sigAlgs 8))

(define id-ecdsa-with-sha3-224 (build-OID sigAlgs 9))
(define id-ecdsa-with-sha3-256 (build-OID sigAlgs 10))
(define id-ecdsa-with-sha3-384 (build-OID sigAlgs 11))
(define id-ecdsa-with-sha3-512 (build-OID sigAlgs 12))

(define id-rsassa-pkcs1-v1_5-with-sha3-224 (build-OID sigAlgs 13))
(define id-rsassa-pkcs1-v1_5-with-sha3-256 (build-OID sigAlgs 14))
(define id-rsassa-pkcs1-v1_5-with-sha3-384 (build-OID sigAlgs 15))
(define id-rsassa-pkcs1-v1_5-with-sha3-512 (build-OID sigAlgs 16))

;; from PKCS #3

(define dhKeyAgreement (build-OID pkcs-3 1))

;; from scrypt-0 (1.3.6.1.4.1.11591.4.10)

(define id-scrypt (OID 1 3 6 1 4 1 11591 4 11))

;; from PKCS5v2-1 (1.2.840.113549.1.5.16.2)

(define id-PBKDF2 (build-OID pkcs-5 12))

(define pbeWithMD2AndDES-CBC (build-OID pkcs-5 1))
(define pbeWithMD2AndRC2-CBC (build-OID pkcs-5 4))
(define pbeWithMD5AndDES-CBC (build-OID pkcs-5 3))
(define pbeWithMD5AndRC2-CBC (build-OID pkcs-5 6))
(define pbeWithSHA1AndDES-CBC (build-OID pkcs-5 10))
(define pbeWithSHA1AndRC2-CBC (build-OID pkcs-5 11))

(define id-des-ede3-cbc (build-OID rsadsi 3 7))
(define id-rc2-cbc (build-OID rsadsi 3 2))
(define id-des-cbc(build-OID id-des-algorithm 7))
                   

(define id-PBES2 (build-OID pkcs-5 13))
(define id-PBMAC1 (build-OID pkcs-5 14))

(define digestAlgorithm (build-OID rsadsi 2))

(define id-hmacWithSHA1 (build-OID digestAlgorithm 7))
(define id-hmacWithSHA224 (build-OID digestAlgorithm 8))
(define id-hmacWithSHA256 (build-OID digestAlgorithm 9))
(define id-hmacWithSHA384 (build-OID digestAlgorithm 10))
(define id-hmacWithSHA512 (build-OID digestAlgorithm 11))
(define id-hmacWithSHA512-224 (build-OID digestAlgorithm 12))
(define id-hmacWithSHA512-256 (build-OID digestAlgorithm 13))

;; (define aes (build-OID nistAlgorithms 1))
(define aes128-CBC-PAD (build-OID aes 2))
(define aes192-CBC-PAD (build-OID aes 22))
(define aes256-CBC-PAD (build-OID aes 42))

;; from CMS-AEADChaCha20Poly1305 (1.2.840.113549.1.9.16.0.66)

(define id-alg-AEADChaCha20Poly1305 (build-OID pkcs-9 (smime 16) (alg 3) 18))

;; from Safecurves-pkix-18 (1.3.6.1.5.5.7.0.93)

(define id-edwards-curve-algs (OID (iso 1) (identified-organization 3) 101))
(define id-X25519 (build-OID id-edwards-curve-algs 110))
(define id-X448 (build-OID id-edwards-curve-algs 111))
(define id-Ed25519 (build-OID id-edwards-curve-algs 112))
(define id-Ed448 (build-OID id-edwards-curve-algs 113))

;; from RFC 7693 (BLAKE2):

;; "The same OID can be used for both keyed and unkeyed hashing since
;; in the latter case the key simply has zero length."

(define blake2-hashAlgs
  (OID (iso 1) (identified-organization 3) (dod 6) (internet 1)
       (private 4) (enterprise 1) (kudelski 1722) (cryptography 12) 2))

(define id-blake2b (build-OID blake2-hashAlgs 1))
(define id-blake2s (build-OID blake2-hashAlgs 2))

(define id-blake2b160 (build-OID id-blake2b 5))
(define id-blake2b256 (build-OID id-blake2b 8))
(define id-blake2b384 (build-OID id-blake2b 12))
(define id-blake2b512 (build-OID id-blake2b 16))

(define id-blake2s128 (build-OID id-blake2s 4))
(define id-blake2s160 (build-OID id-blake2s 5))
(define id-blake2s224 (build-OID id-blake2s 7))
(define id-blake2s256 (build-OID id-blake2s 8))
;; (define id-keyExchangeAlgorithm
;;   (OID (joint-iso-itu-t 2) (country 16) (us 840) (organization 1)
;;        (gov 101) (dod 2) (infosec 1) (algorithms 1) 22))

;; (define secp192r1 (build-OID ansi-X9-62 (curves 3) (prime 1) 1))
;; (define sect163k1 (build-OID certicom (curve 0) 1))
;; (define sect163r2 (build-OID certicom (curve 0) 15))
;; (define secp224r1 (build-OID certicom (curve 0) 33))
;; (define sect233k1 (build-OID certicom (curve 0) 26))
;; (define sect233r1 (build-OID certicom (curve 0) 27))
;; (define secp256r1 (build-OID ansi-X9-62 (curves 3) (prime 1) 7))
;; (define sect283k1 (build-OID certicom (curve 0) 16))
;; (define sect283r1 (build-OID certicom (curve 0) 17))
;; (define secp384r1 (build-OID certicom (curve 0) 34))
;; (define sect409k1 (build-OID certicom (curve 0) 36))
;; (define sect409r1 (build-OID certicom (curve 0) 37))
;; (define secp521r1 (build-OID certicom (curve 0) 35))
;; (define sect571k1 (build-OID certicom (curve 0) 38))
;; (define sect571r1 (build-OID certicom (curve 0) 39))

(define id-md2 (build-OID rsadsi (digestAlgorithm 2) 2))
(define id-md5 (build-OID rsadsi (digestAlgorithm 2) 5))
(define id-sha1
  (OID (iso 1) (identified-organization 3) (oiw 14) (secsig 3) (algorithm 2) 26))

(define md2WithRSAEncryption (build-OID rsadsi (pkcs 1) (pkcs-1 1) 2))
(define md5WithRSAEncryption (build-OID rsadsi (pkcs 1) (pkcs-1 1) 4))
(define sha1WithRSAEncryption (build-OID rsadsi (pkcs 1) (pkcs-1 1) 5))

(define dsa-with-sha1
  (OID (iso 1) (member-body 2) (us 840) (x9-57 10040) (x9algorithm 4) 3))
(define dsa-with-sha224 (build-OID nistAlgorithms (id-dsa-with-sha2 3) 1))
(define dsa-with-sha256 (build-OID nistAlgorithms (id-dsa-with-sha2 3) 2))

(define ecdsa-with-SHA1 (build-OID ansi-X9-62 (signatures 4) 1))
(define ecdsa-with-SHA224 (build-OID ansi-X9-62 (signatures 4) (ecdsa-with-SHA2 3) 1))
(define ecdsa-with-SHA256 (build-OID ansi-X9-62 (signatures 4) (ecdsa-with-SHA2 3) 2))
(define ecdsa-with-SHA384 (build-OID ansi-X9-62 (signatures 4) (ecdsa-with-SHA2 3) 3))
(define ecdsa-with-SHA512 (build-OID ansi-X9-62 (signatures 4) (ecdsa-with-SHA2 3) 4))

;; from PKIX-PSS-OAEP-Algorithms-2009 (1.3.6.1.5.5.7.0.54)

;; (define id-sha224 (build-OID nistAlgorithms (hashalgs 2) 4))
;; (define id-sha256 (build-OID nistAlgorithms (hashalgs 2) 1))
;; (define id-sha384 (build-OID nistAlgorithms (hashalgs 2) 2))
;; (define id-sha512 (build-OID nistAlgorithms (hashalgs 2) 3))

;; (define rsaEncryption (build-OID pkcs-1 1))
(define id-RSAES-OAEP (build-OID pkcs-1 7))
(define id-mgf1 (build-OID pkcs-1 8))
(define id-pSpecified (build-OID pkcs-1 9))
(define id-RSASSA-PSS (build-OID pkcs-1 10))

;; GOST algorithms
(define id-gost-r-3411-2012-256 (build-OID id-tc-digest 2))
(define id-gost-r-3411-2012-512 (build-OID id-tc-digest 3))

(define id-gost-r-3411-94 (build-OID id-cryptopro 9))
(define id-gost-r-3411-89 (build-OID id-cryptopro 22))

