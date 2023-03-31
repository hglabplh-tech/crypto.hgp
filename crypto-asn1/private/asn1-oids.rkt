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