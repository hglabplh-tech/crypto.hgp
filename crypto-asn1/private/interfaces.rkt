;; Copyright 2020 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/contract
         racket/class
         scramble/result
         (only-in asn1 asn1-oid? bit-string?)
         (only-in crypto crypto-factory? public-only-key? security-level/c))
(provide (all-defined-out))

(define INIT-SECURITY-LEVEL 2)

(define (certificate? v) (is-a? v -certificate<%>))
(define (certificate-chain? v) (is-a? v -certificate-chain<%>))
(define (certificate-store? v) (is-a? v -certificate-store<%>))

(define (pre-chain? v) (is-a? v certificate-chain<%>))
(define (anchor? v) (is-a? v -anchor<%>))

(define asn1-algorithm-identifier/c (flat-named-contract 'asn1-algorithm-identifier/c hash?))
(define x509-extension/c (flat-named-contract 'x509-extension/c hash?))
(define x509-name/c (flat-named-contract 'x509-name/c any/c))
(define x509-name-constraints/c (flat-named-contract 'x509-name-constraints/c hash?))
(define x509-validity/c (flat-named-contract 'x509-validity/c hash?))

(define x509-key-usage/c
  (or/c 'digitalSignature 'nonRepudiation 'keyEncipherment 'dataEncipherment
        'keyAgreement 'keyCertSign 'cRLSign 'encipherOnly 'decipherOnly))

(define x509-general-name-tag/c
  (or/c 'otherName 'rfc822Name 'dNSName 'x400Address 'directoryName
        'ediPartyName 'uniformResourceIdentifier 'iPAddress 'registeredID))

(define x509-general-name/c
  (or/c (list/c 'otherName any/c)
        (list/c 'rfc822Name string?)
        (list/c 'dNSName string?)
        (list/c 'x400Address any/c)
        (list/c 'directoryName x509-name/c)
        (list/c 'ediPartyName any/c)
        (list/c 'uniformResourceIdentifier string?)
        (list/c 'iPAddress bytes?)
        (list/c 'registeredID asn1-oid?)))

(define certificate-data<%>
  (interface ()
    [has-same-public-key? (->m certificate? boolean?)]

    [get-der (->m bytes?)]
    [get-signature-info (->m (values asn1-algorithm-identifier/c bytes? bytes?))]

    [get-version (->m exact-integer?)] ;; Note: 2 represents v3
    [get-serial-number (->m exact-integer?)]
    [get-issuer (->m x509-name/c)]
    [get-validity (->m x509-validity/c)]
    [get-subject (->m x509-name/c)]
    [get-spki (->m bytes?)]
    [get-issuer-unique-id (->m (or/c #f bit-string?))]
    [get-subject-unique-id (->m (or/c #f bit-string?))]
    [get-extensions (->m (listof x509-extension/c))]
    [get-subject-common-names (->m (listof string?))]

    [is-CA? (->m boolean?)]
    [is-self-issued? (->m boolean?)]
    [get-key-usages (case->m (-> (listof x509-key-usage/c))
                             (-> any/c any/c))]
    [ok-key-usage? (->*m [x509-key-usage/c] [any/c] any)]
    [get-extended-key-usage (->m asn1-oid? (or/c 'yes 'no 'unset))]
    [get-extended-key-usages (case->m (-> (listof asn1-oid?))
                                      (-> any/c any/c))]

    [get-extension (->m asn1-oid? (or/c #f x509-extension/c))]
    [get-extension-value (->m asn1-oid? any/c any)]

    [get-name-constraints (->m (or/c #f x509-name-constraints/c))]
    [get-subject-alt-names
     (case->m (-> (listof x509-general-name/c))
              (-> (or/c #f x509-general-name-tag/c)
                  (or/c (listof string?) (listof x509-general-name/c))))]
    [get-validity-seconds (->m (list/c exact-integer? exact-integer?))]

    [get-subject-name-string (->m string?)]
    [get-issuer-name-string (->m string?)]
    ))

(define certificate<%>
  (interface (certificate-data<%> equal<%> writable<%>)
    ))

;; Represents TRUSTED CERTIFICATE: concatenation of Certificate + CertAux
(struct certificate+aux (cert aux) #:transparent)

(define time/c exact-integer?)
(define candidate-chain/c (non-empty-listof certificate?))

(define certificate-chain<%>
  (interface ()
    ;; Structure of chain
    [get-certificate (->m certificate?)]
    [get-certificates (->m (listof certificate?))]
    [get-issuer-chain (->m (or/c #f certificate-chain?))]
    [get-anchor (->m anchor?)]
    [is-anchor? (->m boolean?)]

    ;; Convenience, forwarded to certificate
    [get-subject (->m x509-name/c)]
    [get-subject-alt-names
     (case->m (-> (listof x509-general-name/c))
              (-> (or/c #f x509-general-name-tag/c)
                  (or/c (listof string?) (listof x509-general-name/c))))]
    [get-spki (->m bytes?)]

    ;; Signature verification
    [get-public-key
     (->*m [] [(or/c crypto-factory? (listof crypto-factory?))] public-only-key?)]
    [check-signature
     (->*m [(or/c bytes? asn1-algorithm-identifier/c) bytes? bytes?]
           [#:factories (or/c crypto-factory? (listof crypto-factory?))]
           (result/c #t (listof symbol?)))]

    ;; Validity of self chain
    [get-index (->m exact-nonnegative-integer?)]
    [get-max-path-length (->m (or/c #f exact-integer?))]
    [get-validity-seconds (->m (list/c time/c time/c))]

    ;; Security level of self chain
    [get-security-level (->m security-level/c)]
    [get-security-strength (->m exact-nonnegative-integer?)]
    [get-public-key-security-strength (->m exact-nonnegative-integer?)]
    [get-signature-security-strength (->m (or/c #f exact-nonnegative-integer?))]

    ;; Trusted (= trusted by store + valid at time + security level)
    [trusted?
     (->*m [(or/c #f certificate-store?)]
           [time/c time/c #:security-level exact-nonnegative-integer?]
           boolean?)]
    [check-trust
     (->*m [(or/c #f certificate-store?)]
           [time/c time/c #:security-level exact-nonnegative-integer?]
           (result/c #t (listof (cons/c exact-nonnegative-integer? any/c))))]
    [ok-validity-period?
     (->*m [] [time/c time/c] boolean?)]

    ;; Purpose of self chain
    [ok-key-usage? (->*m [x509-key-usage/c] [any/c] any)]
    [ok-extended-key-usage? (->*m [asn1-oid?] [any/c #:recur boolean?] any)]

    ;; Suitability for purpose
    [suitable-for-CA? (->m boolean?)]
    [suitable-for-ocsp-signing? (->m certificate-chain? boolean?)]
    [suitable-for-tls-server? (->m (or/c #f string?) boolean?)]
    [suitable-for-tls-client? (->m (or/c #f x509-general-name/c) boolean?)]
    ))

(struct trustmod
  (replace-ekus ;; #f or (Hash OID #t) -- #f means no override
   reject-ekus  ;; (Hash OID #t)
   ) #:prefab)

(define trust/c (flat-named-contract 'trust/c trustmod?))

(define x509-lookup<%>
  (interface ()
    [get-trust         (->m certificate? (or/c #f trust/c))]
    [lookup-by-subject (->m x509-name/c (listof certificate?))]
    ))

(define certificate-store<%>
  (interface (x509-lookup<%>)
    [check-trust
     (->m anchor? (result/c #t (listof symbol?)))]
    [add
     (->*m []
           [#:trusted (listof (or/c certificate? certificate+aux?))
            #:untrusted (listof certificate?)]
           certificate-store?)]
    [add-lookups
     (->m (listof (is-a?/c x509-lookup<%>))
          certificate-store?)]
    [set-security-level
     (->m security-level/c
          certificate-store?)]
    [add-trusted-from-pem-file
     (->*m [path-string?] [#:allow-aux? boolean?]
           certificate-store?)]
    [add-trusted-from-openssl-directory
     (->m path-string? certificate-store?)]

    [build-chain
     (->*m [certificate?]
           [(listof certificate?)
            time/c]
           certificate-chain?)]
    [build-chains
     (->*m [certificate?] [(listof certificate?) time/c #:empty-ok? boolean?]
           (listof certificate-chain?))]
    [pem-file->chain
     (->*m [path-string?] [time/c]
           certificate-chain?)]
    ))

(define -certificate<%>
  (interface (certificate<%>)))
(define -certificate-chain<%>
  (interface (certificate-chain<%>)))
(define -anchor<%>
  (interface (certificate-chain<%>)))
(define -certificate-store<%>
  (interface (certificate-store<%>)))

(struct exn:x509 exn:fail () #:transparent)
(struct exn:x509:certificate exn:x509 (errors) #:transparent)
(struct exn:x509:chain exn:x509 (errors) #:transparent)

;; An ErrorList is a list of "error description" values.
;; The empty list means no errors were detected.

(define-logger x509)

(define revocation-checker<%>
  (interface ()
    [check-ocsp (->m certificate-chain? (result/c #t symbol?))]
    [check-crl (->m certificate-chain? (result/c #t symbol?))]
    ))

(define cachable<%>
  (interface ()
    [get-expiration-time (->m rational?)] ;; Seconds
    [get-der (->m bytes?)]
    ))
