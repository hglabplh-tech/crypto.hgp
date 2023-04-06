;; Copyright 2020 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require asn1
         racket/contract
         racket/class
         scramble/result         
         (only-in asn1 asn1-oid? bit-string?)
         (only-in crypto crypto-factory? public-only-key? security-level/c))
(provide (all-defined-out))

(define (signer-info? v) (is-a? v signer-info<%>))

(define (issuer-and-serial? v) (is-a? v issuer-and-serial<%>))
(define (name? v) (is-a? v name<%>))
(define (name-attribute? v) (is-a? v name-attribute<%>))
(define (key-trans-recipient-info? v) (is-a? v key-trans-recipient-info<%>))
(define (key-agree-recipient-info? v) (is-a? v key-agree-recipient-info<%>))

(define signed-data<%>
  (interface ()    
    [get-certificate-set        (->m (or/c boolean? (listof procedure?)))]
    [get-signer-infos           (->m (or/c boolean? (listof signer-info?)))]
    [get-digest-algorithms      (->m (listof any/c))]
    [get-encap-content-info     (->m boolean? (listof any/c))]
    ))

(define signer-info<%>
  (interface ()
    [get-digest-algoritm       (->m (list/c any/c any/c))]
    [get-signature-algoritm    (->m (list/c any/c any/c))]
    [get-signature             (->m boolean? (or/c bytes? string?))]
    [get-auth-attributes       (->m (or/c boolean? list?))] ;;enhance to listof
    [get-unauth-attributes     (->m (or/c boolean? list?))]
    [get-issuer-and-serial     (->m (or/c boolean? issuer-and-serial?))]
    [get-subject-identifier    (->m boolean? (or/c string? bytes?))]
    )) ;;enhance to listof

(define issuer-and-serial<%>
  (interface ()
    [get-serial-number       (->m integer?)]
    [get-issuer              (->m (listof name?))]    
    ))

(define name<%>
  (interface ()
    [get-attributes              (->m (listof name-attribute?))]
    [get-attribute-value         (->m any/c any/c)]
    [attribute-value->string     (->m any/c string?)]
    [get-name-normalized         (->m string?)] 
    ))

(define name-attribute<%>
  (interface ()
    [get-type    (->m any/c)]
    [get-value   (->m any/c)]
    ))

(define enveloped-data<%>
  (interface ()
    ))

(define encr-content-info<%>
  (interface ()
    ))

(define key-trans-recipient-info<%>
  (interface ()
    ))

(define key-agree-recipient-info<%>
  (interface ()
    ))