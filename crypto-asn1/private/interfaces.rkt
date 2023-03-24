;; Copyright 2020 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require asn1
         racket/contract
         racket/class
         scramble/result
         x509
         (only-in asn1 asn1-oid? bit-string?)
         (only-in crypto crypto-factory? public-only-key? security-level/c))
(provide (all-defined-out))

(define (signer-info? v) (is-a? v signer-info<%>))
(define signed-data<%>
  (interface ()    
    [get-certificate-set (->m (or/c boolean? (listof certificate?)))]
    [get-signer-infos     (->m (or/c boolean? (listof signer-info?)))]
    ))

(define signer-info<%>
  (interface ()
    [get-auth-attributes       (->m (or/c boolean? list?))] ;;enhance to listof
    [get-unauth-attributes     (->m (or/c boolean? list?))]
    )) ;;enhance to listof

(define issuer-and-serial<%>
  (interface ()
    ))

(define name<%>
  (interface ()
    ))

(define name-attribute<%>
  (interface ()
    ))