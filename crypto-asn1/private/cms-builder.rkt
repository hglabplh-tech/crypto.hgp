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

(require racket/class asn1
         racket/date
         racket/match
         racket/list         
         racket/serialize
         asn1
         racket/pretty
         x509         
         asn1/util/time
         "interfaces.rkt"
         "cmssig-asn1.rkt"
         "asn1-utils.rkt"
         "asn1-oids.rkt"
         "certificates-asn1.rkt")
         
(provide (all-defined-out))

;; contents definitions for sequences and choices....
;; signing
(define signed-data-seq (list (list 'version #t)
                              (list 'digestAlgorithms #t)
                              (list 'encapContentInfo #t)
                              (list 'certificates #f);;#:optional)
                              (list 'crls #f);;#:optional)
                              (list 'signerInfos #t)))
(define signer-info-seq (list 
                         (list 'version #t)
                         (list 'sid #t)
                         (list 'digestAlgorithm #t)
                         (list 'signedAttrs #f)
                         (list 'signatureAlgorithm #t)
                         (list 'signature #t)
                         (list 'unsignedAttrs #f)))

(define sid-choice (list
                    'issuerAndSerialNumber
                    'subjectKeyIdentifier))

(define issuer-and-serial-seq (list (list 'issuer #t)
                                    (list 'serialNumber #t)))
;;enveloped

(define recipient-info-choice (list
                               'ktri 
                               'kari 
                               'kekri 
                               'pwri 
                               'ori)) 

(pretty-print (check-and-make-sequence signed-data-seq 
                                       (list 1 'digestAlg 'encapContent #f #f 'sig-infos)))
(pretty-print (check-and-make-choice sid-choice (list 'issuerAndSerialNumber
 (check-and-make-sequence issuer-and-serial-seq (list 'issuer 12345)))))
(pretty-print (check-and-make-choice  recipient-info-choice (list 'pwri 'geheim)))
;;(pretty-print (check-and-make-choice  recipient-info-choice-def (list 'not-there 'geheim)))