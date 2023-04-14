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
         asn1/util/time
         "interfaces.rkt"
         "cmssig-asn1.rkt"
         "asn1-utils.rkt"
         "asn1-oids.rkt"
         "certificates-asn1.rkt")
         
(provide (all-defined-out))

;; contents definitions for sequences and choices....
;; signing
(define algo-id-seq (list
                     (list 'algorithm #t)
                     (list 'parameters #f)))

(define cms-attribute-seq (list
                           (list 'attrType #t)
                           (list 'attrValues #t)))
                           
(define signed-data-seq (list (list 'version #t)
                              (list 'digestAlgorithms #t)
                              (list 'encapContentInfo #t)
                              (list 'certificates #f);;#:optional)
                              (list 'crls #f);;#:optional)
                              (list 'signerInfos #t)))

(define encap-content-info-seq (list
                                (list 'eContentType #t)
                                (list 'eContent #f)))
(define signer-info-seq (list 
                         (list 'version #t)
                         (list 'sid #t)
                         (list 'digestAlgorithm #t)
                         (list 'signedAttrs #f)
                         (list 'signatureAlgorithm #t)
                         (list 'signature #t)
                         (list 'unsignedAttrs #f)))

(define content-info-seq (list  
                          (list 'contentType #t)        
                          (list 'content #t)))

(define certificate-choice  (list
                             'certificate
                             'extendedCertificate
                             'v1AttrCert
                             'v2AttrCert
                             'other))


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

;; logic for build up a signed data CMS signature

(define (build-alg-id id params)
  (check-and-make-sequence algo-id-seq (list id params)))

(define (build-sid cert-bytes) 
  (let ([cert-val-getter  (build-cert-val-getter cert-bytes)])
    (check-and-make-choice sid-choice
                           (list 'issuerAndSerialNumber
                                 (check-and-make-sequence issuer-and-serial-seq
                                                          (list (get-issuer-checked cert-val-getter)
                                                                (get-serial-checked cert-val-getter)))))))

(define (build-signed-attributes digest-val)
  (date-display-format 'iso-8601)
  (let ([content-type-attr (check-and-make-sequence cms-attribute-seq
                                                    (list id-content-type
                                                          (list id-cms-data)))]
        [signing-time-attr (check-and-make-sequence cms-attribute-seq
                                                    (list id-signing-time
                                                          (date-time->asn1-time (current-date))))]
        [digest-attr (check-and-make-sequence cms-attribute-seq 
                                              (list id-message-digest (list digest-val)))])
    (make-set-of content-type-attr signing-time-attr digest-attr)))

(define (build-cert-val-getter cert-bytes)
  (make-cert-val-getter
   cert-bytes))

(define (build-certificate-set cert-bytes)
  (let ([cert-asn1 (cert->asn1/DER cert-bytes)])
    (make-set-of (check-and-make-choice certificate-choice
                                        (list 'certificate cert-asn1)))))
;; in the following we have to introduce lambda for signature and digest taking the neccessary arguments
;; data and algorithm....
(define (build-signer-info cert-bytes digest-alg private-key
                           calc-digest-proc
                           sign-digest-proc content-bytes)
  (let* ([version 1];; here we need a cond
         [sid (build-sid cert-bytes)]
         [digest-alg-id (asn1->bytes/DER OBJECT-IDENTIFIER
                                         (hash-ref digest-alg 'algorithm))]
         [digest (calc-digest-proc digest-alg-id content-bytes)]
         [cert-val-get (build-cert-val-getter cert-bytes)]
         [signed-attrs (build-signed-attributes digest)];; next to be implemented        
         [sig-alg (get-sig-alg-checked cert-val-get)]
         [signature (sign-digest-proc digest-alg-id private-key
                                      (asn1->bytes/DER SignedAttributes signed-attrs))] ;; call callback to build signature
         )
    (check-and-make-sequence signer-info-seq (list version sid digest-alg
                                                   signed-attrs sig-alg signature #f))))
  



(define (build-signed-data digest-alg content-bytes cert-bytes crls signer-infos) 
  (check-and-make-sequence signed-data-seq 
                           (list 1
                                 (make-set-of digest-alg)
                                 (check-and-make-sequence
                                  encap-content-info-seq (list id-cms-data content-bytes))
                                 (cond [cert-bytes ;; complete this to real sequence
                                        (build-certificate-set cert-bytes)]
                                       [else cert-bytes])
                                 crls signer-infos)))

(define (build-cms-content type content)
  (check-and-make-sequence content-info-seq (list type content)))

(let ([content-data  (build-cms-content
                      id-cms-signed-data

                      (build-signed-data
                       (build-alg-id id-sha512 #f)
                       (read-bytes-from-file "example.rkt")
                       (read-bytes-from-file "data/freeware-user-cert.der")
                       #f
                       (make-set-of
                        (build-signer-info (read-bytes-from-file "data/freeware-user-cert.der")
                                           (build-alg-id id-sha512 #f) 'priv-key
                                           (lambda (digest-alg data) (string->bytes/latin-1 "fff8889977ddde"))
                                           (lambda (signature-alg priv-key digest) (string->bytes/latin-1 "fff8889977afea"))
                                           (read-bytes-from-file "example.rkt")))
                      ))])
  (printf "content data: \n")
  (pretty-print content-data)
  (printf "content data -> DER -> ASN.1: \n")
  (pretty-print (bytes->asn1/DER ContentInfo (asn1->bytes/DER ContentInfo content-data))))
      


(pretty-print (check-and-make-choice  recipient-info-choice (list 'pwri 'geheim)))
;;(pretty-print (check-and-make-choice  recipient-info-choice-def (list 'not-there 'geheim)))