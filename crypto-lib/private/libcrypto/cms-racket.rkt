;; Copyright 2023-2025 Harald Glab-Plhak
;;
;; This library is free software: you can redistribute it and/or modify
;; it under the terms of the GNU Lesser General Public License as published
;; by the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.
;; 
;; This library is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU Lesser General Public License for more details.
;; 
;; You should have received a copy of the GNU Lesser General Public License
;; along with this library.  If not, see <http://www.gnu.org/licenses/>.

#lang racket/base
(require ffi/unsafe
         racket/class
         racket/pretty
         asn1
         ;;"../common/asn1.rkt"
         "../crypto-asn1/private/cmssig-asn1.rkt"
         "../crypto-asn1/private/cms-builder.rkt" ;;import for test delete if tested
         "../crypto-asn1/private/asn1-oids.rkt"
         "cmssig.rkt" ;; only for quick test
         "ffi.rkt")
(provide (all-defined-out))

;;utility funs

(define (calc-digest-proc digest-alg-id/DER data)
  (let* ([evp-md (get-digest-by-obj/DER digest-alg-id/DER)]
         [ctx (EVP_MD_CTX_create)]
         [size (EVP_MD_size evp-md)]
         [outbuf (make-bytes size)])                            
    (EVP_Digest data (bytes-length data) outbuf evp-md)
    (EVP_MD_CTX_destroy ctx)
    outbuf))
(define (sign-digest-proc digest-alg-id/DER private-key data)
  (let* ([evp-md (get-digest-by-obj/DER digest-alg-id/DER)]
         [ctx (EVP_MD_CTX_create)]
         [evp-priv-key (d2i_AutoPrivateKey private-key (bytes-length private-key))]
         [ret-init (EVP_DigestSignInit ctx evp-md evp-priv-key)]
         [dummy 0]
         [sig-length (EVP_DigestSign ctx #f  dummy data (bytes-length data))])
    (cond [(> sig-length 1)
           (let ([sig (make-bytes sig-length 0)])            
             (printf "sig-len : ~a \n" sig-length)
             (EVP_DigestSign ctx sig (bytes-length sig) data (bytes-length data))
             (EVP_MD_CTX_destroy ctx)
             sig)]
          [else #f])))

             
  

(calc-digest-proc (asn1->bytes/DER OBJECT-IDENTIFIER id-sha512)
                  (string->bytes/latin-1 "Hello this is romeo calling me "))
(sign-digest-proc (asn1->bytes/DER OBJECT-IDENTIFIER id-sha512)
                  (read-bytes-from-file  "data/freeware-user-key.der")  ;; as key
                  (read-bytes-from-file  "data/freeware-user-key.der")) ;; key as data

(let ([content-data  (build-cms-content
                      id-cms-signed-data
                      (send+ (new signed-data-builder%)                      
                             (add-content-bytes
                              (read-bytes-from-file "cms-ffi.rkt"))                      
                             (add-signer-info)
                             (add-digest-alg
                              (build-alg-id id-sha512 #f))
                             (add-cert-bytes
                              (read-bytes-from-file "data/freeware-user-cert.der"))
                             (add-private-key
                             (read-bytes-from-file "data/freeware-user-key.der"))
                             (add-calc-digest-proc
                              calc-digest-proc)
                             (add-sign-digest-proc
                              sign-digest-proc)
                             (end-def)
                             (add-signer-info)
                             (add-digest-alg
                              (build-alg-id id-sha512 #f))
                             (add-cert-bytes
                              (read-bytes-from-file "data/freeware-user-cert_1.der"))
                             (add-private-key
                               (read-bytes-from-file "data/freeware-user-key_1.der"))
                             (add-calc-digest-proc
                              calc-digest-proc)
                              (add-sign-digest-proc
                              sign-digest-proc)
                             (end-def)
                             (build-asn1))
                      )]) (printf "==================================================================\n")
  (printf "=========== CLASSES LOGIC ==================\n" )
  (printf "==================================================================\n" )
  (printf "content data: \n")
  (pretty-print content-data)
  (printf "content data -> DER -> ASN.1: \n")
  (write-bytes-to-file "data/racket.pkcs7" (asn1->bytes/DER ContentInfo content-data))
  (pretty-print (bytes->asn1/DER ContentInfo (asn1->bytes/DER ContentInfo content-data))))



