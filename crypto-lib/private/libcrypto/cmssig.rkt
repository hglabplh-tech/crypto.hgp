#lang racket/base
;; Copyright 2012-2018 Ryan Culpepper
;; Copyright 2007-2009 Dimitris Vyzovitis <vyzo at media.mit.edu>
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


(require ffi/unsafe
         racket/class
         racket/match
         asn1
         "../common/interfaces.rkt"
         "../common/catalog.rkt"
         "../common/common.rkt"
         "../common/cmssigbase.rkt"
         "../common/asn1.rkt"
         "../common/error.rkt"
         "ffi.rkt"
         "digest.rkt")
(provide (all-defined-out))

(define libcrypto-cms-sign%
  (class object% 
    (super-new)
      (define/public (cms-sign-sure cert-bytes ca-cert-bytes pkey-bytes data-bytes flags)
                                      (let* ([cert-len (bytes-length cert-bytes)]
                                             [ca-cert-len (bytes-length ca-cert-bytes)]
                                             [pkey-len (bytes-length pkey-bytes)]
                                             [data-len (bytes-length data-bytes)]                                                                                          
                                             [bio_mem_data (BIO_new_mem_buf (buff-pointer-new data-bytes) data-len)]
                                             [bio_mem_x509 (BIO_new_mem_buf (buff-pointer-new cert-bytes) cert-len)]
                                             [bio_mem_x509-ca (BIO_new_mem_buf (buff-pointer-new ca-cert-bytes) ca-cert-len)]
                                             [x509Cert (d2i_X509_bio bio_mem_x509)]
                                             [x509Cert-ca (d2i_X509_bio bio_mem_x509-ca)]
                                             [pkey (d2i_PrivateKey EVP_PKEY_RSA pkey-bytes pkey-len)]
                                             [cert-stack (OPENSSL_sk_new_null)]                                             
                                             [stackret (OPENSSL_sk_push cert-stack x509Cert-ca)])                                             
                                        
                                      (cond [(not (ptr-equal? x509Cert #f))                                       
                                        (let* (
                                               [content-info (CMS_sign  x509Cert pkey cert-stack bio_mem_data flags)]
                                              )
                                          (cond [(eq? (CMS_verify content-info cert-stack #f #f CMS_NO_SIGNER_CERT_VERIFY) 1)
                                                (i2d i2d_CMS_ContentInfo content-info)])
                                        
                                        )]
                                        )))))