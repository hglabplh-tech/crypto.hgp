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
         binaryio/reader
         rnrs/io/ports-6
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
    ;;(class* impl-base% (cms-sign<%>)
    ;;(inherit-field factory)
    ;;(super-new (spec 'libcrypto-cms-sign))
  (super-new)

    (field [content-info-ptr #f]
           [signer-info-ptr #f]
           [x509-ptr #f]
           [data-buffer #f]
           [cert-chain-stack (OPENSSL_sk_new_null)])
    
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
                                        )))
    
    (define/public (cms-init-signing cert-bytes pkey-bytes data-bytes flags)
      (let* ([cert-len (bytes-length cert-bytes)]                                             
             [pkey-len (bytes-length pkey-bytes)]
             [data-len (bytes-length data-bytes)]
             [bio_mem_data (BIO_new_mem_buf (buff-pointer-new data-bytes) data-len)]
             [bio_mem_x509 (BIO_new_mem_buf (buff-pointer-new cert-bytes) cert-len)]
             [x509Cert (d2i_X509_bio bio_mem_x509)]
             [pkey (d2i_PrivateKey EVP_PKEY_RSA pkey-bytes pkey-len)]
             [content-info (CMS_sign  x509Cert pkey #f bio_mem_data (bitwise-ior flags CMS_PARTIAL))])
        (begin
              (set-field! content-info-ptr this content-info)
               (set-field! x509-ptr this x509Cert)
               (set-field! data-buffer this data-bytes))
        
      ))
    
    (define/public (cms-add-cert cert-bytes)
      (let* ([bio-mem-cert (BIO_new_mem_buf (buff-pointer-new cert-bytes) (bytes-length cert-bytes))]                                             
             [cert-to-add (d2i_X509_bio bio-mem-cert)])
        (begin
               (OPENSSL_sk_push (get-field cert-chain-stack this) cert-to-add)
               (CMS_add1_cert (get-field content-info-ptr this) cert-to-add))
               
        ))
    
    (define/public (cms-add-signer cert-bytes pkey-bytes digest-name flags)
      (let* ([bio-mem-cert (BIO_new_mem_buf (buff-pointer-new cert-bytes) (bytes-length cert-bytes))]                                             
             [cert-to-add (d2i_X509_bio bio-mem-cert)]
             [pkey (d2i_PrivateKey EVP_PKEY_RSA pkey-bytes (bytes-length pkey-bytes))]
             [evp-digest (EVP_get_digestbyname digest-name)]
             [signer-info (CMS_add1_signer (get-field content-info-ptr this) cert-to-add pkey evp-digest flags)]
             )      
        (set-field! signer-info-ptr this signer-info)              
        ))

    ;;encrypt enveloped data

    (define/public (cms-encrypt cert-bytes data-bytes cipher-name flags)
      (let* ([evp-cipher (EVP_get_cipherbyname cipher-name)]
            [cert-len (bytes-length cert-bytes)]
            [data-len (bytes-length data-bytes)]                                                                                          
            [bio_mem_data (BIO_new_mem_buf (buff-pointer-new data-bytes) data-len)]
            [bio_mem_x509 (BIO_new_mem_buf (buff-pointer-new cert-bytes) cert-len)]
            [x509Cert (d2i_X509_bio bio_mem_x509)]
            [stack_len (OPENSSL_sk_push cert-chain-stack x509Cert)]
            [content-info (CMS_encrypt cert-chain-stack bio_mem_data evp-cipher (bitwise-ior flags CMS_PARTIAL))])
        
      (begin (set-field! content-info-ptr this content-info)
               (set-field! x509-ptr this x509Cert)
               (set-field! data-buffer this data-bytes))))

    (define/public (cms-add-receipient-cert cert-bytes flags)
      (let* ([bio-mem-cert (BIO_new_mem_buf (buff-pointer-new cert-bytes) (bytes-length cert-bytes))]                                             
             [cert-to-add (d2i_X509_bio bio-mem-cert)])
          (CMS_add1_recipient_cert (get-field content-info-ptr this) cert-to-add flags))
      )
;; end encrypt enveloped data
    (define/public (cms-signerinfo-sign)
      (CMS_SignerInfo_sign (get-field signer-info-ptr this)))
    
    (define/public (cms-sign-finalize data-bytes flags)
      (let* ([data-len (bytes-length data-bytes)]                                                                                          
             [bio-mem-data (BIO_new_mem_buf (buff-pointer-new data-bytes) data-len)])
        (begin 
              (CMS_final (get-field content-info-ptr this) bio-mem-data #f (bitwise-ior flags CMS_PARTIAL))
        )))
    
    (define/public (get-cms-content-info )
      (get-field content-info-ptr this))
    
    (define/public (get-cms-content-info/DER)      
            (i2d i2d_CMS_ContentInfo (get-field content-info-ptr this)))

    (define/public (cms-sign-receipt cert-bytes pkey-bytes flags)
      (let* ([signer-info (get-first-signer-info)]
            [bio-mem-cert (BIO_new_mem_buf (buff-pointer-new cert-bytes) (bytes-length cert-bytes))]
            [cert-to-sign (d2i_X509_bio bio-mem-cert)]
            [pkey (d2i_PrivateKey EVP_PKEY_RSA pkey-bytes (bytes-length pkey-bytes))])
        (CMS_sign_receipt signer-info cert-to-sign pkey #f flags)
        ))
    
    (define/private (get-first-signer-info)
      (let ([stack (CMS_get0_SignerInfos (get-field content-info-ptr this))])
        (cond [(not (eq? (OPENSSL_sk_num stack) 0))
              (let ([sig-info (sk-typed-value stack 0 _CMS_SignerInfo)])
                (begin (display (ptr-ref sig-info _pointer))
                       sig-info)
                )])
        ))
    ))


;; helper exports
 (define read-bytes-from-file
   (lambda (fname)
     (let*([port (open-file-input-port fname)]
       [reader (make-binary-reader port)]
       {file-size (file-size fname)}
       )
       (b-read-bytes reader file-size)
       )))
(define write-bytes-to-file
   (lambda (fname buffer)
     (let*([port (open-file-output-port fname (file-options no-fail))]
       [length (bytes-length buffer)])
       (begin
       (write-bytes buffer port 0 length)
       (close-output-port port))
       )))


(define libcrypto-cms-verify%
  (class object%
    (field [content-info-ptr #f]
           [x509-ptr #f]
           [data-buffer #f])
    (super-new)))