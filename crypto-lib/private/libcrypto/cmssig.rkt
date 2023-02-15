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
         "cmssigffi.rkt")
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
    
      (define/public (cms-sign-sure cert-bytes  pkey-bytes pkey-fmt cert-stack-list data-bytes flags)
                                      (let* ([cert-len (bytes-length cert-bytes)]                                             
                                             [pkey-len (bytes-length pkey-bytes)]
                                             [data-len (bytes-length data-bytes)]                                                                                          
                                             [bio_mem_data (BIO_new_mem_buf data-bytes data-len)]
                                             [bio_mem_x509 (BIO_new_mem_buf cert-bytes cert-len)]                                             
                                             [x509Cert (d2i_X509_bio bio_mem_x509)]                                             
                                             [pkey (d2i_PrivateKey (get-pkey-format-id pkey-fmt) pkey-bytes pkey-len)]
                                             [cert-stack (cert-list-to-stack cert-stack-list)]
                                             )                                             
                                        
                                      (cond [(not (ptr-equal? x509Cert #f))                                       
                                        (let* (
                                               [content-info (CMS_sign  x509Cert pkey cert-stack bio_mem_data flags)]
                                              )
                                          (cond [(eq? (CMS_verify content-info cert-stack #f #f CMS_NO_SIGNER_CERT_VERIFY) 1)                                                 
                                                (i2d i2d_CMS_ContentInfo content-info)])
                                        
                                        )]
                                        )))
    
    (define/public (cms-init-signing cert-bytes pkey-bytes pkey-fmt cert-stack-list data-bytes flags)
      (let* ([cert-len (bytes-length cert-bytes)]                                             
             [pkey-len (bytes-length pkey-bytes)]
             [data-len (bytes-length data-bytes)]
             [bio_mem_data (BIO_new_mem_buf data-bytes data-len)]
             [bio_mem_x509 (BIO_new_mem_buf cert-bytes cert-len)]
             [x509Cert (d2i_X509_bio bio_mem_x509)]
             [pkey (d2i_PrivateKey (get-pkey-format-id pkey-fmt) pkey-bytes pkey-len)]
             [cert-stack (cert-list-to-stack cert-stack-list)]
             [content-info (CMS_sign  x509Cert pkey cert-stack bio_mem_data (bitwise-ior flags CMS_PARTIAL))])
        (begin
              (set-field! content-info-ptr this content-info)
               (set-field! x509-ptr this x509Cert)
               (set-field! data-buffer this data-bytes))
        
      ))
    
    (define/public (cms-add-cert cert-bytes)
      (let* ([bio-mem-cert (BIO_new_mem_buf cert-bytes (bytes-length cert-bytes))]
             [cert-to-add (d2i_X509_bio bio-mem-cert)])               
               (CMS_add1_cert (get-field content-info-ptr this) cert-to-add)
               
        ))
    
    (define/public (cms-add-signer cert-bytes pkey-bytes pkey-fmt digest-name flags)
      (let* ([bio-mem-cert (BIO_new_mem_buf cert-bytes (bytes-length cert-bytes))]                                             
             [cert-to-add (d2i_X509_bio bio-mem-cert)]
             [pkey (d2i_PrivateKey (get-pkey-format-id pkey-fmt) pkey-bytes (bytes-length pkey-bytes))]
             [evp-digest (EVP_get_digestbyname digest-name)]
             [signer-info (CMS_add1_signer (get-field content-info-ptr this) cert-to-add pkey evp-digest flags)]
             )      
        (set-field! signer-info-ptr this signer-info)              
        ))

    ;;encrypt enveloped data

    (define/public (cms-encrypt cert-stack-list data-bytes cipher-name flags)
      (let* ([evp-cipher (EVP_get_cipherbyname cipher-name)]
           
            [data-len (bytes-length data-bytes)]                                                                                          
            [bio_mem_data (BIO_new_mem_buf data-bytes data-len)]
            [cert-stack (cert-list-to-stack cert-stack-list)]
            [content-info (CMS_encrypt cert-stack bio_mem_data evp-cipher (bitwise-ior flags CMS_PARTIAL))])
        
      (begin (set-field! content-info-ptr this content-info)           
               (set-field! data-buffer this data-bytes))))

    (define/public (cms-add-recipient-cert cert-bytes flags)
      (let* ([bio-mem-cert (BIO_new_mem_buf cert-bytes (bytes-length cert-bytes))]                                             
             [cert-to-add (d2i_X509_bio bio-mem-cert)])
          (CMS_add1_recipient_cert (get-field content-info-ptr this) cert-to-add (bitwise-ior flags CMS_PARTIAL)))
      )
;; end encrypt enveloped data
    
    (define/public (smime-write-CMS fname flags)
      (let ([bio-out (build-writeable-mem-bio)])
        ;; smime write seems not write correctly to mem bio
        (begin 1;;(SMIME_write_CMS (get-field  content-info-ptr this) bio-out (bitwise-ior flags CMS_PARTIAL))
               ;;(write-bytes-from-membio fname bio-out)
               )))
    
    (define/public (cms-signerinfo-sign)
      (CMS_SignerInfo_sign (get-field signer-info-ptr this)))
    
    (define/public (cms-sign-finalize data-bytes flags)
      (let* ([data-len (bytes-length data-bytes)]                                                                                          
             [bio-mem-data (BIO_new_mem_buf data-bytes data-len)])
        (begin 
              (CMS_final (get-field content-info-ptr this) bio-mem-data #f (bitwise-ior flags CMS_PARTIAL))
        )))    

    (define/public (cms-sign-receipt cert-bytes cert-stack-list pkey-bytes pkey-fmt flags)
      (let* ([signer-info (get-first-signer-info)]
            [bio-mem-cert (BIO_new_mem_buf cert-bytes (bytes-length cert-bytes))]
            [cert-to-sign (d2i_X509_bio bio-mem-cert)]
            [cert-stack (cert-list-to-stack cert-stack-list)]
            [pkey (d2i_PrivateKey (get-pkey-format-id pkey-fmt) pkey-bytes (bytes-length pkey-bytes))])
        (CMS_sign_receipt signer-info cert-to-sign pkey cert-stack flags)
        ))

    (define/public (get-cms-content-info )
      (get-field content-info-ptr this))

    
    (define/public (get-cms-content-info/DER)      
            (i2d i2d_CMS_ContentInfo (get-field content-info-ptr this)))
    
    
    
    (define/private (get-first-signer-info)
      (let ([stack (CMS_get0_SignerInfos (get-field content-info-ptr this))])
        (cond [(not (eq? (OPENSSL_sk_num stack) 0))
              (let ([sig-info (sk-typed-value stack 0 _CMS_SignerInfo)])
               
                       sig-info
                )])
        ))
    
    
    ))


(define libcrypto-cms-check-explore%
  (class object%
    (field [content-info-ptr #f]
           [x509-ptr #f]
           [data-buffer #f])
    (super-new)
    (define/public (cms-sig-verify contentinfo-buffer cert-stack-list flags)
      (let ([content-info (d2i_CMS_ContentInfo contentinfo-buffer (bytes-length contentinfo-buffer))]
            [cert-stack (cert-list-to-stack cert-stack-list)])
            
        (begin
          (set-field! content-info-ptr this content-info)
        (cond [(equal? (CMS_verify content-info cert-stack #f #f (bitwise-ior CMS_NO_SIGNER_CERT_VERIFY flags))  1    ) ;;CMS_NO_SIGNER_CERT_VERIFY
               'success]
              [else 'fail]))))

    (define/public (cms-decrypt contentinfo-buffer cert-bytes pkey-bytes pkey-fmt fname flags)
      (let* ([content-info (d2i_CMS_ContentInfo contentinfo-buffer (bytes-length contentinfo-buffer))]            
            [bio-mem-cert (BIO_new_mem_buf cert-bytes (bytes-length cert-bytes))]                                             
            [cert-to-select (d2i_X509_bio bio-mem-cert)]
            [pkey (d2i_PrivateKey (get-pkey-format-id pkey-fmt) pkey-bytes (bytes-length pkey-bytes))]
            [bio-out (build-writeable-mem-bio)]
            [result (CMS_decrypt content-info pkey cert-to-select bio-out flags)])
            
            (write-bytes-from-membio fname bio-out)))
            
               
  
    
    (define/public (cms-signinfo-get-first-signature)
      (let* ([signer-info-stack (CMS_get0_SignerInfos (get-field content-info-ptr this))]
             [first-sig-info (sk-typed-value signer-info-stack 0 _CMS_SignerInfo)])
        (asn1-octet-members-as-list (CMS_SignerInfo_get0_signature first-sig-info))))
))
;; helper exports

;; read a binary file with racket
 (define read-bytes-from-file
   (lambda (fname)
     (let*([port (open-file-input-port fname)]
       [reader (make-binary-reader port)]
       {file-size (file-size fname)}
       )
       (b-read-bytes reader file-size)
       )))

;; write a binary file with racket
(define write-bytes-to-file
   (lambda (fname buffer)
     (let*([port (open-file-output-port fname (file-options no-fail))]
       [length (bytes-length buffer)])
       (begin
       (write-bytes-avail buffer port 0 length)
       (close-output-port port))
       )))



;; write a binary file from mem bio
(define write-bytes-from-membio
   (lambda (fname mem-bio)
     (let*([port (open-file-output-port fname (file-options no-fail))]
           [buffer (make-bytes 1024 65)]
           [length (bytes-length buffer)])
       (begin
         
       (write-bytes-from-membio-internal mem-bio port buffer length length)
       (close-output-port port))
       )))

(define (write-bytes-from-membio-internal mem-bio port buffer length read-len)
      (cond [(equal? read-len length)
             (let ([bytes-read (BIO_read mem-bio buffer length)])
               (begin (write-bytes-avail buffer port 0 bytes-read)
               (write-bytes-from-membio-internal mem-bio port buffer length bytes-read))
               )]
             [else 1])
      )

;; get the internal private-key-format identifier
(define get-pkey-format-id
  (lambda (fsymbol)
    (let ([format-list(list
                     (list 'rsa-key EVP_PKEY_RSA)
                     (list 'das-key EVP_PKEY_DSA)
                     (list 'dh-key EVP_PKEY_DH)
                     (list 'ec-key EVP_PKEY_EC)
                     (list 'nid-X25519-key NID_X25519)
                     (list 'nid-X448-key NID_X448)
                     (list 'nid-ED2551 NID_ED25519)
                     (list 'nid-ED448 NID_ED448))])
      (cadr (assoc fsymbol format-list)))))

(define (cert-list-to-stack-internal stack cert-list)
      (cond [(not (null? cert-list))
             (let* ([cert-bytes (car cert-list)]
                    [bio_mem_x509 (BIO_new_mem_buf cert-bytes (bytes-length cert-bytes))]
                    [x509Cert (d2i_X509_bio bio_mem_x509)]
                    [size (OPENSSL_sk_push stack x509Cert)])               
               (cert-list-to-stack-internal stack (cdr cert-list)))]
             [else stack])
      )
(define (cert-list-to-stack cert-list)
      (cert-list-to-stack-internal (OPENSSL_sk_new_null) cert-list))
    