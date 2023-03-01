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
(provide (all-defined-out)
         get-asn1-data)

(define libcrypto-cms-sign%
  (class* impl-base% (cms-sign<%>)
  (inherit-field factory)
  (super-new (spec 'cms-sign))

    
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
                                               [content-info (CMS_sign  x509Cert pkey cert-stack bio_mem_data
                                                                        (build-attr-val-from-list 0 flags))]
                                              )
                                          (cond [(eq? (CMS_verify content-info cert-stack #f #f
                                                                  (build-attr-val-from-list
                                                                   (get-cms-attr 'cms-no-signer-cert-verify) flags))
                                                      1)
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
             [content-info (CMS_sign  x509Cert pkey cert-stack bio_mem_data (build-attr-val-from-list
                                                                   (get-cms-attr 'cms-partial) flags))])
        (box-immutable content-info)
      ))
    
    (define/public (cms-add-cert box-content-info cert-bytes)
      (let* ([bio-mem-cert (BIO_new_mem_buf cert-bytes (bytes-length cert-bytes))]
             [cert-to-add (d2i_X509_bio bio-mem-cert)])               
               (CMS_add1_cert (unbox box-content-info) cert-to-add)
               
        ))
    
    (define/public (cms-add-signer box-content-info cert-bytes pkey-bytes pkey-fmt digest-name flags)
      (let* ([bio-mem-cert (BIO_new_mem_buf cert-bytes (bytes-length cert-bytes))]                                             
             [cert-to-add (d2i_X509_bio bio-mem-cert)]
             [pkey (d2i_PrivateKey (get-pkey-format-id pkey-fmt) pkey-bytes (bytes-length pkey-bytes))]
             [evp-digest (EVP_get_digestbyname digest-name)]
             [signer-info (CMS_add1_signer (unbox box-content-info) cert-to-add pkey evp-digest (build-attr-val-from-list 0 flags))]
             )      
        (box-immutable signer-info)
        ))

    ;;encrypt enveloped data

    (define/public (cms-encrypt cert-stack-list data-bytes cipher-name flags)
      (let* ([evp-cipher (EVP_get_cipherbyname cipher-name)]           
            [data-len (bytes-length data-bytes)]                                                                                          
            [bio_mem_data (BIO_new_mem_buf data-bytes data-len)]
            [cert-stack (cert-list-to-stack cert-stack-list)]
            [content-info (CMS_encrypt cert-stack bio_mem_data evp-cipher (build-attr-val-from-list
                                                                   (get-cms-attr 'cms-partial) flags))])
        
      (box-immutable content-info)))

    (define/public (cms-encrypt-with-skey skey-bytes data-bytes cipher-name flags)
      (let* ([evp-cipher (EVP_get_cipherbyname cipher-name)]           
            [data-len (bytes-length data-bytes)]                                                                                          
            [bio_mem_data (BIO_new_mem_buf data-bytes data-len)]
            [content-info (CMS_EncryptedData_encrypt bio_mem_data evp-cipher skey-bytes (bytes-length skey-bytes)
                                                     (build-attr-val-from-list
                                                                   0 flags))])
        
      (box-immutable content-info)))

    (define/public (cms-add-recipient-cert box-content-info cert-bytes flags)
      (let* ([bio-mem-cert (BIO_new_mem_buf cert-bytes (bytes-length cert-bytes))]                                             
             [cert-to-add (d2i_X509_bio bio-mem-cert)])
          (CMS_add1_recipient_cert (unbox box-content-info) cert-to-add (build-attr-val-from-list
                                                                   (get-cms-attr 'cms-partial) flags)))
      )
;; end encrypt enveloped data
    
    (define/public (smime-write-CMS box-content-info fname flags)
      (let ([bio-out (build-writeable-mem-bio)])
        ;; smime write seems not write correctly to mem bio
        (begin (SMIME_write_CMS bio-out (unbox  box-content-info)  #f (build-attr-val-from-list
                                                                   0 flags)))
               (write-bytes-from-membio fname bio-out)
               ))

    (define/public (smime-write-CMS-detached box-content-info fname data-bytes flags)
      (let ([bio-out (build-writeable-mem-bio)]
             [bio_mem_data (BIO_new_mem_buf data-bytes (bytes-length data-bytes))])
        ;; smime write seems not write correctly to mem bio
        (begin (SMIME_write_CMS bio-out (unbox  box-content-info)  (build-attr-val-from-list
                                                                   0 flags)))
               (write-bytes-from-membio fname bio-out)
               ))
    
    (define/public (cms-signerinfo-sign)
      (CMS_SignerInfo_sign (get-field signer-info-ptr this)))
    
    (define/public (cms-sign-finalize box-content-info data-bytes flags)
      (let* ([data-len (bytes-length data-bytes)]                                                                                          
             [bio-mem-data (BIO_new_mem_buf data-bytes data-len)])
        (begin 
              (CMS_final (unbox box-content-info) bio-mem-data #f (build-attr-val-from-list
                                                                   (get-cms-attr 'cms-partial) flags))
        )))    

    (define/public (cms-sign-receipt cert-bytes cert-stack-list pkey-bytes pkey-fmt flags)
      (let* ([signer-info (get-first-signer-info)]
            [bio-mem-cert (BIO_new_mem_buf cert-bytes (bytes-length cert-bytes))]
            [cert-to-sign (d2i_X509_bio bio-mem-cert)]
            [cert-stack (cert-list-to-stack cert-stack-list)]
            [pkey (d2i_PrivateKey (get-pkey-format-id pkey-fmt) pkey-bytes (bytes-length pkey-bytes))])
        (CMS_sign_receipt signer-info cert-to-sign pkey cert-stack (build-attr-val-from-list
                                                                   0 flags))
        ))

    (define/public (get-cms-content-info box-content-info )
      (unbox box-content-info))

    (define/public (get-cms-content-info-type box-content-info)
        (get-asn1-data (CMS_get0_type (unbox box-content-info))))
    
    (define/public (get-cms-content-info/DER box-content-info)      
            (i2d i2d_CMS_ContentInfo (unbox box-content-info)))

    (define/public (get-pkey-format-from-sym pkey-fmt)
                   (get-pkey-format-id pkey-fmt))    
    
    (define/private (get-first-signer-info box-content-info)
      (let ([stack (CMS_get0_SignerInfos (unbox box-content-info))])
        (cond [(not (eq? (OPENSSL_sk_num stack) 0))
              (let ([sig-info (sk-typed-value stack 0 _CMS_SignerInfo)])
               
                       sig-info
                )])
        ))
    
    
    ))


(define libcrypto-cms-check-explore%
  (class object%
    
    (super-new)
    
    (define/public (cms-sig-verify contentinfo-buffer cert-stack-list flags)
      (let ([content-info (d2i_CMS_ContentInfo contentinfo-buffer (bytes-length contentinfo-buffer))]
            [cert-stack (cert-list-to-stack cert-stack-list)])
            
        (begin          
        (cond [(equal? (CMS_verify content-info cert-stack #f #f  (build-attr-val-from-list
                                                                   (get-cms-attr 'cms-no-signer-cert-verify) flags))  1    ) ;;CMS_NO_SIGNER_CERT_VERIFY
               (box content-info)]
              [else 'fail]))))

    (define/public (cms-decrypt contentinfo-buffer cert-bytes pkey-bytes pkey-fmt fname flags)
      (let* ([content-info (d2i_CMS_ContentInfo contentinfo-buffer (bytes-length contentinfo-buffer))]
            [bio-mem-cert (BIO_new_mem_buf cert-bytes (bytes-length cert-bytes))]                                             
            [cert-to-select (d2i_X509_bio bio-mem-cert)]
            [pkey (d2i_PrivateKey (get-pkey-format-id pkey-fmt) pkey-bytes (bytes-length pkey-bytes))]
            [bio-out (build-writeable-mem-bio)]
            [result (begin (CMS_decrypt_set1_pkey content-info pkey cert-to-select)
                      (CMS_decrypt content-info #f #f bio-out (build-attr-val-from-list 0
                                                                    flags)))])            
            (write-bytes-from-membio fname bio-out)))

    (define/public (cms-smime-decrypt smimecont-buffer cert-bytes pkey-bytes pkey-fmt fname flags)
      (let* ([smime-bio (BIO_new_mem_buf smimecont-buffer (bytes-length smimecont-buffer))]
             [content-info
              (cond [(not (ptr-equal? smime-bio #f)) (SMIME_read_CMS smime-bio)]
                      [else #f])]
            [bio-mem-cert (BIO_new_mem_buf cert-bytes (bytes-length cert-bytes))]                                             
            [cert-to-select (cond [(not (ptr-equal? bio-mem-cert #f)) (d2i_X509_bio bio-mem-cert)]
                      [else  #f])]
            [pkey (d2i_PrivateKey (get-pkey-format-id pkey-fmt) pkey-bytes (bytes-length pkey-bytes))]
            [bio-out (build-writeable-mem-bio)]
            [result (begin
                      (CMS_decrypt_set1_pkey content-info pkey cert-to-select)
                      (CMS_decrypt content-info #f #f bio-out (build-attr-val-from-list 0
                                                                    flags)))])            
            (write-bytes-from-membio fname bio-out)))
            
               
  (define/public (cms-decrypt-with-skey  contentinfo-buffer skey-bytes fname flags)
      (let* ([bio-out (build-writeable-mem-bio)]
             [content-info (d2i_CMS_ContentInfo contentinfo-buffer (bytes-length contentinfo-buffer))]

             [result (CMS_EncryptedData_decrypt content-info skey-bytes (bytes-length skey-bytes)
                                                #f bio-out
                                                     (build-attr-val-from-list
                                                                   0 flags))])
        
      (write-bytes-from-membio fname bio-out)))
    
    (define/public (cms-signinfo-get-first-signature box-content-info)
      (let* ([signer-info-stack (CMS_get0_SignerInfos (unbox box-content-info))]
             [first-sig-info (sk-typed-value signer-info-stack 0 _CMS_SignerInfo)])
        (asn1-octet-members-as-list (CMS_SignerInfo_get0_signature first-sig-info))))
))
;; helper exports

;; read a binary file with racket
 (define read-bytes-from-file
   (lambda (fname)
     (let*([port (open-file-input-port fname)]
       [reader (make-binary-reader port)]
       [file-size (file-size fname)])
       (let ([buffer (b-read-bytes reader file-size)])
         (close-input-port port)
         buffer)
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
    (let ([search-key (cond[(string? fsymbol) (string->symbol fsymbol)]
                           [else fsymbol])]
          [format-list(list
                     (list 'rsa-key EVP_PKEY_RSA)
                     (list 'das-key EVP_PKEY_DSA)
                     (list 'dh-key EVP_PKEY_DH)
                     (list 'ec-key EVP_PKEY_EC)
                     (list 'nid-X25519-key NID_X25519)
                     (list 'nid-X448-key NID_X448)
                     (list 'nid-ED2551 NID_ED25519)
                     (list 'nid-ED448 NID_ED448))])
      (cadr (assoc search-key format-list)))))

;; functions to make cms-attributes accessible
(define cms-attributes-assoc-list (list
(list 'cms-text CMS_TEXT)
(list 'cms-nocerts CMS_NOCERTS)
(list 'cms-no-content-verify CMS_NO_CONTENT_VERIFY)
(list 'cms-no-attr-verify CMS_NO_ATTR_VERIFY        )
(list 'cms-nointern CMS_NOINTERN                    )
(list 'cms-no-signer-cert-verify CMS_NO_SIGNER_CERT_VERIFY       )
(list 'cms-noverify CMS_NOVERIFY                    )
(list 'cms-detached CMS_DETACHED                    )
(list 'cms-binary CMS_BINARY                      )
(list 'cms-no-attr CMS_NOATTR                      )
(list 'cms-nosmimecap CMS_NOSMIMECAP                  )
(list 'cms-nooldmimetype CMS_NOOLDMIMETYPE               )
(list 'cms-crleof CMS_CRLFEOL                     )
(list 'cms-stream CMS_STREAM                      )
(list 'cms-nocrl CMS_NOCRL                       )
(list 'cms-partial CMS_PARTIAL                     )
(list 'cms-reuse-digest CMS_REUSE_DIGEST                )
(list 'cms-use-keyid CMS_USE_KEYID                   )
(list 'cms-debug-decrypt CMS_DEBUG_DECRYPT               )
(list 'cms-key-param CMS_KEY_PARAM                   )
(list 'cms-asciicrlf CMS_ASCIICRLF                   )
(list 'cms-cades CMS_CADES                       )
(list 'cms-use-originator-keyid CMS_USE_ORIGINATOR_KEYID        )))

(define (get-cms-attrs-from-list attr-sym-list)
    (map (lambda (search-key)
         (cadr (assoc search-key cms-attributes-assoc-list))) attr-sym-list))

(define (get-cms-attr attr-sym)
        (let ([value (assoc attr-sym cms-attributes-assoc-list)])
          (cond [(not (eq? value #f)) (cadr value)]
                [else 0])))

(define (list-of-num->ior-val start-val values-list)
  (let ([value start-val])
    (cond [(not (null? values-list))
           (let ([result (bitwise-ior value (car values-list))])
             (list-of-num->ior-val result (cdr values-list)))]
          [else start-val])))

(define (build-attr-val-from-list start-val sym-list)
  (list-of-num->ior-val start-val (get-cms-attrs-from-list sym-list)))
             
;; build up a internal stack fom a list
(define (cert-list-to-stack-internal stack cert-list)
      (cond [(not (null? cert-list))
             (let* ([cert-bytes (car cert-list)]
                    [bio_mem_x509 (BIO_new_mem_buf cert-bytes (bytes-length cert-bytes))]
                    [x509Cert (d2i_X509_bio bio_mem_x509)]
                    [size (OPENSSL_sk_push stack x509Cert)])
               (printf "cert-pointer ~a \n" x509Cert)
               (cert-list-to-stack-internal stack (cdr cert-list)))]
             [else stack])
      )
;; public caller for definition above
(define (cert-list-to-stack cert-list)
      (cert-list-to-stack-internal (OPENSSL_sk_new_null) cert-list))

(define get-symkey
  (lambda(cipher-name)
    (let* ([evp-cipher (EVP_get_cipherbyname cipher-name)]
           [key-len (EVP_CIPHER_key_length evp-cipher)])
      (crypto-random-bytes key-len))))