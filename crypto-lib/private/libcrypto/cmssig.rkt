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
  (class*  cms-sign-impl-base% (cms-sign<%>)
    (inherit-field factory)
    (super-new (spec 'cms-sign))

    
    (define/override (cms-sign-sure cert-bytes  pkey-bytes pkey-fmt cert-stack-list data-bytes flags)
      (let* ([cert-len (bytes-length cert-bytes)]                                             
             [pkey-len (bytes-length pkey-bytes)]
             [data-len (bytes-length data-bytes)]                                                                                          
             [bio_mem_data (BIO_new_mem_buf data-bytes data-len)]
             [bio_mem_x509 (BIO_new_mem_buf cert-bytes cert-len)]                                             
             [x509Cert (d2i_X509_bio bio_mem_x509)]                                             
             [pkey (d2i_PrivateKey (get-pkey-format-id pkey-fmt) pkey-bytes pkey-len)]
             [cert-stack (cert-list-to-stack cert-stack-list)])
        (cond [(not (ptr-equal? x509Cert #f))
               (let* ([content-info (CMS_sign  x509Cert pkey cert-stack bio_mem_data
                                               (build-attr-val-from-list 0 flags))])
                 (cond [(eq? (CMS_verify content-info cert-stack #f #f
                                         (build-attr-val-from-list
                                          (get-cms-attr 'cms-no-signer-cert-verify) flags)) 1)
                        (i2d i2d_CMS_ContentInfo content-info)]))]
              )))
    
    (define/override (cms-init-signing cert-bytes pkey-bytes pkey-fmt cert-stack-list data-bytes flags)
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
    
    (define/override (cms-add-cert box-content-info cert-bytes)
      (let* ([bio-mem-cert (BIO_new_mem_buf cert-bytes (bytes-length cert-bytes))]
             [cert-to-add (d2i_X509_bio bio-mem-cert)])               
        (CMS_add1_cert (unbox box-content-info) cert-to-add)
               
        ))
    
    (define/override (cms-add-signer box-content-info cert-bytes pkey-bytes pkey-fmt digest-name flags)
      (let* ([bio-mem-cert (BIO_new_mem_buf cert-bytes (bytes-length cert-bytes))]                                             
             [cert-to-add (d2i_X509_bio bio-mem-cert)]
             [pkey (d2i_PrivateKey (get-pkey-format-id pkey-fmt) pkey-bytes (bytes-length pkey-bytes))]
             [evp-digest (EVP_get_digestbyname digest-name)]
             [signer-info (CMS_add1_signer (unbox box-content-info) cert-to-add pkey evp-digest (build-attr-val-from-list 0 flags))]
             )      
        (box-immutable signer-info)
        ))

    ;;encrypt enveloped data

    (define/override (cms-encrypt cert-stack-list data-bytes cipher-name flags)
      (let* ([evp-cipher (EVP_get_cipherbyname cipher-name)]           
             [data-len (bytes-length data-bytes)]                                                                                          
             [bio_mem_data (BIO_new_mem_buf data-bytes data-len)]
             [cert-stack (cert-list-to-stack cert-stack-list)]
             [content-info (CMS_encrypt cert-stack bio_mem_data evp-cipher (build-attr-val-from-list
                                                                            (get-cms-attr 'cms-partial) flags))])
        
        (box-immutable content-info)))

    (define/override (cms-encrypt-with-skey skey-bytes data-bytes cipher-name flags)
      (let* ([evp-cipher (EVP_get_cipherbyname cipher-name)]           
             [data-len (bytes-length data-bytes)]                                                                                          
             [bio_mem_data (BIO_new_mem_buf data-bytes data-len)]
             [content-info (CMS_EncryptedData_encrypt bio_mem_data evp-cipher skey-bytes (bytes-length skey-bytes)
                                                      (build-attr-val-from-list
                                                       0 flags))])
        
        (box-immutable content-info)))

    (define/override (cms-add-recipient-cert box-content-info cert-bytes flags)
      (let* ([bio-mem-cert (BIO_new_mem_buf cert-bytes (bytes-length cert-bytes))]                                             
             [cert-to-add (d2i_X509_bio bio-mem-cert)])
        (CMS_add1_recipient_cert (unbox box-content-info) cert-to-add (build-attr-val-from-list
                                                                       (get-cms-attr 'cms-partial) flags)))
      )
    ;; end encrypt enveloped data
    
    (define/override (smime-write-CMS box-content-info fname flags)
      (let ([bio-out (build-writeable-mem-bio)])
        ;; smime write seems not write correctly to mem bio
        (begin (SMIME_write_CMS bio-out (unbox  box-content-info)  #f (build-attr-val-from-list
                                                                       0 flags)))
        (write-bytes-from-membio fname bio-out)
        ))

    *     (define/override (write-CMS/BER box-content-info fname flags)
            (let ([bio-out (build-writeable-mem-bio)])        
              (begin (i2d_CMS_bio_stream bio-out (unbox  box-content-info)  #f (build-attr-val-from-list
                                                                                0 flags)))
              (write-bytes-from-membio fname bio-out)
              ))


    (define/override (smime-write-CMS-detached box-content-info fname data-bytes flags)
      (let ([bio-out (build-writeable-mem-bio)]
            [bio_mem_data (BIO_new_mem_buf data-bytes (bytes-length data-bytes))])       
        (begin (SMIME_write_CMS bio-out (unbox  box-content-info) bio_mem_data (build-attr-val-from-list
                                                                                0 flags)))
        (write-bytes-from-membio fname bio-out)
        ))
    
    (define/override (cms-signerinfo-sign signer-info)
      (CMS_SignerInfo_sign (unbox signer-info)))
    
    (define/override (cms-sign-finalize box-content-info data-bytes flags)
      (let* ([data-len (bytes-length data-bytes)]                                                                                          
             [bio-mem-data (BIO_new_mem_buf data-bytes data-len)])
        (begin 
          (CMS_final (unbox box-content-info) bio-mem-data #f (build-attr-val-from-list
                                                               (get-cms-attr 'cms-partial) flags))
          )))    

    (define/override (cms-sign-receipt  box-content-info cert-bytes cert-stack-list pkey-bytes pkey-fmt flags)
      (let* ([signer-info (get-first-signer-info box-content-info)]
             [bio-mem-cert (BIO_new_mem_buf cert-bytes (bytes-length cert-bytes))]
             [cert-to-sign (d2i_X509_bio bio-mem-cert)]
             [cert-stack (cert-list-to-stack cert-stack-list)]
             [pkey (d2i_PrivateKey (get-pkey-format-id pkey-fmt) pkey-bytes (bytes-length pkey-bytes))])
        (CMS_sign_receipt (unbox signer-info) cert-to-sign pkey cert-stack (build-attr-val-from-list
                                                                            0 flags))
        ))

    (define/override (get-cms-content-info box-content-info )
      (unbox box-content-info))

    (define/override (get-cms-content-info-type box-content-info)
      (get-cms-cont-info-type (unbox box-content-info)))
    
    (define/override (get-cms-content-info/DER box-content-info)      
      (i2d i2d_CMS_ContentInfo (unbox box-content-info)))

    (define/override (get-pkey-format-from-sym pkey-fmt)
      (get-pkey-format-id pkey-fmt))
    
    (define/override (get-symmetric-key cipher-name)  
      (let* ([evp-cipher (EVP_get_cipherbyname cipher-name)]
             [key-len (EVP_CIPHER_key_length evp-cipher)])
        (crypto-random-bytes key-len)))
    
    (define/private (get-first-signer-info box-content-info)
      (let ([stack (CMS_get0_SignerInfos (unbox box-content-info))])
        (cond [(not (eq? (OPENSSL_sk_num stack) 0))
               (let ([sig-info (sk-typed-value stack 0 _CMS_SignerInfo)])
               
                 (box-immutable sig-info)
                 )])
        ))

   
    
    ))


(define libcrypto-cms-check-explore%
  (class* cms-check-explore-impl-base% (cms-check-explore<%>)
    (inherit-field factory)
    (super-new (spec 'cms-check-explore))

    (define/override (cms-content/DER->content-info  content-info-buffer)
      (let ([content-info
             (d2i_CMS_ContentInfo content-info-buffer (bytes-length content-info-buffer))])
        (cond [(not (ptr-equal? content-info #f)) (box-immutable content-info)]
              [else #f])))

    (define/override (cms-content/SMIME->content-info content-info-buffer)
      (let* ([smime-bio (BIO_new_mem_buf content-info-buffer
                                         (bytes-length content-info-buffer))]
             [content-info
              (cond [(not (ptr-equal? smime-bio #f)) (SMIME_read_CMS smime-bio)]
                    [else #f])])
        (cond [(not (ptr-equal? content-info #f)) (box-immutable content-info)]
              [else #f])))
                      
    
    (define/override (cms-sig-verify box-content-info cert-stack-list flags)
      (let ([content-info (unbox box-content-info)]
            [cert-stack (cert-list-to-stack cert-stack-list)])
            
        (begin
          (raise-cont-inf-type-error content-info sig-cinfo-type)
          (cond [(equal? (CMS_verify content-info cert-stack #f #f  (build-attr-val-from-list
                                                                     (get-cms-attr 'cms-no-signer-cert-verify) flags))  1    ) ;;CMS_NO_SIGNER_CERT_VERIFY
                 'success]
                [else 'fail]))))

    (define/override (cms-decrypt box-content-info cert-bytes pkey-bytes pkey-fmt flags)
      (let*  ([content-info (unbox box-content-info)]
              [bio-mem-cert (BIO_new_mem_buf cert-bytes (bytes-length cert-bytes))]                                             
              [cert-to-select (d2i_X509_bio bio-mem-cert)]
              [pkey (d2i_PrivateKey (get-pkey-format-id pkey-fmt) pkey-bytes (bytes-length pkey-bytes))]
              [bio-out (build-writeable-mem-bio)]
              [result (begin
                        (raise-cont-inf-type-error content-info encr-cinfo-type)
                        (CMS_decrypt_set1_pkey content-info pkey cert-to-select)
                        (CMS_decrypt content-info #f #f bio-out (build-attr-val-from-list 0
                                                                                          flags)))])            
        bio-out))

    
    ;;(write-bytes-from-membio fname bio-out)))
            
               
    (define/override (cms-decrypt-with-skey  box-content-info skey-bytes flags)
      (let* ([bio-out (build-writeable-mem-bio)]
             [content-info (unbox box-content-info)]
             [dummy (raise-cont-inf-type-error content-info symmetric-encr-cinfo-type)]
             [result (CMS_EncryptedData_decrypt content-info skey-bytes (bytes-length skey-bytes)
                                                #f bio-out
                                                (build-attr-val-from-list
                                                 0 flags))])
        
        bio-out))
    
    (define/override (cms-signinfo-get-first-signature box-content-info)
      (let* ([signer-info-stack (CMS_get0_SignerInfos (unbox box-content-info))]
             [first-sig-info (sk-typed-value signer-info-stack 0 _CMS_SignerInfo)])
        (asn1-string-members-as-list (CMS_SignerInfo_get0_signature first-sig-info))))

    (define/override (cms-signer-infos-get-signatures box-content-info)
      (let* ([sig-infos-list (get-signer-infos-list box-content-info)])
        (map
         (lambda (box-sign-info)(asn1-string-members-as-list
                                 (CMS_SignerInfo_get0_signature (unbox box-sign-info))))
         sig-infos-list)
        ))

    (define/override (get-signer-infos-list box-content-info) 
      (let* ([stack (CMS_get0_SignerInfos (unbox box-content-info))]
             [sk-size (OPENSSL_sk_num stack)])
        (get-stack-elements-list stack _CMS_SignerInfo)))

    (define/override (get-signer-certs-list box-content-info) 
      (let* ([stack (CMS_get0_signers (unbox box-content-info))])             
        (get-stack-elements-list stack _X509)))

    (define/override (get-issuer-x509 box-cert)
      (X509_name_st->list (X509_get_issuer_name (unbox box-cert))))

    (define/override (get-subject-x509 box-cert)
      (X509_name_st->list (X509_get_subject_name (unbox box-cert))))
    

    (define/private (get-stack-elements-list stack type)
      (stack-content->list stack type))
      
    
    ))

(define libcrypto-cms-tools%
  (class* cms-tools-base% (cms-tools<%>)
    (inherit-field factory)
    (super-new (spec 'cms-tools-base))
    
    (define/override (internal-bytes-read-fun)
      (lambda (mem-bio prev-read-len)        
        (let* ([len 1024]
               [buffer (make-bytes len 0)]
               [read-len
                (cond [(>= prev-read-len  len) (send this read-internal mem-bio buffer len)]
                      [else 0])])                         
          (cond [(> read-len  0)
                 (list buffer read-len)]
                [else #f]))))
    
    (define/public (read-internal mem-internal buffer len)
      (call-with-exception-handler(lambda(e)
                                    "read from internal CMS buffer failed")
                                  (lambda () (BIO_read mem-internal buffer len))))
    
    (define/public (eof-bio mem-bio)
      (BIO_eof mem-bio))
    ))
;; helper exports

;; read a binary file with racket
(define read-bytes-from-file
  (lambda (fname)
    (let*([port (open-input-file fname #:mode 'binary )]
          [reader (make-binary-reader port)]
          [file-size (file-size fname)])
      (let ([buffer (b-read-bytes reader file-size)])
        (close-input-port port)
        buffer)
      )))

;; write a binary file with racket
(define write-bytes-to-file
  (lambda (fname buffer)
    (let*([port (open-output-file fname #:mode 'binary #:exists 'replace)]
          [length (bytes-length buffer)])
      (begin
        (write-bytes-avail buffer port 0 length)
        (close-output-port port))
      )))



;; write a binary file from mem bio
(define write-bytes-from-membio
  (lambda (fname mem-bio)
    (let*([port (open-output-file fname #:mode 'binary #:exists 'replace)]
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
             

;; build up a libcrypto stack fom a list
(define (cert-list-to-stack cert-list)
  (let ([stack (OPENSSL_sk_new_null)])
    (let cert-list-to-stack-internal
      ([cert-list-internal cert-list])
      (cond [(not (null? cert-list-internal))
             (let* ([cert-bytes (car cert-list-internal)]
                    [bio_mem_x509 (BIO_new_mem_buf cert-bytes (bytes-length cert-bytes))]
                    [x509Cert (d2i_X509_bio bio_mem_x509)]
                    [size (OPENSSL_sk_push stack x509Cert)])               
               (cert-list-to-stack-internal (cdr cert-list-internal)))]
            [else stack]))))

(define get-symkey
  (lambda(cipher-name)
    (let* ([evp-cipher (EVP_get_cipherbyname cipher-name)]
           [key-len (EVP_CIPHER_key_length evp-cipher)])
      (crypto-random-bytes key-len))))


(define (raise-cont-inf-type-error content-info type-to-check)
  (let* ([given-type (get-cms-cont-info-type content-info)])
    (cond [(not (equal? given-type type-to-check)) (crypto-error "wrong content-info type: ~a wait for ~a" given-type type-to-check)]
          [else void])))

(define (get-cms-cont-info-type content-info)
  (get-asn1-data (CMS_get0_type content-info)))