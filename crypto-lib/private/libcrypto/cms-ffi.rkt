#lang racket/base
(require binaryio/reader
         rnrs/io/ports-6
         racket/class
         racket/match crypto crypto/libcrypto         
         "cmssig.rkt"
         "../common/cmssigbase.rkt"        
          
         )


;;========================================
;; CMS signing
;;========================================

(define cipher-name "AES-256-CBC")

(define symetric-key (get-symkey cipher-name))


(define generate-cms-from-signature-files (lambda(cert-fname ca-cert-fname pkey-fname pkey-fmt data-fname out-name flags)
                                            (let* ([cert-bytes (read-bytes-from-file cert-fname)]
                                                   [ca-cert-bytes (read-bytes-from-file ca-cert-fname)]
                                                   [pkey-bytes (read-bytes-from-file pkey-fname)]
                                                   [data-bytes  (read-bytes-from-file data-fname)]
                                                   [sign-impl (new libcrypto-cms-sign%  (factory libcrypto-factory))]
                                                   [cms-sig-der (send sign-impl cms-sign-sure cert-bytes pkey-bytes pkey-fmt 
                                                                      (list ca-cert-bytes)
                                                                      data-bytes flags)])                                   
                                              (write-bytes-to-file out-name cms-sig-der)
                                              )))
(define generate-cms-from-signature-files-ext (lambda(cert-fname ca-cert-fname pkey-fname pkey-fmt data-fname out-names sig-cert-fname
                                                                 sig-pkey-fname flags sig-flags)
                                                (let* ([cert-bytes (read-bytes-from-file cert-fname)]
                                                       [ca-cert-bytes (read-bytes-from-file ca-cert-fname)]
                                                       [pkey-bytes (read-bytes-from-file pkey-fname)]
                                                       [data-bytes  (read-bytes-from-file data-fname)]
                                                       [sig-cert-bytes (read-bytes-from-file sig-cert-fname)]
                                                       [sig-pkey-bytes (read-bytes-from-file sig-pkey-fname)]
                                                       [sign-impl (new libcrypto-cms-sign%  (factory libcrypto-factory))]
                                                       [check-impl (new libcrypto-cms-check-explore% (factory libcrypto-factory))]
                                                       [content-info (send sign-impl cms-init-signing cert-bytes pkey-bytes pkey-fmt
                                                                           '()
                                                                           data-bytes flags)])
                                                  (begin (display (send sign-impl cms-add-cert content-info ca-cert-bytes))                                              
                                                         (displayln (send sign-impl cms-add-signer content-info
                                                                          sig-cert-bytes sig-pkey-bytes pkey-fmt "SHA512" sig-flags))                                                         
                                                         ;;(display (send sign-impl cms-sign-receipt content-info sig-cert-bytes (list)  sig-pkey-bytes pkey-fmt flags))
                                                         (displayln (send sign-impl cms-sign-finalize content-info data-bytes '()))
                                                         (printf "signature content-info-type: ~a\n" (send sign-impl
                                                                                                           get-cms-content-info-type content-info))
                                                         
                                                         (let ([cms-sig-der (send sign-impl get-cms-content-info/DER content-info )]                                                    )
                                                           (begin (write-bytes-to-file (car out-names) cms-sig-der)
                                                                  (send sign-impl  smime-write-CMS content-info (cadr out-names) '())
                                                                  
                                                                  ))))
                                                ))

(define generate-cms-encrypt-from-files (lambda(cert-fname pkey-fname data-fname out-names sig-cert-fname
                                                           sig-pkey-fname flags sig-flags)
                                          (let* ([cert-bytes (read-bytes-from-file cert-fname)]                                        
                                                 [pkey-bytes (read-bytes-from-file pkey-fname)]
                                                 [data-bytes  (read-bytes-from-file data-fname)]
                                                 [sig-cert-bytes (read-bytes-from-file sig-cert-fname)]
                                                 [sig-pkey-bytes (read-bytes-from-file sig-pkey-fname)]
                                                 [sign-impl (new libcrypto-cms-sign%  (factory libcrypto-factory))]
                                                 [cert-stack-list (list cert-bytes)]
                                                 [content-info (send sign-impl cms-encrypt cert-stack-list data-bytes cipher-name flags)])
                                            (begin ;;(display (send sign-impl cms-add-recipient-cert content-info sig-cert-bytes '()))
                                              
                                              (displayln (send sign-impl cms-sign-finalize content-info data-bytes '()))
                                              (printf "encryption content-info-type: ~a\n" (send sign-impl get-cms-content-info-type content-info))
                                              (let ([cms-sig-der (send sign-impl get-cms-content-info/DER content-info)]                                                    )
                                                (begin (write-bytes-to-file (car out-names) cms-sig-der)
                                                       (send sign-impl  write-CMS/BER content-info (cadr out-names) '())
                                                       )))
                                            )))

(define generate-cms-encrypt-skey-files (lambda(skey-bytes data-fname out-name
                                                           flags)
                                          (let* ([data-bytes  (read-bytes-from-file data-fname)]                                       
                                                 [sign-impl (new libcrypto-cms-sign%  (factory libcrypto-factory))]
                                        
                                                 [content-info (send sign-impl cms-encrypt-with-skey skey-bytes data-bytes  "AES-256-CBC" flags)])
                                            (begin
                                              (printf "symmetric encryption content-info-type: ~a\n" (send sign-impl get-cms-content-info-type content-info))
                                              (let ([cms-sig-der (send sign-impl get-cms-content-info/DER content-info)])                                            
                                                (write-bytes-to-file out-name cms-sig-der)                                              
                                                )))))
                                   

(define cms-decrypt (lambda(cert-fname pkey-fname pkey-fmt content-info-file fname flags )
                      (let* ([cert-bytes (read-bytes-from-file cert-fname)]
                             [content-info-bytes (read-bytes-from-file content-info-file)]
                             [pkey-bytes (read-bytes-from-file pkey-fname)]                        
                             [check-impl (new libcrypto-cms-check-explore% (factory libcrypto-factory))]
                             [box-content-info (send check-impl
                                                     cms-content/DER->content-info content-info-bytes)]
                             )                                      

                        (let ([mem-bio
                               (send check-impl cms-decrypt box-content-info
                                     cert-bytes pkey-bytes pkey-fmt flags)])
                          (write-internal-to-file fname mem-bio )
                          )
                        )))

(define cms-smime-decrypt (lambda(cert-fname pkey-fname pkey-fmt content-info-file fname flags )
                            (let* ([cert-bytes (read-bytes-from-file cert-fname)]
                                   [content-info-bytes (read-bytes-from-file content-info-file)]
                                   [pkey-bytes (read-bytes-from-file pkey-fname)]
                                   [check-impl (new libcrypto-cms-check-explore% (factory libcrypto-factory))]
                                   [box-content-info (send check-impl
                                                           cms-content/SMIME->content-info content-info-bytes)]
                                   )
                                (let ([mem-bio
                                       (send check-impl cms-decrypt box-content-info
                                             cert-bytes pkey-bytes pkey-fmt flags)])
                                  (write-internal-to-file fname mem-bio )
                                  )
                                )))
                    
(define cms-decrypt-with-skey  (lambda (content-info-file skey-bytes fname flags)
                                 (let* ([check-impl (new libcrypto-cms-check-explore% (factory libcrypto-factory))]
                                        [content-info-bytes (read-bytes-from-file content-info-file)]
                                        [box-content-info (send check-impl
                                                                cms-content/DER->content-info content-info-bytes)])
                                   (send check-impl cms-decrypt-with-skey box-content-info skey-bytes flags)
                                      (let ([mem-bio
                               (send check-impl
                                     cms-decrypt-with-skey
                                     box-content-info skey-bytes flags)])                                 
                          (write-internal-to-file fname mem-bio )
                          )
                        )))
                                 

(define verify-cms-from-files (lambda(cert-fname ca-cert-fname sig-cert-fname signature-name flags)
                                (let* ([cert-bytes (read-bytes-from-file cert-fname)]
                                       [ca-cert-bytes (read-bytes-from-file ca-cert-fname)]
                                       [sig-cert-bytes (read-bytes-from-file sig-cert-fname)]
                                       [content-info-bytes (read-bytes-from-file signature-name)]
                                       [check-impl (new libcrypto-cms-check-explore% (factory libcrypto-factory))]
                                       [box-content-info (send check-impl
                                                               cms-content/DER->content-info content-info-bytes)]                                       
                                       [cert-stack-list (list cert-bytes ca-cert-bytes)])
                                  
                                  (let ([result (send check-impl cms-sig-verify box-content-info
                                                      (list cert-bytes sig-cert-bytes ca-cert-bytes) flags)])
                                    (printf "verification result: ~a\n" result)
                                    (displayln (send check-impl cms-signer-infos-get-signatures box-content-info))                                    
                                    (displayln (send check-impl get-signer-certs-list box-content-info))
                                    (send check-impl cms-signinfo-get-first-signature box-content-info ))
                                  )))

(define (write-internal-to-file fname internal)
  (let* ([tool% (new libcrypto-cms-tools% (factory libcrypto-factory))]
         [port (send tool% open-stream-file-write fname)]
         [read-fun (send tool% internal-bytes-read-fun)]
         [write-fun (send tool% stream-file-write)]
         [close-fun (send tool% close-fun #f close-output-port)]
         [copy-stream (send tool% build-copy-stream read-fun internal write-fun port close-fun)])
    (send tool% call-with-val-copy-stream copy-stream)
    ))

(define (write-internal-to-mem internal)
  (let* ([tool% (new libcrypto-cms-tools% (factory libcrypto-factory))]
         [mem-stream (send tool% open-stream-mem)]
         [read-fun (send tool% internal-bytes-read-fun)]
         [write-fun (send tool% stream-write-mem)]
         [close-fun (send tool% close-fun #f #f)]
         [copy-stream (send tool% build-copy-stream read-fun internal write-fun mem-stream close-fun)])
    (send tool% call-with-val-copy-streamcopy-stream)
    ))

(define outage (generate-cms-from-signature-files "data/freeware-user-cert.der" "data/freeware-ca-cert.der"
                                                  "data/freeware-user-key.der" 'rsa-key "pkey.rkt" 
                                                  "data/cms-sig.pkcs7" '(cms-binary cms-cades)))

(define outage-ext (generate-cms-from-signature-files-ext "data/freeware-user-cert.der" "data/freeware-ca-cert.der"
                                                          "data/freeware-user-key.der" 'rsa-key "pkey.rkt" (list "data/cms-sig-ext.pkcs7"
                                                                                                                 "data/cms-sig-ext-SMIME.smime")
                                                          "data/freeware-user-cert_1.der"
                                                          "data/freeware-user-key_1.der" '(cms-cades cms-binary) '(cms-cades cms-binary)))

(define outage-envelop (generate-cms-encrypt-from-files "data/freeware-user-cert.der" 
                                                        "data/freeware-user-key.der"  "ffi.rkt" (list "data/cms-envelop-ext.pkcs7"
                                                                                                      "data/cms-envelop-ext-i2d-write.pkcs7")
                                                        "data/freeware-user-cert_1.der"
                                                        "data/freeware-user-key_1.der" '(cms-binary cms-stream) '(cms-binary cms-stream)))

(printf "first print skey: ~a\n" (bytes->hex-string symetric-key))
(printf "second print skey: ~a\n" (bytes->hex-string symetric-key))


(generate-cms-encrypt-skey-files symetric-key  "ffi.rkt" "data/cms-encrypt-ext.pkcs7" '())


(verify-cms-from-files "data/freeware-user-cert.der" "data/freeware-ca-cert.der"
                       "data/freeware-user-cert_1.der"
                       "data/cms-sig-ext.pkcs7" '())
                                             
(printf "Key id of '~a is ~a ~n" 'rsa-key (get-pkey-format-id 'rsa-key))
(printf "Key id of '~a is ~a ~n" 'ec-key (get-pkey-format-id 'ec-key))
(printf "Attribute-List ~a ~n" (get-cms-attrs-from-list '(cms-detached cms-binary cms-partial)))
(printf "Attribute-intern ~a ~n" (build-attr-val-from-list 0 '(cms-detached cms-binary cms-partial)))

(cms-decrypt "data/freeware-user-cert.der" "data/freeware-user-key.der" 'rsa-key  "data/cms-envelop-ext.pkcs7" "data/out.bin" '(cms-binary))
(cms-smime-decrypt "data/freeware-user-cert.der" "data/freeware-user-key.der" 'rsa-key  "data/cms-envelop-ext-SMIME.smime" "data/out-smime.bin" '(cms-binary))
(cms-decrypt-with-skey  "data/cms-encrypt-ext.pkcs7" symetric-key "data/encrypt-decr-data.bin" '())
