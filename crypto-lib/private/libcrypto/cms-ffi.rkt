#lang racket/base
(require binaryio/reader
         rnrs/io/ports-6
         racket/class
         racket/match crypto crypto/libcrypto         
         "cmssig.rkt"
         "ffi.rkt"
         
          
         )


;;========================================
;; CMS signing
;;========================================




(define generate-cms-from-signature-files (lambda(cert-fname ca-cert-fname pkey-fname pkey-fmt data-fname out-name flags)
                                 (let* ([cert-bytes (read-bytes-from-file cert-fname)]
                                        [ca-cert-bytes (read-bytes-from-file ca-cert-fname)]
                                        [pkey-bytes (read-bytes-from-file pkey-fname)]
                                        [data-bytes  (read-bytes-from-file data-fname)]
                                        [sign-impl (make-object libcrypto-cms-sign% )]
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
                                        [sign-impl (make-object libcrypto-cms-sign%)])
                                       (begin (send sign-impl cms-init-signing cert-bytes pkey-bytes pkey-fmt
                                                    '()
                                                    data-bytes flags)
                                              (display (send sign-impl cms-add-cert ca-cert-bytes))                                              
                                              (display (send sign-impl cms-add-signer sig-cert-bytes sig-pkey-bytes pkey-fmt "SHA512" sig-flags))
                                              ;;(display (send sign-impl cms-sign-receipt sig-cert-bytes (list)  sig-pkey-bytes pkey-fmt flags))
                                              (display (send sign-impl cms-sign-finalize data-bytes 0))                                             
                                              (let ([cms-sig-der (send sign-impl get-cms-content-info/DER)]                                                    )
                                       (begin (write-bytes-to-file (car out-names) cms-sig-der)
                                              ;;(send sign-impl  smime-write-CMS (cadr out-names) 0)
                                              )))
                                   )))

(define generate-cms-envelop-from-files (lambda(cert-fname ca-cert-fname pkey-fname pkey-fmt data-fname out-names sig-cert-fname
                                                                 sig-pkey-fname flags sig-flags)
                                 (let* ([cert-bytes (read-bytes-from-file cert-fname)]
                                        [ca-cert-bytes (read-bytes-from-file ca-cert-fname)]
                                        [pkey-bytes (read-bytes-from-file pkey-fname)]
                                        [data-bytes  (read-bytes-from-file data-fname)]
                                        [sig-cert-bytes (read-bytes-from-file sig-cert-fname)]
                                        [sig-pkey-bytes (read-bytes-from-file sig-pkey-fname)]
                                        [sign-impl (make-object libcrypto-cms-sign%)]
                                        [cert-stack-list (list cert-bytes ca-cert-bytes)])
                                       (begin 
                                              (display (send sign-impl cms-encrypt cert-stack-list data-bytes "AES-256-CBC" flags))                                              
                                              (display (send sign-impl cms-add-recipient-cert sig-cert-bytes 0))
                                              
                                              (display (send sign-impl cms-sign-finalize data-bytes 0))                                             
                                              (let ([cms-sig-der (send sign-impl get-cms-content-info/DER)]                                                    )
                                       (begin (write-bytes-to-file (car out-names) cms-sig-der)
                                              (send sign-impl  smime-write-CMS (cadr out-names) 0)
                                              )))
                                   )))

(define cms-decrypt (lambda(cert-fname pkey-fname pkey-fmt contentinfo-file fname flags )
                                 (let* ([cert-bytes (read-bytes-from-file cert-fname)]
                                        [contentinfo-buffer (read-bytes-from-file contentinfo-file)]
                                        [pkey-bytes (read-bytes-from-file pkey-fname)]                        
                                        [check-impl (make-object libcrypto-cms-check-explore%)]
                                        )                                       

                                   (send check-impl cms-decrypt contentinfo-buffer cert-bytes pkey-bytes pkey-fmt fname flags))))
                    


(define verify-cms-from-files (lambda(cert-fname ca-cert-fname sig-cert-fname signature-name flags)
                                 (let* ([cert-bytes (read-bytes-from-file cert-fname)]
                                        [ca-cert-bytes (read-bytes-from-file ca-cert-fname)]
                                        [sig-cert-bytes (read-bytes-from-file sig-cert-fname)]
                                        [content-info-bytes (read-bytes-from-file signature-name)]
                                        [check-impl (make-object libcrypto-cms-check-explore%)]
                                        [cert-stack-list (list cert-bytes ca-cert-bytes)])
                                   (begin (display (send check-impl cms-sig-verify content-info-bytes (list cert-bytes  ca-cert-bytes sig-cert-bytes) flags))
                                   (send check-impl cms-signinfo-get-first-signature))
                                   )))

(define outage (generate-cms-from-signature-files "data/freeware-user-cert.der" "data/freeware-ca-cert.der"
                                             "data/freeware-user-key.der" 'rsa-key "pkey.rkt" 
                                             "data/cms-sig.pkcs7" 0))

(define outage-ext (generate-cms-from-signature-files-ext "data/freeware-user-cert.der" "data/freeware-ca-cert.der"
                                             "data/freeware-user-key.der" 'rsa-key "pkey.rkt" (list "data/cms-sig-ext.pkcs7"
                                                                                                    "data/cms-sig-ext-SMIME.pkcs7")
                                             "data/freeware-user-cert_1.der"
                                             "data/freeware-user-key_1.der" 0 0))

(define outage-envelop (generate-cms-envelop-from-files "data/freeware-user-cert.der" "data/freeware-ca-cert.der"
                                             "data/freeware-user-key.der" 'rsa-key "ffi.rkt" (list "data/cms-envelop-ext.pkcs7"
                                                                                                    "data/cms-envelop-ext-SMIME.pkcs7")
                                             "data/freeware-user-cert_1.der"
                                             "data/freeware-user-key_1.der" 0 0))


(verify-cms-from-files "data/freeware-user-cert.der" "data/freeware-ca-cert.der"
                                                          "data/freeware-user-cert_1.der"
                                             "data/cms-sig-ext.pkcs7" 0)
                                             
(printf "Key id of '~a is ~a ~n" 'rsa-key (get-pkey-format-id 'rsa-key))
(printf "Key id of '~a is ~a ~n" 'ec-key (get-pkey-format-id 'ec-key))

(cms-decrypt "data/freeware-user-cert.der" "data/freeware-user-key.der" 'rsa-key  "data/cms-envelop-ext.pkcs7" "data/out.bin" 0)



;;(define outage-det (generate-cms-signature-files "data/domain.der" "data/privkey.der" "pkey.rkt" "data/cms-sig-det.pkcs7" CMS_DETACHED))
;;(display outage-det)