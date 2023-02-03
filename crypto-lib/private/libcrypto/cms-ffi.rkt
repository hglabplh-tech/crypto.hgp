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




(define generate-cms-from-signature-files (lambda(cert-fname ca-cert-fname pkey-fname data-fname out-name flags)
                                 (let* ([cert-bytes (read-bytes-from-file cert-fname)]
                                        [ca-cert-bytes (read-bytes-from-file ca-cert-fname)]
                                        [pkey-bytes (read-bytes-from-file pkey-fname)]
                                        [data-bytes  (read-bytes-from-file data-fname)]
                                        [sign-impl (make-object libcrypto-cms-sign% )]
                                       [cms-sig-der (send sign-impl cms-sign-sure cert-bytes ca-cert-bytes pkey-bytes data-bytes flags)])
                                       (write-bytes-to-file out-name cms-sig-der)
                                   )))
(define generate-cms-from-signature-files-ext (lambda(cert-fname ca-cert-fname pkey-fname data-fname out-name sig-cert-fname
                                                                 sig-pkey-fname flags sig-flags)
                                 (let* ([cert-bytes (read-bytes-from-file cert-fname)]
                                        [ca-cert-bytes (read-bytes-from-file ca-cert-fname)]
                                        [pkey-bytes (read-bytes-from-file pkey-fname)]
                                        [data-bytes  (read-bytes-from-file data-fname)]
                                        [sig-cert-bytes (read-bytes-from-file sig-cert-fname)]
                                        [sig-pkey-bytes (read-bytes-from-file sig-pkey-fname)]
                                        [sign-impl (make-object libcrypto-cms-sign%)])
                                       (begin (send sign-impl cms-init-signing cert-bytes pkey-bytes data-bytes flags)
                                              (display (send sign-impl cms-add-cert ca-cert-bytes))                                              
                                              (display (send sign-impl cms-add-signer sig-cert-bytes sig-pkey-bytes "SHA512" sig-flags))                                              
                                              (display (send sign-impl cms-sign-finalize data-bytes 0))                                             
                                              (let ([cms-sig-der (send sign-impl get-cms-content-info/DER)]                                                    )
                                       (begin (write-bytes-to-file out-name cms-sig-der))))
                                   )))
                                       

(define outage (generate-cms-from-signature-files "data/freeware-user-cert.der" "data/freeware-ca-cert.der"
                                             "data/freeware-user-key.der" "pkey.rkt" "data/cms-sig.pkcs7" 0))

(define outage-ext (generate-cms-from-signature-files-ext "data/freeware-user-cert.der" "data/freeware-ca-cert.der"
                                             "data/freeware-user-key.der" "pkey.rkt" "data/cms-sig-ext.pkcs7" "data/freeware-user-cert_1.der"
                                             "data/freeware-user-key_1.der" 0 0))
(display outage)
(display (EVP_get_cipherbyname "AES-256-CBC"))

;;(define outage-det (generate-cms-signature-files "data/domain.der" "data/privkey.der" "pkey.rkt" "data/cms-sig-det.pkcs7" CMS_DETACHED))
;;(display outage-det)