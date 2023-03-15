#lang racket/base
(require crypto crypto/libcrypto racket/match
         "cms-utils.rkt")

(crypto-factories libcrypto-factory)

(define cipher-name "AES-256-CBC")

(define symetric-key (get-symmetric-key cipher-name))

;; up to now only check if the entry is really exported 
;;(cms-sign-simple "")
;;(cms-init-signing "")
;;(cms-add-signing-cert "")
;;(write-CMS/BER "")

(define generate-cms-from-signature-files (lambda(cert-fname ca-cert-fname pkey-fname pkey-fmt data-fname out-name flags)
                                            (let* ([cert-bytes (read-bytes-from-file cert-fname)]
                                                   [ca-cert-bytes (read-bytes-from-file ca-cert-fname)]                                                   
                                                   [pkey-bytes (read-bytes-from-file pkey-fname)]
                                                   [data-bytes  (read-bytes-from-file data-fname)]                                                
                                                   [cms-sig-der (cms-sign-simple cert-bytes pkey-bytes pkey-fmt 
                                                                                 (list ca-cert-bytes)
                                                                                 data-bytes flags)])                                   
                                              (write-bytes-to-file out-name cms-sig-der)
                                              (let ([result (cms-content/DER->content-info cms-sig-der)])
                                                (cond [(box? result)
                                                       (printf "this should be a content-info-ptr: ~a"
                                                               (unbox result))]))
                                              )))



;;call it

(generate-cms-from-signature-files "data/freeware-user-cert.der" "data/freeware-ca-cert.der"
                                                  
                                   "data/freeware-user-key.der" 'rsa-key "key-agreement-dh.rkt" 
                                   "data/cms-sig.pkcs7" '(cms-binary cms-cades))


