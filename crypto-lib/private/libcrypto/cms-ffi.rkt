#lang racket/base
(require ffi/unsafe
         ffi/unsafe/define
         ffi/unsafe/alloc
         ffi/unsafe/atomic
         opencl/c/types
         openssl/libcrypto
         binaryio/reader
         rnrs/io/ports-6
         racket/class
         racket/match crypto crypto/libcrypto         
         "cmssig.rkt"
         "../common/error.rkt")

(crypto-factories libcrypto-factory)
;;========================================
;; CMS signing
;;========================================



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
(define generate-cms-signature-files (lambda(cert-fname ca-cert-fname pkey-fname data-fname out-name flags)
                                 (let* ([cert-bytes (read-bytes-from-file cert-fname)]
                                        [ca-cert-bytes (read-bytes-from-file ca-cert-fname)]
                                        [pkey-bytes (read-bytes-from-file pkey-fname)]
                                        [data-bytes  (read-bytes-from-file data-fname)]
                                        [sign-impl (make-object libcrypto-cms-sign%)]
                                       [cms-sig-der (send sign-impl cms-sign-sure cert-bytes ca-cert-bytes pkey-bytes data-bytes flags)])
                                       (write-bytes-to-file out-name cms-sig-der)
                                   )))
                                       

(define outage (generate-cms-signature-files "data/freeware-user-cert.der" "data/freeware-ca-cert.der"
                                             "data/freeware-user-key.der" "pkey.rkt" "data/cms-sig.pkcs7" 0))
(display outage)

;;(define outage-det (generate-cms-signature-files "data/domain.der" "data/privkey.der" "pkey.rkt" "data/cms-sig-det.pkcs7" CMS_DETACHED))
;;(display outage-det)