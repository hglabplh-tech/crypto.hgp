#lang racket/base
(require ffi/unsafe
         ffi/unsafe/define
         ffi/unsafe/alloc
         ffi/unsafe/atomic
         opencl/c/types
         openssl/libcrypto
         binaryio/reader
         rnrs/io/ports-6
         "ffi.rkt"
         "../common/error.rkt")


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
(define generate-cms-signature-files (lambda(cert-fname pkey-fname data-fname out-name flags)
                                 (let* ([cert-bytes (read-bytes-from-file cert-fname)]
                                        [pkey-bytes (read-bytes-from-file pkey-fname)]
                                       [data-bytes  (read-bytes-from-file data-fname)]
                                       [cms-sig-der (generate-cms-signature-bytes cert-bytes pkey-bytes data-bytes flags)])
                                       (write-bytes-to-file out-name cms-sig-der)
                                   )))
                                       
(define generate-cms-signature-bytes(lambda (cert-bytes pkey-bytes data-bytes flags)
                                      (let* ([cert-len (bytes-length cert-bytes)]
                                             [pkey-len (bytes-length pkey-bytes)]
                                             [data-len (bytes-length data-bytes)]                                                                                          
                                             [bio_mem_data (BIO_new_mem_buf (buff-pointer-new data-bytes) data-len)]
                                             [bio_mem_x509 (BIO_new_mem_buf (buff-pointer-new cert-bytes) cert-len)]
                                             [x509Cert (d2i_X509_bio bio_mem_x509)]
                                             [pkey (d2i_PrivateKey EVP_PKEY_RSA pkey-bytes pkey-len)]
                                             [stack (OPENSSL_sk_new_null)]
                                             [stackret (OPENSSL_sk_push stack x509Cert)]
                                             [stack_cert (OPENSSL_sk_pop stack)]
                                             )
                                        
                                      (cond [(not (ptr-equal? x509Cert #f))
                                            (begin
                                        (display stack)
                                        (display stackret)
                                        (display stack_cert)
                                        (OPENSSL_sk_free stack)
                                        (display cert-bytes)
                                        (display data-bytes)
                                        (display "\n")                                        
                                        (display cert-len)
                                        (display "\n")                                        
                                        (display data-len)
                                        (display "\n")
                                        (display bio_mem_data)
                                        (display (ptr-ref x509Cert _pointer))                                        
                                        (let* (
                                               [content-info (CMS_sign  x509Cert pkey bio_mem_data flags)]
                                              )
                                          (cond [(eq? (CMS_verify content-info #f #f CMS_NO_SIGNER_CERT_VERIFY) 1)
                                                (i2d i2d_CMS_ContentInfo content-info)])
                                        
                                        ))]
                                        ))))

(define outage (generate-cms-signature-files "data/domain.der" "data/privkey.der" "pkey.rkt" "data/cms-sig.pkcs7" 0))
(display outage)

;;(define outage-det (generate-cms-signature-files "data/domain.der" "data/privkey.der" "pkey.rkt" "data/cms-sig-det.pkcs7" CMS_DETACHED))
;;(display outage-det)