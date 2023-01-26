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
(define generate-cms-signature-files (lambda(cert-fname pkey-fname data-fname flags)
                                 (let* ([cert-bytes (read-bytes-from-file cert-fname)]
                                        [pkey-bytes (read-bytes-from-file pkey-fname)]
                                       [data-bytes  (read-bytes-from-file data-fname)])
                                   (generate-cms-signature-bytes cert-bytes pkey-bytes data-bytes flags))))
                                       
(define generate-cms-signature-bytes(lambda (cert-bytes pkey-bytes data-bytes flags)
                                      (let* ([cert-len (bytes-length cert-bytes)]
                                             [pkey-len (bytes-length pkey-bytes)]
                                             [data-len (bytes-length data-bytes)]                                                                                          
                                             [_bio_mem (BIO_new_mem_buf (buff-pointer-new data-bytes) data-len)]
                                             [_bio_mem_fin (BIO_new_mem_buf (buff-pointer-new data-bytes) data-len)]
                                             [_x509Cert (d2i_X509 cert-bytes cert-len)]
                                             [_pkey (d2i_PrivateKey EVP_PKEY_RSA pkey-bytes pkey-len)]
                                             )
                                        
                                      (cond [(not (ptr-equal? _x509Cert #f))
                                            (begin
                                        (display cert-bytes)
                                        (display data-bytes)
                                        (display "\n")                                        
                                        (display cert-len)
                                        (display "\n")                                        
                                        (display data-len)
                                        (display "\n")
                                        (display _bio_mem)
                                        (display _x509Cert)
                                        
                                        (let* ([_contentInfo (CMS_sign  _x509Cert _pkey _bio_mem flags)]
                                              )
                                          (CMS_verify _contentInfo #f #f CMS_NO_SIGNER_CERT_VERIFY))
                                        
                                        )]
                                        ))))

(generate-cms-signature-files "data/domain.der" "data/privkey.der" "pkey.rkt" CMS_BINARY)
;;(d2i_X509 #f #f 6)