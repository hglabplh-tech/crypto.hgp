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

(provide (protect-out (all-defined-out))
         libcrypto)

(define ((K v) . args) v)

;; ============================================================
;; Library initialization & error-catching wrappers

(define-ffi-definer define-crypto libcrypto
  #:default-make-fail make-not-available)
(define libcrypto-load-error libcrypto-load-fail-reason)

(define-crypto SSLeay (_fun -> _long) #:fail (K (K #f)))
(define-crypto OpenSSL_version_num (_fun -> _long) #:fail (K SSLeay))

(define libcrypto-ok?
  (let ([v (or (OpenSSL_version_num) 0)])
    ;; at least version 1.0.0 (MNNFFPPS)
    (>= v #x10000000)))

(let ()
  (define-crypto ERR_load_crypto_strings (_fun -> _void) #:fail (K void))
  (define-crypto OpenSSL_add_all_ciphers (_fun -> _void) #:fail (K void))
  (define-crypto OpenSSL_add_all_digests (_fun -> _void) #:fail (K void))
  (ERR_load_crypto_strings)
  (OpenSSL_add_all_ciphers)
  (OpenSSL_add_all_digests))

(define-crypto CRYPTO_free
  (_fun _pointer -> _void))

;; ----

(define-crypto ERR_get_error
  (_fun -> _ulong))
(define-crypto ERR_peek_error
  (_fun -> _ulong))
(define-crypto ERR_peek_last_error
  (_fun -> _ulong))
(define-crypto ERR_lib_error_string
  (_fun _ulong -> _string))
(define-crypto ERR_func_error_string
  (_fun _ulong -> _string))
(define-crypto ERR_reason_error_string
  (_fun _ulong -> _string))

;; Use atomic wrapper around ffi calls to avoid race retrieving error info.

;; Since 3.0, some operations put errors in the error queue even on success.
(define default-log-errors? (< (or (OpenSSL_version_num) 0) #x30000000))

(define (err-wrap who [ok? positive?]
                  #:convert [convert values]
                  #:log-errors? [log? default-log-errors?])
  (lambda (proc)
    (lambda args
      (call-as-atomic
       (lambda ()
         (let ([result (apply proc args)])
           (cond [(ok? result)
                  (drain-errors who log?)
                  (convert result)]
                 [else (raise-crypto-error who)])))))))

(define (drain-errors who log?)
  (let loop ()
    (define e (ERR_get_error))
    (unless (zero? e)
      (when log?
        (log-crypto-error "~a: internal error: unhandled error\n ~a [~a:~a:~a]\n"
                          (or who '?)
                          (or (ERR_reason_error_string e) "?")
                          (or (ERR_lib_error_string e) "?")
                          (or (ERR_func_error_string e) "?")
                          e))
      (loop))))

(define (err-wrap/pointer who)
  (err-wrap who values))

(define (raise-crypto-error where)
  (let ([e (ERR_get_error)])
    (drain-errors #f #f)
    (crypto-error "~a: ~a [~a:~a:~a]"
                  where
                  (or (ERR_reason_error_string e) "?")
                  (or (ERR_lib_error_string e) "?")
                  (or (ERR_func_error_string e) "?")
                  e)))

(define (i2d i2d_Type x)
  (define outlen (i2d_Type x #f))
  ; buffer must not move since pointer passed to i2d_Type does not trace it
  (define outbuf (malloc outlen 'atomic-interior))
  (define outlen2 (i2d_Type x outbuf))
  (when (> outlen2 outlen)
    (error 'i2d "openssl promised i2d result of length at most ~a but returned length ~a" outlen outlen2))
  (define res (make-bytes outlen2 0))
  (memcpy res outbuf outlen2)
  res)

(define-crypto OBJ_nid2sn
  (_fun _int -> _string/utf-8))
(define-crypto OBJ_nid2ln
  (_fun _int -> _string/utf-8))
(define-crypto OBJ_sn2nid
  (_fun _string/utf-8 -> _int))

(define SSLEAY_VERSION		0)
(define SSLEAY_CFLAGS		2)
(define SSLEAY_BUILT_ON		3)
(define SSLEAY_PLATFORM		4)
(define SSLEAY_DIR		5)

(define-crypto SSLeay_version (_fun _int -> _string/utf-8) #:fail (K (K #f)))
(define-crypto OpenSSL_version (_fun _int -> _string/utf-8) #:fail (K SSLeay_version))

(define (parse-version v)
  ;; MNNFFPPS
  (define S (bitwise-bit-field v 0 3))
  (define P (bitwise-bit-field v 4 11))
  (define F (bitwise-bit-field v 12 19))
  (define N (bitwise-bit-field v 20 27))
  (define M (bitwise-bit-field v 28 31))
  (values M N F P S))

(define (openssl-version>=? a b c)
  (define-values (va vb vc vd ve) (parse-version (OpenSSL_version_num)))
  (or (> va a)
      (and (= va a)
           (or (> vb b)
               (and (= vb b)
                    (>= vc c))))))

; _fun argument type to pass pointer q to pointer p to freshly-allocated buffer
; - buffer is initialized with the argued bytes?
; - modification of p will not interfere with garbage collection
; - the buffer is collected after p
; _fun argument type to pass pointer q to pointer p to freshly-allocated buffer
; - buffer is initialized with the argued bytes?
; - modification of p will not interfere with garbage collection
; - the buffer is collected after p
(define-fun-syntax _dptr_to_bytes
  (syntax-id-rules (_dptr_to_bytes)
    [_dptr_to_bytes
      (type: _pointer
       pre: (x => (begin
                    (unless (bytes? x)
                      (error '_dptr_to_bytes "expected bytes?"))
                    (let ([p (malloc _pointer 1 'atomic)]
                          [b (malloc _byte (bytes-length x) 'raw)])
                      (register-finalizer p
                        (lambda (_) (free b)))
                      (memcpy b x (bytes-length x))
                      (ptr-set! p _pointer b)
                      p))))]))
(define  _dptr-to-bytes (lambda(x)    
       (begin
                    (unless (bytes? x)
                      (error '_dptr_to_bytes "expected bytes?"))
                    (let ([p (malloc _pointer 1 'atomic)]
                          [b (malloc _byte (bytes-length x) 'raw)])
                      (register-finalizer p
                        (lambda (_) (free b)))
                      (memcpy b x (bytes-length x))
                      (ptr-set! p _pointer b)
                      p))))

(define _dptr_to_dptr (lambda(p)
                      (begin
                  (let ([pp (malloc _pointer 1 'atomic)])                    
                    (ptr-set! pp _pointer p)
                    pp))))

;; ============================================================
;; Bignum

(define-cpointer-type _BIGNUM)

(define-crypto BN_free
  (_fun _BIGNUM
        -> _void)
  #:wrap (deallocator))

(define BN-no-gc ((deallocator) void))

;;========================================
;; CMS signing
;;========================================

;;defined flags
( define CMS_SIGNERINFO_ISSUER_SERIAL    0)
( define CMS_SIGNERINFO_KEYIDENTIFIER    1)

( define CMS_RECIPINFO_NONE              -1)
( define CMS_RECIPINFO_TRANS             0)
( define CMS_RECIPINFO_AGREE             1)
( define CMS_RECIPINFO_KEK               2)
( define CMS_RECIPINFO_PASS              3)
( define CMS_RECIPINFO_OTHER             4)



( define CMS_TEXT                        #x1)
( define CMS_NOCERTS                     #x2)
( define CMS_NO_CONTENT_VERIFY           #x4)
( define CMS_NO_ATTR_VERIFY              #x8)
( define CMS_NOINTERN                    #x10)
( define CMS_NO_SIGNER_CERT_VERIFY       #x20)
( define CMS_NOVERIFY                    #x20)
( define CMS_DETACHED                    #x40)
( define CMS_BINARY                      #x80)
( define CMS_NOATTR                      #x100)
( define CMS_NOSMIMECAP                  #x200)
( define CMS_NOOLDMIMETYPE               #x400)
( define CMS_CRLFEOL                     #x800)
( define CMS_STREAM                      #x1000)
( define CMS_NOCRL                       #x2000)
( define CMS_PARTIAL                     #x4000)
( define CMS_REUSE_DIGEST                #x8000)
( define CMS_USE_KEYID                   #x10000)
( define CMS_DEBUG_DECRYPT               #x20000)
( define CMS_KEY_PARAM                   #x40000)
( define CMS_ASCIICRLF                   #x80000)
( define CMS_CADES                       #x100000)
( define CMS_USE_ORIGINATOR_KEYID        #x200000)



;;========================================
;;fun definitions and struct pinters
;;========================================
(define-cpointer-type _X509)


(define-crypto X509_free
  (_fun _X509 -> _void)
  #:wrap (deallocator))

(define-crypto X509_new
  (_fun -> _X509/null)
  #:wrap (compose (allocator X509_free) (err-wrap/pointer 'X509_new)))

 

;;TODO:cleanup moving to ffi.rkt... defining interface with classes
;; define read funcion for getting a _X509 from DER
(define-crypto d2i_X509 (_fun
                          (_pointer = #f) _dptr_to_bytes _long -> _X509/null)
  #:wrap (compose (allocator X509_free) (err-wrap/pointer 'd2i_X509)))

;;BIO create mem BIO for CMS signing
;;BIO *BIO_new_mem_buf(const void *buf, int len);
(define-cpointer-type _BIO)

(define-crypto BIO_new_mem_buf (_fun
                 _dptr_to_bytes _int -> _BIO/null)
                 #:wrap (err-wrap/pointer 'BIO_new_mem_buf))

;;CMS_ContentInfo *CMS_sign(X509 *signcert, EVP_PKEY *pkey, STACK_OF(X509) *certs,
                           ;;BIO *data, unsigned int flags);
(define-cpointer-type _CMS_ContentInfo)

(define-crypto CMS_sign (_fun
                _X509 _EVP_PKEY (_pointer = #f) _BIO (_int = 0) -> _CMS_ContentInfo)
                #:wrap (err-wrap/pointer 'CMS_sign))
                          
;; some pre-code to test

;;X509 *d2i_X509(X509 **px, const unsigned char **in, long len);
 ;;X509 *d2i_X509(X509 **px, const unsigned char **in, long len);
 (define read-bytes-from-file
   (lambda (fname)
     (let*([port (open-file-input-port fname)]
       [reader (make-binary-reader port)]
       {file-size (file-size fname)}
       )
       (b-read-bytes reader file-size)
       )))
(define generate-cms-signature-files (lambda(cert-fname pkey-fname data-fname)
                                 (let* ([cert-bytes (read-bytes-from-file cert-fname)]
                                        [pkey-bytes (read-bytes-from-file pkey-fname)]
                                       [data-bytes  (read-bytes-from-file data-fname)])
                                   (generate-cms-signature-bytes cert-bytes pkey-bytes data-bytes))))
                                       
(define generate-cms-signature-bytes(lambda (cert-bytes pkey-bytes data-bytes)
                                      (let* ([cert-len (bytes-length cert-bytes)]
                                             [pkey-len (bytes-length pkey-bytes)]
                                             [data-len (bytes-length data-bytes)]                                                                                          
                                             [_bio_mem (BIO_new_mem_buf data-bytes data-len)]
                                             [_x509Cert (d2i_X509 cert-bytes cert-len)]
                                             [_pkey (d2i_PrivateKey EVP_PKEY_RSA pkey-bytes pkey-len)] )
                                      (begin
                                        (display cert-bytes)
                                        (display data-bytes)
                                        (display "\n")                                        
                                        (display cert-len)
                                        (display "\n")                                        
                                        (display data-len)
                                        (display "\n")
                                        (display _bio_mem)
                                        (CMS_sign  _x509Cert _pkey _bio_mem)
                                        )
                                        )))

(generate-cms-signature-files "data/domain.der" "data/privkey.der" "pkey.rkt")
;;(d2i_X509 #f #f 6)