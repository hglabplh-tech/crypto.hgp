#lang racket/base
(require ffi/unsafe
         ffi/unsafe/define
         ffi/unsafe/alloc
         ffi/unsafe/atomic
         opencl/c/types
         openssl/libcrypto
         binaryio/reader
         rnrs/io/ports-6
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
(define-cpointer-type _X509)

(define-crypto X509_free
  (_fun _X509 -> _void)
  #:wrap (deallocator))

(define-crypto X509_new
  (_fun -> _X509/null)
  #:wrap (compose (allocator X509_free) (err-wrap/pointer 'X509_new)))

 
(define _px509/null (_cpointer/null (_cpointer/null _X509/null)))
(define _charpp (_cpointer/null _bytes))

(define-crypto d2i_X509 (_fun
                          (_pointer = #f) _dptr_to_bytes _long -> _X509/null)
  #:wrap (compose (allocator X509_free) (err-wrap/pointer 'd2i_X509)))
                          
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
(define generate-cms-signature-files (lambda(cert-fname data-fname)
                                 (let* ([cert-bytes (read-bytes-from-file cert-fname)]
                                       [data-bytes  (read-bytes-from-file data-fname)])
                                   (generate-cms-signature-bytes cert-bytes data-bytes))))
                                       
(define generate-cms-signature-bytes(lambda (cert-bytes data-bytes)
                                      (let* ([cert-len (bytes-length cert-bytes)]
                                             [data-len (bytes-length data-bytes)]
                                             [_p_cert-bytes (_dptr-to-bytes cert-bytes)]
                                             [_p_data-bytes (_dptr-to-bytes data-bytes)]
                                             [_pp_cert-bytes (_dptr_to_dptr _p_cert-bytes)] )
                                      (begin
                                        (display cert-bytes)
                                        (display data-bytes)
                                        (display cert-len)
                                        (display "\n")
                                        (display _pp_cert-bytes)
                                        (display "\n")
                                        (display data-len)
                                        (d2i_X509 cert-bytes cert-len))
                                        )))

(generate-cms-signature-files "ffi.rkt" "pkey.rkt")
;;(d2i_X509 #f #f 6)