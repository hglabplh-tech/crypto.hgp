;; Copyright 2023-2024 Harald Glab-Plhak
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

#lang racket/base
(require ffi/unsafe
         ffi/unsafe/define
         ffi/unsafe/alloc
         ffi/unsafe/atomic
         openssl/libcrypto
         openssl/sha1
         "ffitypes.rkt"
         "../common/error.rkt"
         "ffi.rkt")
(provide (protect-out (all-defined-out))
         libcrypto
         EVP_CIPHER_get_key_length
         EVP_CIPHER_key_length
         d2i_PrivateKey
         EVP_PKEY_RSA
         EVP_PKEY_DSA
         EVP_PKEY_DH
         EVP_PKEY_EC
         NID_X25519
         NID_X448
         NID_ED25519
         NID_ED448
         i2d
         EVP_get_digestbyname
         EVP_get_cipherbyname)

;;=======================================================================
;; CMS signature ffi description / definition
;;=======================================================================
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

(define BIO_NOCLOSE             #x00)
(define BIO_CLOSE               #x01)
(define BIO_CTRL_EOF            2)
(define BIO_C_SET_BUF_MEM       114)

;; content-info-types
(define sig-cinfo-type            "2a864886f70d010702")
(define encr-cinfo-type           "2a864886f70d010703")
(define symmetric-encr-cinfo-type "2a864886f70d010706")



;;========================================
;;fun definitions and struct pointers
;;========================================





;;BIO create mem BIO for CMS signing
;;BIO *BIO_new_mem_buf(const void *buf, int len);
(define-cpointer-type _BIO)
(define-cpointer-type _BIO_METHOD)
(define-cpointer-type _BUF_MEM)

(define-crypto BIO_s_mem (_fun -> _BIO_METHOD/null)
  #:wrap (err-wrap/pointer 'BIO_s_mem))

(define-crypto BIO_vfree(_fun _BIO -> _void)
  #:wrap (deallocator))

(define-crypto BUF_MEM_free(_fun _BUF_MEM -> _void)
  #:wrap (deallocator))

(define-crypto BIO_new (_fun _BIO_METHOD -> _BIO/null)
  #:wrap (compose (allocator BIO_vfree)
                  (err-wrap/pointer 'BIO_s_mem)))

(define-crypto BIO_new_mem_buf (_fun
                 _pointer _int -> _BIO/null)
                 #:wrap (compose (allocator BIO_vfree)
                                 (err-wrap/pointer 'BIO_new_mem_buf)))

(define-crypto BUF_MEM_new(_fun -> _BUF_MEM)
  #:wrap (compose (allocator BUF_MEM_free)
                  (err-wrap/pointer 'BIO_MEM_new)))

(define-crypto BIO_get_data(_fun _BIO -> _pointer)                                                   
  #:wrap (err-wrap/pointer 'BIO_get_data))

(define-crypto BIO_ctrl(_fun _BIO _int _long _pointer -> _long)
  #:wrap (err-wrap 'BIO_ctrl))

(define-crypto BIO_read(_fun _BIO _pointer _int  -> _int)
  #:wrap (err-wrap 'BIO_read))


(define (build-set-membuf-no-close mem-bio)
  (let ([buf-mem (BUF_MEM_new)])
  (BIO_ctrl mem-bio BIO_C_SET_BUF_MEM BIO_NOCLOSE buf-mem)
    mem-bio))

(define (build-writeable-mem-bio)
  (let ([mem-bio (BIO_new(BIO_s_mem))])
    (build-set-membuf-no-close mem-bio)))

(define (BIO_eof bio)
  (BIO_ctrl bio BIO_CTRL_EOF #x00 #f))



;; X509 Pointer
(define-cpointer-type _X509)


(define-crypto X509_free
  (_fun _X509 -> _void)
  #:wrap (deallocator))

(define-crypto X509_new
  (_fun -> _X509/null)
  #:wrap (compose (allocator X509_free) (err-wrap/pointer 'X509_new)))

 
;; define read funcion for getting a _X509 from DER
(define-crypto d2i_X509 (_fun
                          (_pointer = #f) _dptr_to_bytes _long -> _X509/null)
  #:wrap (compose (allocator X509_free) (err-wrap/pointer 'd2i_X509)))

(define-crypto d2i_X509_bio (_fun
                          _BIO (_pointer = #f) -> _X509/null)
  #:wrap (compose (allocator X509_free) (err-wrap/pointer 'd2i_X509_bio)))

;; CMS signing

;;define a *char pointer
(define buff-pointer-new (lambda(buffer)
                                    (let ([p (malloc _byte (bytes-length buffer) 'atomic)])
                                      (memcpy p buffer (bytes-length buffer) _byte) p)))
;; try to define stack
(define-cpointer-type _STACK)

(define-crypto OPENSSL_sk_free(_fun _STACK -> _void)
   #:wrap (deallocator))

(define-crypto OPENSSL_sk_new_null (_fun -> _STACK)
  #:wrap (compose (allocator OPENSSL_sk_free)
                  (err-wrap/pointer 'OPENSSL_sk_new_null)))

  
 
(define-crypto OPENSSL_sk_push(_fun _STACK  _pointer -> _int)
   #:wrap (err-wrap 'OPENSSL_sk_push))

(define-crypto OPENSSL_sk_pop(_fun _STACK -> _pointer)
   #:wrap (err-wrap/pointer 'OPENSSL_sk_pop))

(define-crypto OPENSSL_sk_num(_fun _STACK -> _int)
   #:wrap (err-wrap 'OPENSSL_sk_num))

(define-crypto OPENSSL_sk_value(_fun _STACK  _int -> _pointer)
   #:wrap (err-wrap/pointer 'OPENSSL_sk_value))


(define sk-typed-pop (lambda (stack type)
                    (let ([value (OPENSSL_sk_pop stack)])
                      (cast value _pointer type)
                      )))

(define sk-typed-value (lambda (stack index type)
                    (let ([value (OPENSSL_sk_value stack index)])
                      (cast value _pointer type)
                      )))

  
;;CMS_ContentInfo *CMS_sign(X509 *signcert, EVP_PKEY *pkey, STACK_OF(X509) *certs,
                           ;;BIO *data, unsigned int flags);

(define-cpointer-type _CMS_ContentInfo)
(define-cpointer-type _CMS_SignerInfo)
(define-cpointer-type _CMS_RecipientInfo)

(define-crypto CMS_ContentInfo_free(_fun _CMS_ContentInfo  -> _void)
  #:wrap (deallocator))

(define-crypto i2d_CMS_ContentInfo (_fun
                                    _CMS_ContentInfo (_ptr i _pointer) -> _int)
  #:wrap (err-wrap 'i2d_CMS_ContentInfo))
;;int i2d_CMS_ContentInfo(CMS_ContentInfo *a, unsigned char **pp);

(define-crypto CMS_sign (_fun
                _X509 _EVP_PKEY _STACK/null _BIO _uint -> _CMS_ContentInfo/null)
                #:wrap (compose (allocator CMS_ContentInfo_free) (err-wrap/pointer 'CMS_sign)))

;;int CMS_final(CMS_ContentInfo *cms, BIO *data, BIO *dcont, unsigned int flags);

(define-crypto CMS_final (_fun _CMS_ContentInfo _BIO/null _BIO/null _uint -> _int)
  #:wrap (err-wrap 'CMS_final))

;;int CMS_add1_cert(CMS_ContentInfo *cms, X509 *cert);

(define-crypto CMS_add1_cert (_fun _CMS_ContentInfo _X509 -> _int)
  #:wrap (err-wrap 'CMS_add1_cert))

;;CMS_SignerInfo *CMS_add1_signer(CMS_ContentInfo *cms, X509 *signcert,
                                ;;EVP_PKEY *pkey, const EVP_MD *md,
                                ;;unsigned int flags);

(define-crypto CMS_add1_signer (_fun _CMS_ContentInfo _X509 _EVP_PKEY _EVP_MD _uint -> _CMS_SignerInfo/null)
  #:wrap (err-wrap/pointer 'CMS_add1_signer))

;;int CMS_SignerInfo_sign(CMS_SignerInfo *si);

(define-crypto CMS_SignerInfo_sign (_fun _CMS_SignerInfo -> _int)
   #:wrap (err-wrap 'CMS_SignerInfo_sign))

;;int CMS_verify(CMS_ContentInfo *cms, STACK_OF(X509) *certs, X509_STORE *store,
;;               BIO *indata, BIO *out, unsigned int flags);

(define-crypto CMS_verify(_fun _CMS_ContentInfo _STACK/null (_pointer = #f)
               _BIO/null _BIO/null _uint -> _int)
  #:wrap (err-wrap 'CMS_verify))

;; Recipient signature

;;STACK_OF(CMS_SignerInfo) *CMS_get0_SignerInfos(CMS_ContentInfo *cms);

(define-crypto CMS_get0_SignerInfos(_fun _CMS_ContentInfo -> _STACK/null)
  #:wrap (err-wrap/pointer 'CMS_get0_SignerInfos))

;; CMS_ContentInfo *CMS_sign_receipt(CMS_SignerInfo *si, X509 *signcert,
;;                                  EVP_PKEY *pkey, STACK_OF(X509) *certs,
;;                                  unsigned int flags);

(define-crypto CMS_sign_receipt(_fun _CMS_SignerInfo _X509 _EVP_PKEY _STACK/null _int -> _CMS_ContentInfo/null)
    #:wrap (err-wrap/pointer 'CMS_sign_receipt))

;;CMS_ContentInfo *CMS_encrypt(STACK_OF(X509) *certs, BIO *in,
  ;;                           const EVP_CIPHER *cipher, unsigned int flags);                          

(define-crypto CMS_encrypt(_fun _STACK _BIO _EVP_CIPHER _int -> _CMS_ContentInfo/null)
  #:wrap (compose (allocator CMS_ContentInfo_free) (err-wrap/pointer 'CMS_encrypt)))



;;CMS_RecipientInfo *CMS_add1_recipient_cert(CMS_ContentInfo *cms, X509 *recip, unsigned int flags);

(define-crypto CMS_add1_recipient_cert(_fun _CMS_ContentInfo _X509 _uint -> _CMS_RecipientInfo/null)
  #:wrap (err-wrap/pointer 'CMS_add1_recipient_cert))

;;CMS_RecipientInfo *CMS_add0_recipient_key(CMS_ContentInfo *cms, int nid, unsigned char *key, size_t keylen, unsigned char *id, size_t idlen, ASN1_GENERALIZEDTIME *date, ASN1_OBJECT *otherTypeId, ASN1_TYPE *otherType);

;;CMS_ContentInfo *d2i_CMS_ContentInfo(CMS_ContentInfo **a, unsigned char **pp, long length);

(define-crypto d2i_CMS_ContentInfo (_fun
                          (_pointer = #f) _dptr_to_bytes _long -> _CMS_ContentInfo/null)
  #:wrap (compose (allocator CMS_ContentInfo_free) (err-wrap/pointer 'd2i_CMS_ContentInfo)))

;;int CMS_decrypt(CMS_ContentInfo *cms, EVP_PKEY *pkey, X509 *cert, BIO *dcont, BIO *out, unsigned int flags);

(define-crypto CMS_decrypt (_fun _CMS_ContentInfo _EVP_PKEY/null _X509/null (_pointer = #f) _BIO _uint -> _int)
  #:wrap (err-wrap 'CMS_decrypt)) ;;FIXME

;;int CMS_decrypt_set1_pkey(CMS_ContentInfo *cms, EVP_PKEY *pk, X509 *cert); :: give it a try to use both functions see
;;https://www.openssl.org/docs/manmaster/man3/CMS_decrypt.html

(define-crypto CMS_decrypt_set1_pkey (_fun _CMS_ContentInfo _EVP_PKEY _X509 -> _int)
  #:wrap (err-wrap 'CMS_decrypt_set1_pkey))

;; CMS_ContentInfo *SMIME_read_CMS(BIO *in, BIO **bcont);

(define-crypto SMIME_read_CMS (_fun _BIO (_pointer = #f) -> _CMS_ContentInfo)
  #:wrap (compose (allocator CMS_ContentInfo_free)(err-wrap/pointer 'SMIME_read_CMS)))

;;int SMIME_write_CMS(BIO *out, CMS_ContentInfo *cms, BIO *data, int flags);
(define-crypto SMIME_write_CMS (_fun _BIO _CMS_ContentInfo _BIO/null _int -> _int)
  #:wrap (err-wrap 'SMIME_write_CMS))

;;int i2d_CMS_bio_stream(BIO *out, CMS_ContentInfo *cms, BIO *data, int flags);
(define-crypto i2d_CMS_bio_stream (_fun _BIO _CMS_ContentInfo _BIO/null _int -> _int)
  #:wrap (err-wrap 'i2d_CMS_bio_stream))

;;ASN1_OCTET_STRING *CMS_SignerInfo_get0_signature(CMS_SignerInfo *si);

(define-crypto CMS_SignerInfo_get0_signature (_fun _CMS_SignerInfo -> (octet : _pointer)
                                                   -> (ptr-ref octet _asn1_string_st))
  #:wrap (err-wrap/pointer 'CMS_SignerInfo_get0_signature))

 (define asn1-octet-members-as-list (lambda (instance)
                               (let ([octet-length (asn1_string_st-length instance)]
                                     [octet-type (asn1_string_st-type instance)]
                                     [octet-val (asn1_string_st-data instance)]
                                     [octet-flags (asn1_string_st-flags instance)])
                                 (list (list 'octet-length octet-length) (list 'octet-type octet-type)
                                       (list 'octet-val octet-val) (list 'octet-flags octet-flags)))))

;; Get data from contentinfo / meta data and content

;;const ASN1_OBJECT *CMS_get0_type(CMS_ContentInfo *cms);

(define-cpointer-type _ASN1_OBJECT)

(define-crypto CMS_get0_type (_fun _CMS_ContentInfo -> _ASN1_OBJECT)
  #:wrap (err-wrap/pointer 'CMS_get0_type))

;;size_t OBJ_length(const ASN1_OBJECT *obj);
;; const unsigned char *OBJ_get0_data(const ASN1_OBJECT *obj);

(define-crypto OBJ_length (_fun _ASN1_OBJECT -> _size)
  #:wrap (err-wrap 'OBJ_length))

(define-crypto OBJ_get0_data (_fun _ASN1_OBJECT -> _bytes)
  #:wrap (err-wrap/pointer 'OBJ_get0_data))

(define (get-asn1-data object)
  (let* ([length (OBJ_length object)]
        [bytes (OBJ_get0_data object)]
        [buffer (make-bytes length)])
    (memcpy buffer bytes (bytes-length buffer) _byte) (bytes->hex-string buffer)))
    


;;===============================================
;;simple encryption /decryption
;;===============================================

;;CMS_ContentInfo *CMS_EncryptedData_encrypt(BIO *in,
;;const EVP_CIPHER *cipher, const unsigned char *key, size_t keylen,
  ;;  unsigned int flags);

(define-crypto CMS_EncryptedData_encrypt (_fun _BIO _EVP_CIPHER  _bytes _size _uint -> _CMS_ContentInfo/null)
  #:wrap (compose (allocator CMS_ContentInfo_free)
                   (err-wrap/pointer 'CMS_EncryptedData_encrypt)))

;;int CMS_EncryptedData_decrypt(CMS_ContentInfo *cms,
;;                              const unsigned char *key, size_t keylen,
;;                              BIO *dcont, BIO *out, unsigned int flags);

(define-crypto CMS_EncryptedData_decrypt(_fun _CMS_ContentInfo
                              _bytes _size _BIO/null _BIO _uint -> _int)
   #:wrap (err-wrap 'CMS_EncryptedData_decrypt))
  