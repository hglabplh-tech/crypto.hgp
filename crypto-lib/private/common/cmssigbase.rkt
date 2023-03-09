;; Copyright 2013-2022 Ryan Culpepper
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
(require racket/class
         racket/match
         asn1
         binaryio/integer
         base64
         "catalog.rkt"
         "interfaces.rkt"
         "common.rkt"
         "error.rkt"
         "base256.rkt"
         "asn1.rkt"
         "bytestreaming.rkt"
         "../../util/bech32.rkt")
(provide (all-defined-out))

(define cms-sign-impl-base%
  (class* impl-base% (cms-sign<%>)
    (inherit about get-spec get-factory)
    (super-new)
    (define/public (cms-sign-sure cert-bytes pkey-bytes pkey-fmt cert-stack-list data-bytes flags) #f)
    (define/public (cms-init-signing cert-bytes pkey-bytes pkey-fmt cert-stack-list data-bytes flags) #f)
    (define/public (cms-add-cert box-content-info cert-bytes) #f)
    (define/public (cms-signerinfo-sign) #f)
    (define/public (cms-add-signer box-content-info cert-bytes pkey-bytes digest-name flags) #f)
    (define/public (cms-sign-finalize box-content-info data-bytes flags) #f)
    (define/public (get-cms-content-info box-content-info ) #f)
    (define/public (get-cms-content-info/DER box-content-info) #f)
    (define/public (cms-sign-receipt box-content-info cert-bytes cert-stack-list pkey-bytes pkey-fmt flags) #f)
    (define/public (cms-encrypt cert-stack-list data-bytes cipher-name flags) #f)
    (define/public (cms-add-recipient-cert box-content-info cert-bytes flags) #f)
    (define/public (get-cms-content-info-type box-content-info) #f)
    (define/public (get-pkey-format-from-sym pkey-fmt) #f)
    (define/public (cms-encrypt-with-skey skey-bytes data-bytes cipher-name flags) #f)
    (define/public (smime-write-CMS box-content-info fname flags) #f)
    (define/public (smime-write-CMS-detached box-content-info fname data-bytes flags) #f)
    (define/public (write-CMS/BER box-content-info fname flags) #f)
    
    ))

(define cms-check-explore-impl-base%
  (class* impl-base% (cms-check-explore<%>)
    (inherit about get-spec get-factory)
    (super-new)
    (define/public (cms-sig-verify contentinfo-buffer cert-stack-list flags) #f)
    (define/public (cms-decrypt contentinfo-buffer cert-bytes pkey-bytes pkey-fmt fname flags) #f)
    (define/public (cms-smime-decrypt smimecont-buffer cert-bytes pkey-bytes pkey-fmt fname flags) #f)
    (define/public (cms-decrypt-with-skey  contentinfo-buffer skey-bytes fname flags) #f)
    (define/public (cms-signinfo-get-first-signature box-content-info) #f)))

(define cms-tools-base% 
   (class* impl-base% (cms-tools<%>)
     (inherit about get-spec get-factory)
    (super-new)

     (define/public (internal-bytes-read-fun) #f)

     (define/public (stream-file-write)
       (lambda (buffer buff-len port)
                 (write-bytes-avail buffer port 0 buff-len)))
     
     (define/public (open-stream-file-write fname)
       (open-output-file fname #:mode 'binary #:exists 'replace))

      (define/public (open-stream-mem)
        (new  bytes-stream%))
     
     (define/public (stream-write-mem)
       (lambda (buffer buff-len stream)
       (send stream write-bytes-range buffer 0 buff-len)))

     (define/public (get-bytes-from-mem stream)
       (send stream get-bytes))
  
     (define/public (close-fun proc-close-in proc-close-out)
       (lambda (source target)
         (cond [(not (eq? proc-close-in #f)) (proc-close-in source)])
         (cond [(not (eq? proc-close-out #f)) (proc-close-out target)])))

     (define/public (call-with-val-copy-stream proc)       
       (call-with-values proc copy-stream-by-funs))     

     (define/public (build-copy-stream in-proc source out-proc target close-proc)
       (lambda ()         
         (values in-proc source out-proc target close-proc)))
     ))
