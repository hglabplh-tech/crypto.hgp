;; Copyright 2023-2025 Harald Glab-Plhak
;; 
;; This library is free software: you can redistribute it and/or modify
;; it under the terms of the GNU Lesser General Public License as published
;; by the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.
;; us
;; This library is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU Lesser General Public License for more details.
;; 
;; You should have received a copy of the GNU Lesser General Public License
;; along with this library.  If not, see <http://www.gnu.org/licenses/>.
#lang racket/base

(require racket/class asn1
         racket/date
         racket/match
         racket/list         
         racket/serialize
         asn1         
         racket/pretty     
         asn1/util/time
         "interfaces.rkt"
         "cmssig-asn1.rkt"
         "asn1-utils.rkt"
         "asn1-oids.rkt"
         "certificates-asn1.rkt")
         
(provide (all-defined-out))

;; contents definitions for sequences and choices....
;; signing
(define algo-id-seq (list
                     (list 'algorithm #t)
                     (list 'parameters #f)))

(define cms-attribute-seq (list
                           (list 'attrType #t)
                           (list 'attrValues #t)))
                           
(define signed-data-seq (list (list 'version #t)
                              (list 'digestAlgorithms #t)
                              (list 'encapContentInfo #t)
                              (list 'certificates #f);;#:optional)
                              (list 'crls #f);;#:optional)
                              (list 'signerInfos #t)))

(define encap-content-info-seq (list
                                (list 'eContentType #t)
                                (list 'eContent #f)))
(define signer-info-seq (list 
                         (list 'version #t)
                         (list 'sid #t)
                         (list 'digestAlgorithm #t)
                         (list 'signedAttrs #f)
                         (list 'signatureAlgorithm #t)
                         (list 'signature #t)
                         (list 'unsignedAttrs #f)))

(define content-info-seq (list  
                          (list 'contentType #t)        
                          (list 'content #t)))

(define certificate-choice  (list
                             'certificate
                             'extendedCertificate
                             'v1AttrCert
                             'v2AttrCert
                             'other))


(define sid-choice (list
                    'issuerAndSerialNumber
                    'subjectKeyIdentifier))

(define issuer-and-serial-seq (list (list 'issuer #t)
                                    (list 'serialNumber #t)))

(define SMIME-capability-seq (list 
                              (list 'capabilityID #t)
                              (list 'parameters #f)))
;;enveloped

(define recipient-info-choice (list
                               'ktri 
                               'kari 
                               'kekri 
                               'pwri 
                               'ori))

;; logic for build up a signed data CMS signature

(define (build-alg-id id params)
  (check-and-make-sequence algo-id-seq (list id params)))

(define (build-sid cert-bytes) 
  (let ([cert-val-getter  (build-cert-val-getter cert-bytes)])
    (check-and-make-choice sid-choice
                           (list 'issuerAndSerialNumber
                                 (check-and-make-sequence issuer-and-serial-seq
                                                          (list (get-issuer-checked cert-val-getter)

                                                                (get-serial-checked cert-val-getter)))))))
(define (smime-cap id param)
  (check-and-make-sequence SMIME-capability-seq                            
                           (list id (cond [param
                                           (make-choice 'int-val param)]
                                          [else param]))));; may be change definitions of parameters

(define (standard-smime-caps)
  (list (smime-cap id-gost-r-3411-2012-256 #f)
        (smime-cap id-gost-r-3411-2012-512 #f)
        (smime-cap id-gost-r-3411-94 #f)
        (smime-cap id-gost-r-3411-89 #f)
        (smime-cap id-aes192-CBC #f)
        (smime-cap id-aes128-CBC #f)
        (smime-cap id-des-ede3-cbc #f)
        (smime-cap id-des-cbc #f)
        (smime-cap id-rc2-cbc 128)
        (smime-cap id-rc2-cbc 64)
        (smime-cap id-rc2-cbc 40)
        ))

(define (build-signed-attributes digest-val)
  (date-display-format 'iso-8601)
  (let ([content-type-attr (check-and-make-sequence cms-attribute-seq
                                                    (list id-content-type
                                                          (list id-cms-data)))]
        [signing-time-attr (check-and-make-sequence cms-attribute-seq
                                                    (list id-signing-time
                                                          (date-time->asn1-time (current-date))))]
        [smime-cap-attrs (check-and-make-sequence cms-attribute-seq
                                                  (list id-smime-capabilities
                                                        (list (standard-smime-caps))))]
        [digest-attr (check-and-make-sequence cms-attribute-seq 
                                              (list id-message-digest (list digest-val)))])
    (make-set-of content-type-attr signing-time-attr digest-attr smime-cap-attrs)))

(define (build-cert-val-getter cert-bytes)
  (make-cert-val-getter
   cert-bytes))

(define (build-certificate-set cert-bytes-list)
  (let ([cert-set (map build-certificate cert-bytes-list)])
    cert-set))

(define (build-certificate cert-bytes)
  (let ([cert-asn1 (cert->asn1/DER cert-bytes)])
    (check-and-make-choice certificate-choice
                           (list 'certificate cert-asn1))))
;; in the following we have to introduce lambda for signature and digest taking the neccessary arguments
;; data and algorithm....
(define (build-signer-info cert-bytes digest-alg private-key
                           calc-digest-proc
                           sign-digest-proc content-bytes)
  (let* ([version 1];; here we need a cond
         [sid (build-sid cert-bytes)]
         [digest-alg-id (asn1->bytes/DER OBJECT-IDENTIFIER
                                         (hash-ref digest-alg 'algorithm))]
         [digest (calc-digest-proc digest-alg-id content-bytes)]
         [cert-val-get (build-cert-val-getter cert-bytes)]
         [signed-attrs (build-signed-attributes digest)];; next to be implemented        
         [sig-alg (get-sig-alg-checked cert-val-get)]
         [signature (sign-digest-proc digest-alg-id private-key
                                      (asn1->bytes/DER SignedAttributes signed-attrs))] ;; call callback to build signature
         )
    (check-and-make-sequence signer-info-seq (list version sid digest-alg
                                                   signed-attrs sig-alg signature #f))))
  



(define (build-signed-data digest-algs content-bytes cert-bytes-list other-x509certs attr-certs crls priv-keys
                           calc-digest-proc
                           sign-digest-proc) 
  (check-and-make-sequence signed-data-seq 
                           (list (cond [(not (null? attr-certs)) 4][else 1]) ;; version
                                 digest-algs
                                 (check-and-make-sequence
                                  encap-content-info-seq (list id-cms-data content-bytes))
                                 (build-certificate-set (append cert-bytes-list other-x509certs))                                    
                                 crls (build-sig-infos digest-algs content-bytes cert-bytes-list priv-keys
                                                       calc-digest-proc
                                                       sign-digest-proc))))

(define (build-sig-infos digest-algs content-bytes cert-bytes-list priv-keys
                         calc-digest-proc
                         sign-digest-proc)
  (let recur-signerinf ([sig-infos null]
                        [int-cert-list cert-bytes-list]
                        [int-digest-algs digest-algs]
                        [int-priv-keys priv-keys])
    (cond [(not (or (null? int-cert-list)
                    (null? int-digest-algs)
                    (null? int-priv-keys)))
           (recur-signerinf (append sig-infos
                                    (list
                                     (build-signer-info (car int-cert-list)
                                                        (car int-digest-algs) 'priv-key
                                                        calc-digest-proc
                                                        sign-digest-proc
                                                        content-bytes)))
                            (cdr int-cert-list)
                            (cdr int-digest-algs)
                            (cdr int-priv-keys))]
          [else sig-infos])))
                                               
           

  
                               

(define (build-cms-content type content)
  (check-and-make-sequence content-info-seq (list type content)))

;; the classes this will be the truth

(define signed-data-builder%
  (class object%
    (super-new)
    (init-field [digest-algs  null]
                [content-bytes #f]
                [cert-bytes-list null]
                [other-x509certs null]
                [attr-certs null]
                [crls null]               
                [signer-infos null])
    
    (define/public (add-digest-alg algorithm)
      (new this% [digest-algs (append digest-algs (list algorithm))]
           [content-bytes content-bytes]
           [cert-bytes-list cert-bytes-list]
           [other-x509certs other-x509certs]
           [attr-certs attr-certs]
           [crls crls]
           [signer-infos signer-infos]
           ))

    (define/public (add-content-bytes content)
      (new this% [digest-algs digest-algs]
           [content-bytes content]
           [cert-bytes-list cert-bytes-list]
           [other-x509certs other-x509certs]
           [attr-certs attr-certs]
           [crls crls]
           [signer-infos signer-infos]
           ))

    (define/public (add-sig-bytes sig-bytes)
      (new this% [digest-algs digest-algs]
           [content-bytes content-bytes]
           [cert-bytes-list (append cert-bytes-list (list sig-bytes))]
           [other-x509certs other-x509certs]
           [attr-certs attr-certs]
           [crls crls]
           [signer-infos signer-infos]
           ))

    (define/public (add-more-certs more-certs)
      (new this% [digest-algs digest-algs]
           [content-bytes content-bytes]
           [cert-bytes-list cert-bytes-list]
           [other-x509certs more-certs]
           [attr-certs attr-certs]
           [crls crls]
           [signer-infos signer-infos]
           ))

    (define/public (add-attr-certs attribute-certs)
      (new this% [digest-algs digest-algs]
           [content-bytes content-bytes]
           [cert-bytes-list cert-bytes-list]
           [other-x509certs other-x509certs]
           [attr-certs attribute-certs]
           [crls crls]
           [signer-infos signer-infos]
           ))

    (define/public (add-crls cert-revoc-lists)
      (new this% [digest-algs digest-algs]
           [content-bytes content-bytes]
           [cert-bytes-list cert-bytes-list]
           [other-x509certs other-x509certs]
           [attr-certs attr-certs]
           [crls cert-revoc-lists]
           [signer-infos signer-infos]
           ))

    (define/public (add-to-sig-infos-int signer-info)
      (new this% [digest-algs digest-algs]
           [content-bytes content-bytes]
           [cert-bytes-list cert-bytes-list]
           [other-x509certs other-x509certs]
           [attr-certs attr-certs]
           [crls crls]
           [signer-infos (append signer-infos (list signer-info))]
           )) 

  
    
    (define/public (add-signer-info)
      (new signer-info% [content-bytes content-bytes] [parent-obj this]))

    (define/public (build-asn1)
      (check-and-make-sequence signed-data-seq 
                               (list (cond [(not (null? attr-certs)) 4][else 1]) ;; version
                                     digest-algs
                                     (check-and-make-sequence
                                      encap-content-info-seq (list id-cms-data content-bytes))
                                     (build-certificate-set (append cert-bytes-list other-x509certs))                                    
                                     crls (map (lambda (sig-info)
                                                 (send sig-info build-asn1)) signer-infos))))
    
    ))

(define signer-info%
  (class object%
    (super-new)
    (init-field [cert-bytes #f]
                [digest-alg #f]
                [private-key #f]
                [calc-digest-proc #f]
                [sign-digest-proc #f]
                [content-bytes #f]
                [parent-obj #f])
    
    (define/public (add-cert-bytes cert-bytes-in)
      (new this%
           [digest-alg digest-alg]
           [content-bytes content-bytes]
           [cert-bytes cert-bytes-in]         
           [private-key private-key]
           [calc-digest-proc calc-digest-proc]
           [sign-digest-proc sign-digest-proc]
           [parent-obj (send parent-obj add-sig-bytes cert-bytes-in)]
           ))

    (define/public (add-digest-alg algorithm)
      (new this%
           [digest-alg algorithm]
           [content-bytes content-bytes]
           [cert-bytes cert-bytes]         
           [private-key private-key]
           [calc-digest-proc calc-digest-proc]
           [sign-digest-proc sign-digest-proc]
           [parent-obj (send parent-obj add-digest-alg algorithm)]
           ))

    (define/public (add-private-key private-key-in)
      (new this%
           [digest-alg digest-alg]
           [content-bytes content-bytes]
           [cert-bytes cert-bytes]         
           [private-key private-key-in]
           [calc-digest-proc calc-digest-proc]
           [sign-digest-proc sign-digest-proc]
           [parent-obj parent-obj]
           ))

    (define/public (add-calc-digest-proc c-dig-proc)
      (new this%
           [digest-alg digest-alg]
           [content-bytes content-bytes]
           [cert-bytes cert-bytes]         
           [private-key private-key]
           [calc-digest-proc c-dig-proc]
           [sign-digest-proc sign-digest-proc]
           [parent-obj parent-obj]
           ))

    (define/public (add-sign-digest-proc sign-dig-proc)
      (new this%
           [digest-alg digest-alg]
           [content-bytes content-bytes]
           [cert-bytes cert-bytes]         
           [private-key private-key]
           [calc-digest-proc calc-digest-proc]
           [sign-digest-proc sign-dig-proc]
           [parent-obj parent-obj]
           ))
    
    (define/public (end-def)
      (send parent-obj add-to-sig-infos-int this))
      
    
    ;; add the missing setters / add content / add parent set and end
    (define/public (build-asn1)
      (cond [(and cert-bytes digest-alg private-key content-bytes
                  calc-digest-proc sign-digest-proc)
             (build-signer-info cert-bytes digest-alg private-key
                                calc-digest-proc
                                sign-digest-proc content-bytes)]
            [else (error 'not-all-sig-info-values-set)]))
    

    ))




