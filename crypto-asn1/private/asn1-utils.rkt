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
(require asn1 asn1/util/names
         asn1/util/time
         racket/match         
         "basesig-asn1.rkt"
         "asn1-oids.rkt")
         
(provide (all-defined-out))




(define name-oid-to-string
  (hash id-at-commonName             "CN"
        id-at-localityName           "L"
        id-at-stateOrProvinceName    "ST"
        id-at-organizationName       "O"
        id-at-organizationalUnitName "OU"
        id-at-countryName            "C"
        id-domainComponent           "DC"
        id-emailAddress              "EMAIL"))

;;attribute value transformations

(define (signed-attr->values-list  attr-value)
  (let* ([type (hash-ref attr-value 'attrType #f)]
         [values (hash-ref attr-value 'attrValues #f)]
         [fun (attr-type->fun type)])
         (fun values)))
        

(define (asn1->smime-capability attr-value)
  (let ([id (hash-ref attr-value 'capabilityID #f)]        
        [params (hash-ref attr-value 'parameters 'no-param)])
    (cons id (cond [(not (equal? params 'no-param))
                    (let ([parm-int (assoc 'int-val (list params))]
                          [parm-octet (assoc 'octet-string (list params))])
                      (cond [parm-int
                             (cadr parm-int)]
                            [parm-octet
                             (bytes->hex (cadr parm-octet))]
                            [else params]))]
                   [else params]))))
                          
(define (attr-type->fun attr-type)
  (or (relation-ref ATTRVAL-GET-FUNS 'type attr-type 'val-fun) ANY))     
            
                  
         

(define (asn1->smime-attrs-seq attr-value)
  (map asn1->smime-capability attr-value))

(define (asn1-smime-attrs->smime-cap attr-value)
  (map asn1->smime-attrs-seq attr-value))
  
  
(define (asn1-time->seconds t)
  (define (map-num ss) (map string->number ss))
  (match t
    [(list 'utcTime s)
     ;; See 4.1.2.5.1 for interpretation (YY in range [1950-2049]).
     (asn1-utc-time->seconds s)]
    [(list 'generalTime s)
     (asn1-generalized-time->seconds s)]))

(define (asn1-time->date-time attr-value)
  (seconds->date (asn1-times->seconds attr-value)))

(define (asn1-times->seconds attr-value)
  (cond [(and (list? attr-value) (pair? (car attr-value)))
     (asn1-time->seconds (car attr-value))]))

(define (asn1->content-type attr-value)
  attr-value)

(define (asn1->digest attr-value)
  (map bytes->hex attr-value))


(define ATTRVAL-GET-FUNS
  (relation
   #:heading
   ['type                         'val-fun]
   #:tuples
   [id-smime-capabilities        asn1-smime-attrs->smime-cap]
   [id-content-type              asn1->content-type]
   [id-message-digest            asn1->digest]
   [id-signing-time              asn1-time->date-time ]
   [id-counter-signature         (lambda (arg)
                                   (map asn1->bytes/DER ANY arg))] ;; last one may be has to be enhanced
   
   ))


;; other utils

(define (byte->hex b) (bytes-ref #"0123456789abcdef" b))

(define (bytes->hex bs)
  (let* ([len (bytes-length bs)]
         [obs (make-bytes (* 2 len))])
    (for ([i (in-range len)])
      (let ([b (bytes-ref bs i)]
            [j (* 2 i)])
        (bytes-set! obs j (byte->hex (arithmetic-shift b -4)))
        (bytes-set! obs (add1 j) (byte->hex (bitwise-and b #x0f)))))
    obs))

(define (bytes->hex-string bs)
  (bytes->string/latin-1 (bytes->hex bs)))