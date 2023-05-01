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
         rnrs/io/ports-6
         binaryio/reader
         racket/string
         racket/date
         "cmssig-asn1.rkt"
         "certificates-asn1.rkt"
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

                         
(define (attr-type->fun attr-type)
  (or (relation-ref ATTRVAL-GET-FUNS 'type attr-type 'val-fun) (lambda (v) v)))  

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
                            [else (cadr params)]))]
                   [else params]))))         

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

(define (date-time->asn1-time time)
  (date-display-format 'iso-8601)
  (let ([date-string (string-append (string-replace (string-replace
                                                     (string-replace
                                                      (date->string time #t) "-" "") "T" "")
                                                    ":" "") "Z")])
    (printf "date string : ~a\n" date-string)
    (cond [(asn1-generalized-time? date-string)
           (make-set-of (list 'generalTime  date-string))]
          [else (error 'time-string-invalid)]))) ;; FIXME: define the choice for time
        
         
(define (asn1-time->date-time attr-value)
  (seconds->date (asn1-times->seconds attr-value)))

(define (asn1-times->seconds attr-value)
  (cond [(and (list? attr-value) (pair? (car attr-value)))
         (asn1-time->seconds (car attr-value))]))

(define (asn1->content-type attr-value)
  attr-value)

(define (asn1->digest attr-value)
  (map bytes->hex attr-value))

(define (make-format-alg-id error-sym)
  (lambda (algorithm)
    (format-alg-id algorithm error-sym)))
    
(define (format-alg-id algorithm error-sym)
  (cond [algorithm
         (list (hash-ref algorithm 'algorithm #f)
               (hash-ref algorithm 'parameters #f))]
        [else (error error-sym)]))


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

;; utils to build ASN.1 structures


(define (make-sequence key-list value-list)
  (cond [(not (equal? (length key-list) (length value-list)))
         #f])
  (let recur-lists ([result-list '()]
                    [k-list key-list]
                    [v-list value-list])
    (cond [(null? k-list)
           (make-hasheq result-list)]
          [else
           (recur-lists (cond [(not (equal? (car v-list) #f))
                               (append result-list (list
                                                    (cons (car k-list)
                                                          (car v-list))))]
                              [else result-list])
                        (cdr k-list)
                        (cdr v-list))])
    ))

(define (check-and-make-choice choice-defs key-value-pair)
  (let recur-test ([c-defs choice-defs])
    (cond [(null? c-defs)
           (error 'illegal-choice-tag)]
          [else
           (let ([assoc-result
                  (assoc
                   (car c-defs)
                   (list key-value-pair))])

             (cond [(pair? assoc-result)
                    (make-choice (car key-value-pair) (cadr key-value-pair))]
                   [else (recur-test (cdr c-defs))]))])))
    

(define (check-and-make-sequence sequence-defs values)
  (let recur-defs ([seq-defs sequence-defs]
                   [val-list values]
                   [result-keys '()])
    (cond [(or (null? val-list) (null? sequence-defs))
           (make-sequence (map car sequence-defs) values)]
          [ else (cond [(and (equal? (cadr (car seq-defs)) #t)
                             (equal? (car val-list) #f))
                        (error 'seq-mandatory-not-set)]
                       [else (recur-defs (cdr seq-defs) (cdr val-list)
                                         (append result-keys (list (caar seq-defs))))])])))
           
           
                              

(define (make-set key-list value-list)
  (cond [(not (equal? (length key-list) (length value-list)))
         #f])
  (let recur-lists ([result-list '()]
                    [k-list key-list]
                    [v-list value-list])
    (cond [(null? k-list)
           (make-hash result-list)]
          [else
           (recur-lists (append result-list (cons
                                             (car k-list)
                                             (car v-list)))
                        (cdr k-list)
                        (cdr v-list))])
    ))

(define (make-choice key value)
  (list key value))

;; this is defined because the internal definition can change
(define make-set-of
  (lambda comp-list
    comp-list))
                

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

;; different complex getter helpers

    
(define find-value-element (lambda (content  varargs)
                             (let recur-find-value ([content-to-work content]
                                                    [args varargs])
                               (cond [(null? args) content-to-work])
                               (let* (
                                      [element (car args)]
                                      [found-content (cond [(hash? content-to-work) (hash-ref content-to-work element #f)]
                                                           [else (cond [(not (andmap pair? content-to-work))
                                                                        content-to-work]
                                                                       [(not
                                                                         (equal?
                                                                          (assoc element content-to-work) #f))
                                                                        (cadr(assoc element content-to-work))]
                                                                       [else #f])])])
                                 (cond [found-content
                                        (cond [(null? (cdr args))
                                               found-content]
                                              [else (recur-find-value found-content (cdr args))])]
                                       [else content-to-work])))))
                                                  
(define find-value-element-proc (lambda varargs
                                  (lambda (content)
                                    (find-value-element content  varargs))))
;; functions for certificates
(define x509-from-choice->DER
  (lambda (cert-set-member)    
    (let ([certificate  (cadr ((find-value-element-proc 'certificate) cert-set-member))])     
      ( asn1->bytes/DER Certificate certificate))))

(define (make-cert-val-getter cert/DER)
  (let* ([cert-asn1 (bytes->asn1/DER Certificate cert/DER)]
         [tbs-asn1 (hash-ref cert-asn1 'tbsCertificate)])
    (lambda (reference)
      (let ([cert-ref-val (hash-ref cert-asn1 reference #f)]
            [tbs-ref-val (hash-ref tbs-asn1 reference #f)])
        (cond [tbs-ref-val
               tbs-ref-val]
              [cert-ref-val
               cert-ref-val]
              [else #f])))))

(define (cert->asn1/DER cert/DER)
  (let* ([cert-asn1 (bytes->asn1/DER Certificate cert/DER)])
    cert-asn1))

(define (get-validity-date-time validity)
  (map seconds->date (get-validity-seconds validity)))

(define (get-validity-seconds validity)
  (cond [(hash? validity)               
         (list (asn1-time->seconds (hash-ref validity 'notBefore))
               (asn1-time->seconds (hash-ref validity 'notAfter)))] 
        [else (error 'validity-invalid)]))

(define (get-validity-date-time-checked cert-val-getter)
  (let* ([validity (cert-val-getter 'validity)])
    (cond [validity
           (get-validity-date-time validity)]
          [else (error 'validity-invalid-val)])))

(define (get-issuer-checked cert-val-getter)
  (let* ([issuer (cert-val-getter 'issuer)])
    (cond [issuer
           issuer]
          [else (error 'issuer-invalid)])
           
    ))

(define (get-serial-checked cert-val-getter)
  (let* ([serial (cert-val-getter 'serialNumber)])
    (cond [serial
           serial]
          [else (error 'serial-invalid)])
           
    )) 

(define (get-sig-alg-checked cert-val-getter)
  (let ([sig-alg (cert-val-getter 'signature)])
    (cond [sig-alg
           sig-alg]
          [else (error 'serial-invalid)])
           
    )) 
                              
                                
           

;; general utility funs
(define read-bytes-from-file
  (lambda (fname)
    (let*([port (open-file-input-port fname)]
          [reader (make-binary-reader port)]
          {file-size (file-size fname)}
          )
      (b-read-bytes reader file-size)
      )))