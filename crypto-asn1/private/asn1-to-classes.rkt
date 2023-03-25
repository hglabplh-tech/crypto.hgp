#lang racket/base

(require racket/class asn1
         racket/date
         racket/match
         racket/list         
         racket/serialize
         asn1
         x509
         asn1/util/time
         "interfaces.rkt"
         "cmssig-asn1.rkt"
         "asn1-utils.rkt"
         "certificates-asn1.rkt")
(provide (all-defined-out))

(define signed-data%
  (class* object% (signed-data<%>)
    (init-field der)    
    (super-new)

    (define (der->asn1)
      (let ([asn1-representation (asn1-from-content)])
        (cond [(not (equal? asn1-representation #f))
               asn1-representation]
              [else (raise (list 'exn:cms:signed-data "invalid input for ASN1 signed data"))]))) ;; fixme use struct exn as in x509

    (define/public (get-certificate-set)
      (let* ([signed-data (der->asn1)]
             [cert-data (hash-ref signed-data 'certificates #f)])
        (cond [(not (equal? cert-data #f))
               (let ([cert-list (map bytes->certificate
                                     (map x509-from-choice->DER cert-data))])
                 cert-list)]
              [else #f])))
    
    (define/public (get-signer-infos)
      (let* ([signed-data (der->asn1)]
             [signer-info-data (hash-ref signed-data 'signerInfos #f)])
        (cond [(and (not (equal? signer-info-data #f)) (list? signer-info-data))
               (map asn1->signer-info signer-info-data)]
              [else #f])))
      
                      
                      
             
    

    (define/private (asn1-from-content)
      (let* ([content (bytes->asn1 ContentInfo (get-field der this))]
             [content-type (hash-ref content 'contentType #f)])        
        (cond [(and (not (equal? content-type #f)) (equal? content-type id-cms-signed-data))
               (hash-ref content 'content #f)]
              [else #f])))
                          
        
    ))

(define signer-info%
  (class* object% (signer-info<%>)
    (init-field asn1)
    (super-new)
    
    (define/public (get-auth-attributes)
      (let ([signed-attrs (hash-ref asn1 'signedAttrs #f)])
        (map signed-attr->values-list signed-attrs)))

      
    (define/public (get-unauth-attributes)
      (hash-ref asn1 'unsignedAttrs #f))

    (define/public (get-issuer-and-serial)
      (let ([issuer-and-serial (cadr
                                ((find-value-element-proc 'issuerAndSerialNumber)
                                 (hash-ref asn1 'sid)))])
        (asn1->issuer-and-serial issuer-and-serial)))
    ))

(define issuer-and-serial%
  (class* object% (issuer-and-serial<%>)
    (init-field asn1)
    (super-new)
    
    (define/public (get-serial-number)
      (hash-ref asn1 'serialNumber #f))

    (define/public (get-issuer) 
      (let* ([issuer-raw (hash-ref asn1 'issuer)]
             [name-attr-list (cond [(not (equal? issuer-raw #f))
                                    (issuer-raw->name-attr-list issuer-raw)])])        
        (map asn1->name name-attr-list)
        ))
    ))

(define name%
  (class* object% (name<%>)
    (init-field asn1)
    (super-new)
    
    (define/public (get-attributes)     
      (map asn1->name-attribute (car asn1)))

    (define/public (get-attribute-value type)      
      (get-value-by-type type))

    (define/public (attribute-value->string type)
      (let ([value (get-value-by-type type)])
        (cond [(and value (pair? value))
               (cadr value)]
              [else value])))
    
    (define/public (get-name-normalized)
      (let ([attributes (map asn1->name-attribute asn1)])
        (cond [(not (null? attributes))
               (let recur-attrs
                 ([attrs attributes]
                  [complete-string ""])
                 (cond [(not (null? attrs))
                        (let* ([type (send (car attrs) get-type)]
                               [type-string   (hash-ref  name-oid-to-string type #f)]
                               [value (send (car attrs) get-value)]
                               [val-string  (cond [(and value (pair? value))
                                                   (cadr value)]
                                                  [else value])]
                               [complete-string (string-append
                                                 complete-string 
                                                 type-string "=" val-string ",")])
                          (recur-attrs (cdr attrs ) complete-string)
                          )]                   
                       [else (substring complete-string 0 (- (string-length complete-string) 1))]))]
              [else #f])))         
                      

    (define/private (get-value-by-type type)
      (let ([attributes (map asn1->name-attribute asn1)])
        (cond [(not (null? attributes))
               (let recur-attrs
                 ([attrs attributes])
                 (cond [(and (not (null? attrs))
                             (equal? type (send (car attrs) get-type)))
                        (send (car attrs) get-value)]
                       [(not (null? attrs))
                        (recur-attrs (cdr attrs))]
                       [else #f]))]
              [else #f])))

          
      
    ))



(define name-attribute%
  (class* object% (name-attribute<%>)
    (init-field asn1)
    (super-new)
    
    (define/public (get-type)
      (hash-ref (car asn1) 'type #f))

    (define/public (get-value)
      (hash-ref (car asn1) 'value #f))
    ))


        
      
;; class instantiation and getters
(define asn1->signer-info
  (lambda (asn1-data)
    (new signer-info% (asn1 asn1-data))))

(define asn1->issuer-and-serial
  (lambda (asn1-data)
    (new issuer-and-serial% (asn1 asn1-data))))

(define asn1->name-attribute
  (lambda (asn1-data)
    (new name-attribute% (asn1 asn1-data))))

(define asn1->name
  (lambda (asn1-data)
    (new name% (asn1 asn1-data))))

(define issuer-raw->name-attr-list
  (lambda (issuer-raw)
    (let ([rdn (cdr ((find-value-element-proc 'rdnSequence)
                     issuer-raw))])
     
      rdn)))

;; caller of class methods to use with map for lists
(define get-auth-attr (lambda (clazz)
                        (send clazz get-auth-attributes)))
(define get-unauth-attr (lambda (clazz)
                          (send clazz get-unauth-attributes)))
(define get-cert-validity (lambda (clazz)
                            (let ([validity (send clazz get-validity-date-time)])
                              (map date->string validity))))
(define get-issuer-and-serial (lambda (clazz)
                                (send clazz get-issuer-and-serial)))
(define get-serial-number (lambda (clazz)
                            (send clazz get-serial-number)))

(define get-issuer (lambda (clazz)
                     (send clazz get-issuer)))

(define get-name-attributes (lambda (clazz)
                              (send (car clazz) get-attributes)))

(define get-attrval-by-type (lambda (type)
                              (lambda (clazz)
                                (send (car clazz) get-attribute-value type))))

(define attribute-value->string (lambda (type)
                                  (lambda (clazz)
                                    (send (car clazz) attribute-value->string type))))

(define get-name-normalized (lambda (clazz)
                              (send (car clazz) get-name-normalized)))
                
;; different complex getter helpers

(define x509-from-choice->DER
  (lambda (cert-set-member)
    
    (let ([certificate  (cadr ((find-value-element-proc 'certificate) cert-set-member))])     
      ( asn1->bytes/DER Certificate certificate))))

 
  
  
;;tools



    
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

