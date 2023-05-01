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
         "asn1-oids.rkt"
         "certificates-asn1.rkt")
(provide (all-defined-out))

;;FIXME unify exception to consistent format with a exn struct
(define signed-data%
  (class* object% (signed-data<%>)
    (init-field der)    
    (super-new)

    (define (der->asn1)
      (let ([asn1-representation (asn1-from-content)])
        (cond [(not (equal? asn1-representation #f))
               asn1-representation]
              [else (raise (list 'exn:cms:signed-data "invalid input for ASN1 signed data"))]))) ;; fixme use struct exn as in x509

    (define/public (get-digest-algorithms)
      (let* ([signed-data (der->asn1)]
             [algorithms
              (hash-ref signed-data 'digestAlgorithms #f)])
        (cond [algorithms
               (map (make-format-alg-id 'digest-algorithms-must-be-there)
                    algorithms)]
              [else (error 'digest-algorithms-must-be-there)])))
               
              
    (define/public (get-certificate-set)
      (let* ([signed-data (der->asn1)]
             [cert-data (hash-ref signed-data 'certificates #f)])
        (cond [(not (equal? cert-data #f))
               (let ([cert-list (map make-cert-val-getter
                                     (map x509-from-choice->DER cert-data))])
                 cert-list)]
              [else #f])))
    
    (define/public (get-signer-infos)
      (let* ([signed-data (der->asn1)]
             [signer-info-data (hash-ref signed-data 'signerInfos #f)])
        (cond [(and (not (equal? signer-info-data #f)) (list? signer-info-data))
               (map asn1->signer-info signer-info-data)]
              [else #f])))
      
                      
    (define/public (get-encap-content-info to-hex-string)
      (let* ([signed-data (der->asn1)]
             [encap-info (hash-ref signed-data 'encapContentInfo #f)]
             [data (cond [encap-info
                          (hash-ref encap-info 'eContent #f)]
                         [else (error 'no-encap-info-present)])]
             [type (hash-ref encap-info 'eContentType #f)])
        (list type (cond [data
                          (cond [to-hex-string
                                 (bytes->hex-string data)]
                                [else data])]))
        ))    

    (define/private (asn1-from-content)
      (let* ([content (bytes->asn1 ContentInfo (get-field der this))]
             [content-type (hash-ref content 'contentType #f)])        
        (cond [(and (not (equal? content-type #f))
                    (equal? content-type id-cms-signed-data))
               (hash-ref content 'content #f)]
              [else #f])))
                          
        
    ))

(define signer-info%
  (class* object% (signer-info<%>)
    (init-field asn1)
    (super-new)

    (define/public (get-digest-algoritm)
      (let ([algorithm (hash-ref asn1 'digestAlgorithm #f)])
        (format-alg-id algorithm 'digest-algorithm-must-be-there)))
        

    (define/public (get-signature-algoritm)
      (let ([algorithm (hash-ref asn1 'signatureAlgorithm #f)])
        (format-alg-id algorithm 'signature-algorithm-must-be-there)))

    (define/public (get-signature to-hex-string)
      (let ([signature (hash-ref asn1 'signature #f)])
        (cond [signature
               (cond [to-hex-string
                      (bytes->hex signature)]
                     [else signature])]
              [else (error 'no-signature-present)])))

    
    (define/public (get-auth-attributes)
      (let ([signed-attrs (hash-ref asn1 'signedAttrs #f)])
        (cond [signed-attrs
               (map signed-attr->values-list signed-attrs)]
              [else #f])
        ))

      
    (define/public (get-unauth-attributes)
      (hash-ref asn1 'unsignedAttrs #f))

    (define/public (get-issuer-and-serial)
      (let ([issuer-and-serial (cadr
                                ((find-value-element-proc 'issuerAndSerialNumber)
                                 (hash-ref asn1 'sid)))])
        (cond [issuer-and-serial
               (asn1->issuer-and-serial issuer-and-serial)]
              [else #f])))
    
    (define/public (get-subject-identifier to-hex-string)
      (let ([sub-key-id (cadr
                         ((find-value-element-proc 'subjectKeyIdentifier)
                          (hash-ref asn1 'sid)))])
        (cond [sub-key-id
               (cond [to-hex-string
                      (bytes->hex-string sub-key-id)]
                     [else sub-key-id])]
              [else #f])))
    ))

(define issuer-and-serial%
  (class* object% (issuer-and-serial<%>)
    (init-field asn1)
    (super-new)
    
    (define/public (get-serial-number)
      (hash-ref asn1 'serialNumber #f))

    (define/public (get-issuer) 
      (let* ([issuer-raw (hash-ref asn1 'issuer #f)]
             [name-attr-list (cond [(not (equal? issuer-raw #f))
                                    (issuer-raw->name-attr-list issuer-raw)]
                                   [else '()])])        
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
                       [else (substring
                              complete-string 0
                              (- (string-length complete-string) 1))]))]
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

;; enveloped data

(define enveloped-data%
  (class* object% (enveloped-data<%>)
    (init-field der)    
    (super-new)

    (define (der->asn1)
      (let ([asn1-representation (asn1-from-content)])
        (cond [(not (equal? asn1-representation #f))
               asn1-representation]
              [else (raise (list 'exn:cms:enveloped-data "invalid input for ASN1 enveloped data"))])))

    (define/public (get-encrypted-content-info)
      (let* ([enveloped-data (der->asn1)]
             [encrypted-info
              (hash-ref enveloped-data  'encryptedContentInfo #f)])
        (asn1->encr-content-info encrypted-info)))

    (define/public (get-originator-info)
      (let* ([enveloped-data (der->asn1)]
             [originator-info (hash-ref enveloped-data 'originatorInfo #f)])
        originator-info))

    (define/public (get-recipient-infos)
      (let* ([enveloped-data (der->asn1)]
             [recipient-infos (hash-ref enveloped-data 'recipientInfos #f)])
        (map select-recipient-info recipient-infos)))
        
              
         

    (define/private (asn1-from-content)
      (let* ([content (bytes->asn1 ContentInfo (get-field der this))]
             [content-type (hash-ref content 'contentType #f)])        
        (cond [(and (not (equal? content-type #f))
                    (equal? content-type id-cms-enveloped-data))
               (hash-ref content 'content #f)]
              [else #f])))

    ))

(define encr-content-info%
  (class* object% (encr-content-info<%>)
    (init-field encr-asn1)    
    (super-new)
    
    (define/public (get-content-type)
      (hash-ref encr-asn1 'contentType #f))
    
    (define/public (get-cont-encr-alg)
      (let ([algorithm (hash-ref encr-asn1 'contentEncryptionAlgorithm #f)])
        (format-alg-id algorithm 'content-encr-algorithm-must-be-there)))

    (define/public (get-content  bytes-to-hex)
      (let ([content (hash-ref encr-asn1 'encryptedContent #f)])
        (cond [content
               (cond [bytes-to-hex
                      (bytes->hex-string content)]
                     [else content])]
              [else #f])))
    ))
                             
(define key-trans-recipient-info%
  (class* object% (key-trans-recipient-info<%>)
    (init-field info-asn1)
    (super-new)

    (define/public (get-receipt-identifier to-hex-string)
      (let* ([rid (hash-ref info-asn1 'rid #f)]
             [issuer-and-serial (assoc 'issuerAndSerialNumber (list rid))]
             [subject-key-id (assoc 'subjectKeyIdentifier (list rid))])
        (cond [issuer-and-serial
               (asn1->issuer-and-serial (cadr issuer-and-serial))]
              [subject-key-id
               (cond [to-hex-string
                      (bytes->hex-string (cadr subject-key-id))]
                     [else (cadr subject-key-id)])]
              [else #f])))

    (define/public (get-key-encrypt-algorithm)
      (let ([encr-algo (hash-ref info-asn1 'keyEncryptionAlgorithm #f)])
        (format-alg-id encr-algo 'key-encr-algo-must-be-there)))

    (define/public (get-encrypted-key to-hex-string)
      (let ([encrypted-key (hash-ref info-asn1 'encryptedKey #f)])
        (cond [encrypted-key
               (cond [to-hex-string
                      (bytes->hex-string encrypted-key)]
                     [else encrypted-key])]
              [else #f])))
              
            
    ))

(define key-agree-recipient-info%
  (class* object% (key-agree-recipient-info<%>)
    (init-field info-asn1)
    (super-new)

    (define/public (get-key-encrypt-algorithm)
      (let ([encr-algo (hash-ref info-asn1 'keyEncryptionAlgorithm #f)])
        (format-alg-id encr-algo 'key-encr-algo-must-be-there)))
    ))

(define dummy-recipient-info%
  (class object% 
    (init-field info-asn1)
    (super-new)

    (define/public (get-key-encrypt-algorithm)
      (let ([encr-algo (hash-ref info-asn1 'keyEncryptionAlgorithm #f)])
        (format-alg-id encr-algo 'key-encr-algo-must-be-there)))
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

(define asn1->encr-content-info
  (lambda (asn1-data)
    (new encr-content-info% (encr-asn1 asn1-data))))

;; caller of class methods to use with map for lists
(define get-auth-attr (lambda (clazz)
                        (send clazz get-auth-attributes)))

(define get-unauth-attr (lambda (clazz)
                          (send clazz get-unauth-attributes)))

(define get-cert-validity (lambda (cert-val-getter)
                            (let ([validity (get-validity-date-time-checked cert-val-getter)])
                              (map date->string validity))))

(define get-cert-issuer (lambda (cert-val-getter)
                            (let ([issuer (get-issuer cert-val-getter)])
                              issuer)))

(define get-issuer-and-serial (lambda (clazz)
                                (send clazz get-issuer-and-serial)))

(define get-digest-algoritm (lambda (clazz)
                              (send clazz get-digest-algoritm)))

(define get-signature-algoritm (lambda (clazz)
                                 (send clazz get-signature-algoritm)))

(define get-signature (lambda (to-hex)
                        (lambda (clazz)
                          (send clazz get-signature to-hex))))

(define get-serial-number (lambda (clazz)
                            (send clazz get-serial-number)))

(define get-issuer (lambda (clazz)
                     (send clazz get-issuer)))

(define get-name-attributes (lambda (clazz)
                              (send clazz get-attributes)))

(define get-attrval-by-type (lambda (type)
                              (lambda (clazz)
                                (send clazz get-attribute-value type))))

(define attribute-value->string (lambda (type)
                                  (lambda (clazz)
                                    (send clazz attribute-value->string type))))

(define get-name-normalized (lambda (clazz)
                              (send clazz get-name-normalized)))

(define (list-inlist-resolve fun)
  (lambda (value)
    (fun (car value))))

(define (list-inlist-resolve-param fun param)
  (let ([function (fun param)])
    (lambda (value)
      (function (car value)))))





  (define (get-recipient-class-inst clazz-def asn1-in)
    (new clazz-def (info-asn1 asn1-in)))

  (define (select-recipient-info asn1-in)
    (cond  [(assoc 'ktri (list asn1-in))
            (get-recipient-class-inst key-trans-recipient-info% (cadr asn1-in))]
           [(assoc 'kari (list asn1-in))
            (get-recipient-class-inst key-agree-recipient-info% (cadr asn1-in))]
           [(assoc 'kekri (list asn1-in))
            (get-recipient-class-inst dummy-recipient-info% (cadr asn1-in))]
           [(assoc 'pwri (list asn1-in))
            (get-recipient-class-inst dummy-recipient-info% (cadr asn1-in))]
           [(assoc 'ori (list asn1-in))
            (get-recipient-class-inst dummy-recipient-info% (cadr asn1-in))]))
  


    
  
                
  

 
  
  
  ;;tools




  