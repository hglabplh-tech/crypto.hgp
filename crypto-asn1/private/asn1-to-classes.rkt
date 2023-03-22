#lang racket/base

(require racket/class asn1
         racket/match
         racket/list         
         racket/serialize
         asn1
         x509
         asn1/util/time
         "interfaces.rkt"
         "cmssig-asn1.rkt"
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

    (define/public (get-certificates-set)
      (let* ([signed-data (der->asn1)]
             [cert-data (hash-ref signed-data 'certificates #f)])
        (cond [(not (equal? cert-data #f))
               (let ([cert-list (map bytes->certificate
                                     (map asn1->bytes/DER cert-data))])
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
      (hash-ref asn1 'signedAttrs #f)
      )
    ))
        
      
;; class instantiation and getters
(define asn1->signer-info
  (lambda (asn1-data)
    (new signer-info% (asn1 asn1-data))))
                                    
                  
    

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
                                                                       [(assoc element content-to-work)
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

