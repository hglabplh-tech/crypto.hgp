#lang racket/base
(require 
  "cmssig-asn1.rkt"
  "asn1-to-classes.rkt"
  "asn1-oids.rkt"
  "interfaces.rkt"
  "asn1-utils.rkt"
  asn1        
  racket/class
  racket/pretty
  binaryio/reader
  rnrs/io/ports-6)




(define test-Bytes->ASN1(lambda (fname)
                          (let ([bytes (read-bytes-from-file fname)])
                            (bytes->asn1 ContentInfo bytes))))


(displayln id-cms-enveloped-data)
(displayln id-cms-signed-data)


(let* ([bytes (read-bytes-from-file  "data/cms-sig-ext.pkcs7")]
       [signed-data (new signed-data% (der bytes))]
       [sig-info-list (send signed-data get-signer-infos)])  
  (displayln sig-info-list)
  (printf "digest algorithms in signed data :\n~a\n" (send signed-data get-digest-algorithms))
  (printf "encapsulated data :\n~a\n" (send signed-data get-encap-content-info #f))  
  (printf " validity : ~a\n" (map get-cert-validity (send signed-data get-certificate-set)))
  (printf " cert issuer : ~a\n" (map get-issuer-checked (send signed-data get-certificate-set)))
  (printf "signed attributes :\n")
  (pretty-print (map get-auth-attr sig-info-list))
  (printf "issuer and serial :\n")
  (pretty-print (map get-serial-number (map get-issuer-and-serial sig-info-list)))
  (printf "sig-info digest-algorithm :\n")
  (pretty-print (map get-digest-algoritm sig-info-list))
  (printf "sig-info signature-algorithm :\n")
  (pretty-print (map get-signature-algoritm sig-info-list))
  (printf "signature (raw):\n")
  (pretty-print (map (get-signature #f) sig-info-list))
  (printf "signature (hex):\n")
  (pretty-print (map (get-signature #t) sig-info-list))
  (printf "issuer  :\n")
  (pretty-print (map get-issuer (map get-issuer-and-serial sig-info-list)))
  (printf "issuer attributes :\n")
  (for-each (lambda (v) (pretty-print ((list-inlist-resolve get-name-attributes) v)))
                                                           
            (map get-issuer (map get-issuer-and-serial sig-info-list)))
  (printf "get issuer asn1:\n")
  (pretty-print (map get-issuer-and-serial sig-info-list))
  (printf "issuer -attr field :\n")
  (pretty-print (map (list-inlist-resolve-param attribute-value->string id-at-commonName)
                     (map get-issuer (map get-issuer-and-serial sig-info-list))))
  (printf "normalized issuer: \n")
  (pretty-print (map (list-inlist-resolve get-name-normalized)
                     (map get-issuer (map get-issuer-and-serial sig-info-list))))
          
  (map get-unauth-attr sig-info-list))



;;(displayln "=============================================================")
(let* ([bytes (read-bytes-from-file  "data/cms-envelop-ext.pkcs7")]
       [enveloped-data (new enveloped-data% (der bytes))]
       [encr-content-info (send enveloped-data get-encrypted-content-info)])
  (pretty-print encr-content-info)
  (printf "encrypted content type : ~a \n" (send encr-content-info get-content-type))
  (printf "encrypted content algorithm : ~a \n" (send encr-content-info get-cont-encr-alg))
  ;;(printf "encrypted content raw :\n" )
  ;;(pretty-print (send encr-content-info get-content #f))
  (printf "encrypted content hex-string :\n" )
  (pretty-print (send encr-content-info get-content #t))
  (printf "originator info :\n" ) 
  (pretty-print (send enveloped-data get-originator-info))
  (printf "recipient infos :\n" ) 
  (let ([receipt-list (send enveloped-data get-recipient-infos)])
    (printf "values of first info :\n" )
    (printf "get-receipt-identifier to-hex-string\n\n")    
    (pretty-print (map get-name-normalized
                       (send (send (car receipt-list) get-receipt-identifier #t) get-issuer)))
    (printf "encryption alg : \n")
    (pretty-print (send (car receipt-list) get-key-encrypt-algorithm))
    (printf "encrypted key : \n")
    (pretty-print (send (car receipt-list) get-encrypted-key #t))
   
    )
          
  )
;;(test-Bytes->ASN1 "data/cms-envelop-ext.pkcs7")
(displayln "=============================================================")
(map (find-value-element-proc 'attrValues)
     (car (map  (find-value-element-proc 'signedAttrs)
                ((find-value-element-proc 'content 'signerInfos)
                 (test-Bytes->ASN1 "data/cms-sig-ext.pkcs7")))))
(displayln "=============================================================")
((find-value-element-proc 'content 'signerInfos)
 (test-Bytes->ASN1 "data/cms-sig-ext.pkcs7"))
;;(test-Bytes->ASN1 "data/cms-encrypt-ext.pkcs7")


