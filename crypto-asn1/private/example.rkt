#lang racket/base
(require 
  "cmssig-asn1.rkt"
         "asn1-to-classes.rkt"
         asn1        
         racket/class
         racket/pretty
         binaryio/reader
         rnrs/io/ports-6)



(define read-bytes-from-file
  (lambda (fname)
    (let*([port (open-file-input-port fname)]
          [reader (make-binary-reader port)]
          {file-size (file-size fname)}
          )
      (b-read-bytes reader file-size)
      )))
(define test-Bytes->ASN1(lambda (fname)
                          (let ([bytes (read-bytes-from-file fname)])
                            (bytes->asn1 ContentInfo bytes))))


(displayln id-cms-enveloped-data)
(displayln id-cms-signed-data)


(let* ([bytes (read-bytes-from-file  "data/cms-sig-ext.pkcs7")]
       [signed-data (new signed-data% (der bytes))]
       [sig-info-list (send signed-data get-signer-infos)])  
  (displayln sig-info-list)
  (printf " validy : ~a\n" (map get-cert-validity (send signed-data get-certificate-set)))
  (printf "signed attributes :\n")
  (pretty-print (map get-auth-attr sig-info-list))
  (printf "issuer and serial :\n")
  (pretty-print (map get-serial-number (map get-issuer-and-serial sig-info-list)))
  (printf "issuer  :\n")
  (pretty-print (map get-issuer (map get-issuer-and-serial sig-info-list)))
  (printf "issuer attributes :\n")
  (pretty-print (map get-name-attributes
                     (map get-issuer (map get-issuer-and-serial sig-info-list))))
  (printf "issuer -attr field :\n")
  (pretty-print (map (attribute-value->string id-at-commonName)
                     (map get-issuer (map get-issuer-and-serial sig-info-list))))
  (printf "normalized issuer: \n")
  (pretty-print (map get-name-normalized
                     (map get-issuer (map get-issuer-and-serial sig-info-list))))
          
  (map get-unauth-attr sig-info-list))



;;(map (find-value-element-proc 'attrValues) (car (map  (find-value-element-proc 'signedAttrs)
;;     ((find-value-element-proc 'content 'signerInfos)
;;      (test-Bytes->ASN1 "data/cms-sig-ext.pkcs7")))))
;;(displayln "=============================================================")
;;(test-Bytes->ASN1 "data/cms-envelop-ext.pkcs7")
;;(displayln "=============================================================")
;;(test-Bytes->ASN1 "data/cms-encrypt-ext.pkcs7")


