#lang racket/base
(require "cmssig-asn1.rkt"
         asn1
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
(define test(lambda (fname)
              (let ([bytes (read-bytes-from-file fname)])
                (bytes->asn1 ContentInfo bytes))))


(displayln id-cms-auth-enveloped-data)
(test "data/cms-sig-ext.pkcs7")