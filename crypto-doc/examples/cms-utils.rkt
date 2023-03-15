#lang racket/base
;; read a binary file with racket

(require  binaryio/reader)
(provide (all-defined-out))

(define read-bytes-from-file
  (lambda (fname)
    (let*([port (open-input-file fname #:mode 'binary )]
          [reader (make-binary-reader port)]
          [file-size (file-size fname)])
      (let ([buffer (b-read-bytes reader file-size)])
        (close-input-port port)
        buffer)
      )))

;; write a binary file with racket
(define write-bytes-to-file
  (lambda (fname buffer)
    (let*([port (open-output-file fname #:mode 'binary #:exists 'replace)]
          [length (bytes-length buffer)])
      (begin
        (write-bytes-avail buffer port 0 length)
        (close-output-port port))
      )))
