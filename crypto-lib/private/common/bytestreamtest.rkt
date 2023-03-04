#lang racket/base
(require racket/class
         "bytestreaming.rkt")

(let ([stream (new  bytes-stream%)])
  (send stream write-bytes (string->bytes/latin-1 "1234567890erdeistgrün "))
  (send stream write-bytes (string->bytes/latin-1 "add-on-bytes "))
  (send stream write-bytes (string->bytes/latin-1 "ABCDEFGHI"))
  (let reader ([bytes-read (send stream read-range 5)])
    (cond [(equal? (bytes-length bytes-read) 0) #f]
          [else (printf "bytes streamed: ~a\n" bytes-read) (reader (send stream read-range 5))]))
  (send stream reset)            
  (printf "bytes read: ~a\n"(send stream read-range 5))
  (printf "bytes read: ~a\n"(send stream read-range 5))
  (printf "bytes read: ~a\n"(send stream read-range 5))
  (printf "bytes read: ~a\n"(send stream read-range 5))
  (printf "bytes read: ~a\n"(send stream read-range 5))
  (printf "bytes read: ~a\n"(send stream read-range 5))
  (printf "bytes read: ~a\n"(send stream read-range 5))
  (printf "bytes read: ~a\n"(send stream read-range 5))
  (printf "bytes read: ~a\n"(send stream read-range 5))
  (send stream reset)
  (copy-stream (lambda (input)
                 (let ([buffer (send input read-range 5)])
                   (cond [(equal? (bytes-length buffer) 0) #f]
                         [else (list (bytes-length buffer) buffer)])))
               stream
               (lambda (buff-len buffer)
                 (printf "length: ~a --> read step: ~a \n" buff-len buffer)))
                            
                                
  (printf "bytes of buffer: ~a\n"(send stream get-bytes)))
  
