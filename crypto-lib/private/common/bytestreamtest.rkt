#lang racket/base
(require racket/class
         "bytestreaming.rkt")

(let ([stream (new  bytes-stream%)])
  (send stream write-bytes (string->bytes/utf-8 "1234567890erdeistgrün: "))
  (send stream write-bytes (string->bytes/utf-8 "add-on-bytes: "))
  (send stream write-bytes (string->bytes/utf-8 "->ABCDEFGHI"))
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
  (printf "bytes read: ~a\n"(send stream read-range 5))
  (send stream reset)
  (copy-stream-by-funs (lambda (input)
                 (let ([buffer (send input read-range 5)])
                   (cond [(equal? (bytes-length buffer) 0) #f]
                         [else (list buffer (bytes-length buffer))])))
               stream
               (lambda (buffer buff-len target)
                 (printf "length: ~a --> read step: ~a \n" buff-len buffer))

               #t
               (lambda(source target)
                 (printf "bytes of read buffer : ~a\n"(send source get-bytes))
                 (printf "value of target: ~a \n" target)))
                            
                                
  (printf "bytes of buffer: ~a\n"(send stream get-bytes)))
  
