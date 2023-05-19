;; Copyright 2023-2025 Harald Glab-Plhak
;;
;; This library is free software: you can redistribute it and/or modify
;; it under the terms of the GNU Lesser General Public License as published
;; by the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.
;; 
;; This library is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU Lesser General Public License for more details.
;; 
;; You should have received a copy of the GNU Lesser General Public License
;; along with this library.  If not, see <http://www.gnu.org/licenses/>.

#lang racket/base
(require (only-in srfi/1 iota)
         (only-in srfi/60 rotate-bit-field)
         binaryio/integer
         rnrs/arithmetic/bitwise-6
         "basic-sig-utils.rkt"         
         )

(provide (all-defined-out))

;; 64 Bit endian definitions
;;========================================
(define (bytes->64-big the-bytes)
  (cond [(system-big-endian?)
         (bytes->integer the-bytes	 	 	 	 
                         #f 	 	 	 
                         (system-big-endian?)	 	 	 	 
                         0	 	 	 
                         (bytes-length the-bytes))]
        [else  (bitwise-ior #x0000000000000000 (<< (bytes-ref the-bytes 0) 56)
                            (<< (bytes-ref the-bytes 1) 48)
                            (<< (bytes-ref the-bytes 2) 40)
                            (<< (bytes-ref the-bytes 3) 32)
                            (<< (bytes-ref the-bytes 4) 24)
                            (<< (bytes-ref the-bytes 5) 16)
                            (<< (bytes-ref the-bytes 6) 8)
                            (bytes-ref the-bytes 7))]))

(define (bytes->64-little the-bytes)
  (cond [(not (system-big-endian?))
         (bytes->integer the-bytes	 	 	 	 
                         #f 	 	 	 
                         (not (system-big-endian?))	 	 	 	 
                         0	 	 	 
                         (bytes-length the-bytes))]
        [else  (bitwise-ior #x0000000000000000 (bytes-ref the-bytes 0)
                            (<< (bytes-ref the-bytes 1) 8)
                            (<< (bytes-ref the-bytes 2) 16)
                            (<< (bytes-ref the-bytes 3) 24)
                            (<< (bytes-ref the-bytes 4) 32)
                            (<< (bytes-ref the-bytes 5) 40)
                            (<< (bytes-ref the-bytes 6) 48)
                            (<< (bytes-ref the-bytes 7) 56))]))

(define (bytes->64-force-big the-bytes)  
  (bitwise-ior #x0000000000000000 (<< (bytes-ref the-bytes 0) 56)
               (<< (bytes-ref the-bytes 1) 48)
               (<< (bytes-ref the-bytes 2) 40)
               (<< (bytes-ref the-bytes 3) 32)
               (<< (bytes-ref the-bytes 4) 24)
               (<< (bytes-ref the-bytes 5) 16)
               (<< (bytes-ref the-bytes 6) 8)
               (bytes-ref the-bytes 7)))

(define (bytes->64-force-little the-bytes)
  (bitwise-ior #x0000000000000000 (bytes-ref the-bytes 0)
               (<< (bytes-ref the-bytes 1) 8)
               (<< (bytes-ref the-bytes 2) 16)
               (<< (bytes-ref the-bytes 3) 24)
               (<< (bytes-ref the-bytes 4) 32)
               (<< (bytes-ref the-bytes 5) 40)
               (<< (bytes-ref the-bytes 6) 48)
               (<< (bytes-ref the-bytes 7) 56)))

(define (64->bytes-little integer)  
  (cond [(not (system-big-endian?))           
        (integer->bytes integer 8 #f)]
        [else (let ([p (make-bytes 8 0)])
                (bytes-set! p 0 (bitwise-and integer #x00000000000000FF))
                (bytes-set! p 1 (bitwise-and (>> integer 8)#x00000000000000FF))
                (bytes-set! p 2 (bitwise-and (>> integer 16)#x00000000000000FF))
                (bytes-set! p 3 (bitwise-and (>> integer 24)#x00000000000000FF))
                (bytes-set! p 4 (bitwise-and (>> integer 32)#x00000000000000FF))
                (bytes-set! p 5 (bitwise-and (>> integer 40)#x00000000000000FF))
                (bytes-set! p 6 (bitwise-and (>> integer 48)#x00000000000000FF))
                (bytes-set! p 7 (bitwise-and (>> integer 56)#x00000000000000FF))
                p)]))

(define (64->bytes-big integer)  
    (cond [(system-big-endian?)           
            (integer->bytes integer 8 #f)]
          [else (let ([p (make-bytes 8 0)])
                (bytes-set! p 0 (bitwise-and (>> integer 56) #x00000000000000FF))
                (bytes-set! p 1 (bitwise-and (>> integer 48)#x00000000000000FF))
                (bytes-set! p 2 (bitwise-and (>> integer 40)#x00000000000000FF))
                (bytes-set! p 3 (bitwise-and (>> integer 32)#x00000000000000FF))
                (bytes-set! p 4 (bitwise-and (>> integer 24)#x00000000000000FF))
                (bytes-set! p 5 (bitwise-and (>> integer 16)#x00000000000000FF))
                (bytes-set! p 6 (bitwise-and (>> integer 8)#x00000000000000FF))
                (bytes-set! p 7 (bitwise-and integer #x00000000000000FF))
                p)]))


;; 32 Bit endian definitions
;;========================================
(define (bytes->32-big the-bytes)
  (cond [(system-big-endian?)
         (bytes->integer the-bytes	 	 	 	 
                         #f 	 	 	 
                         (system-big-endian?)	 	 	 	 
                         0	 	 	 
                         (bytes-length the-bytes))]
        [else  (bitwise-ior #x00000000                           
                            (<< (bytes-ref the-bytes 0) 24)
                            (<< (bytes-ref the-bytes 1) 16)
                            (<< (bytes-ref the-bytes 2) 8)
                            (bytes-ref the-bytes 3))]))

(define (bytes->32-little the-bytes)
  (cond [(not (system-big-endian?))
         (bytes->integer the-bytes	 	 	 	 
                         #f 	 	 	 
                         (not (system-big-endian?))	 	 	 	 
                         0	 	 	 
                         (bytes-length the-bytes))]
        [else  (bitwise-ior #x00000000 (bytes-ref the-bytes 0)
                            (<< (bytes-ref the-bytes 1) 8)
                            (<< (bytes-ref the-bytes 2) 16)
                            (<< (bytes-ref the-bytes 3) 24))
                            ]))

(define (bytes->32-force-big the-bytes)  
  (bitwise-ior #x00000000               
               (<< (bytes-ref the-bytes 0) 24)
               (<< (bytes-ref the-bytes 1) 16)
               (<< (bytes-ref the-bytes 2) 8)
               (bytes-ref the-bytes 3)))

(define (bytes->32-force-little the-bytes)
  (bitwise-ior #x00000000 (bytes-ref the-bytes 0)
               (<< (bytes-ref the-bytes 1) 8)
               (<< (bytes-ref the-bytes 2) 16)
               (<< (bytes-ref the-bytes 3) 24)))

(define (32->bytes-little integer)  
  (cond [(not (system-big-endian?))           
        (integer->bytes integer 4 #f)]
        [else (let ([p (make-bytes 4 0)])
                (bytes-set! p 0 (bitwise-and integer         #x000000FF))
                (bytes-set! p 1 (bitwise-and (>> integer 8)  #x000000FF))
                (bytes-set! p 2 (bitwise-and (>> integer 16) #x000000FF))
                (bytes-set! p 3 (bitwise-and (>> integer 24) #x000000FF))                
                p)]))

(define (32->bytes-big integer)  
    (cond [(system-big-endian?)           
            (integer->bytes integer 4 #f)]
          [else (let ([p (make-bytes 4 0)])                
                (bytes-set! p 0 (bitwise-and (>> integer 24) #x000000FF))
                (bytes-set! p 1 (bitwise-and (>> integer 16) #x000000FF))
                (bytes-set! p 2 (bitwise-and (>> integer 8)  #x000000FF))
                (bytes-set! p 3 (bitwise-and integer         #x000000FF))
                p)]))

;; bytes 64 fast checks delete later
(bytes->64-big (integer->bytes 71 8 #f))
(bytes->64-little (integer->bytes 71 8 #f))
(bytes->64-force-big (integer->bytes 71 8 #f))
(bytes->64-force-little (integer->bytes 71 8 #f))
(bytes->64-little (64->bytes-big 8990000000011))
(bytes->64-big (64->bytes-little 8990000000011))
(bytes->64-little (64->bytes-little 8990000000011))
(bytes->64-big (64->bytes-big 899123456789123))
;; bytes 32 check delete them later
(bytes->32-big (integer->bytes 71 4 #f))
(bytes->32-little (integer->bytes 71 4 #f))
(bytes->32-force-big (integer->bytes 71 4 #f))
(bytes->32-force-little (integer->bytes 71 4 #f))
(bytes->32-little (32->bytes-big 89900011))
(bytes->32-big (32->bytes-little 89900011))
(bytes->32-little (32->bytes-little 89900011))
(bytes->32-big (32->bytes-big 89900011))
   