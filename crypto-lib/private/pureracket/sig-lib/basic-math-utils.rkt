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
         )
         
(provide (all-defined-out))


(define (sqrt x)
  (foldl (lambda (_ y) (/ (+ (/ x y) y) 2)) 4 (iota 7)))

(define (cbrt x)
  (foldl (lambda (_ y) (/ (+ (/ x y y) y y) 3)) 4 (iota 8)))

(define (frac x scale base)
  (bitwise-and (floor (* x (arithmetic-shift 1 scale)))
               (- (arithmetic-shift 1 base) 1)))

(define (rotr bit-field y word-len) (rotate-bit-field bit-field (- y) 0 word-len))

(define (rotl bit-field y word-len) (rotate-bit-field bit-field y 0 word-len))

(define (shr x y) (arithmetic-shift x (- y)))

(define (u32+ . xs) (bitwise-and (apply + xs) #xffffffff))

(define (u64+ . xs) (bitwise-and (apply + xs) #xffffffffffffffff))

(define (bitwise-majority x y z)
  (bitwise-xor (bitwise-and x y) (bitwise-and x z) (bitwise-and y z)))

(define (bytevector-be-ref bv base n)
  (let loop ((res 0) (i 0))
    (if (< i n)
        (loop (+ (arithmetic-shift res 8) (bytes-ref bv (+ base i)))
              (+ i 1))
        res)))

(define (bytevector-u64-ref bv i)
  (bytevector-be-ref bv (arithmetic-shift i 3) 8))
(define (bytevector-u32-ref bv i)
  (bytevector-be-ref bv (arithmetic-shift i 2) 4))

(define (bytevector-be-set! bv base n val)
  (let loop ((i n) (val val))
    (when (positive? i)
      (bytes-set! bv (+ base i -1) (bitwise-and val 255))
      (loop (- i 1) (arithmetic-shift val -8)))))

(define (<< value shift)
  (bitwise-arithmetic-shift-left value shift))

(define (>> value shift)
  (bitwise-arithmetic-shift-right value shift))

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
                            (<< (bytes-ref the-bytes 7)))]))

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


;; do this again no blessing thought wrong
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
   

(sqrt 4)
(cbrt 27)
(shr 16 3)
(rotr 2048 3 32)
(rotl 2048 3 32)
(frac 450 1 32)
(bitwise-majority 6 9 10)
(u32+ 32 33 45 1234567890 33331234567890)
(u64+ 32 33 45 1234567890 33331234567890)
(bitwise-majority 15 9 10)
(bytes->64-big (integer->bytes 71 8 #f))
(bytes->64-little (integer->bytes 71 8 #f))
(bytes->64-force-big (integer->bytes 71 8 #f))
(bytes->64-force-little (integer->bytes 71 8 #f))
(bytes->64-little (64->bytes-big 899))
(bytes->64-big (64->bytes-little 899))
(bytes->64-little (64->bytes-little 899))
(bytes->64-big (64->bytes-big 899))