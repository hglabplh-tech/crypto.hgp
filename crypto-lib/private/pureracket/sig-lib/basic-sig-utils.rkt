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

(struct rel (heading tuples) #:transparent)
(define (relation* heading tuples)
  (define nfields (vector-length heading))
  (for ([tuple (in-vector tuples)])
    (unless (= (vector-length tuple) nfields)
      (error 'relation "wrong number of fields\n  expected: ~s fields\n  tuple: ~e"
             nfields tuple)))
  (rel heading tuples))
(define-syntax-rule (relation #:heading [field ...] #:tuples [value ...] ...)
  (relation* (vector field ...) (vector (vector value ...) ...)))

(define (relation-field-index rel keyfield #:who [who 'relation-field-index])
  (or (for/first ([field (in-vector (rel-heading rel))]
                  [index (in-naturals)]
                  #:when (equal? field keyfield))
        index)
      (error who "field not found in relation\n  field: ~e\n  heading: ~e"
             keyfield (rel-heading rel))))

(define (relation-find rel keyfield key #:who [who 'relation-find])
  (define keyindex (relation-field-index rel keyfield #:who who))
  (for/first ([tuple (in-vector (rel-tuples rel))]
              #:when (equal? (vector-ref tuple keyindex) key))
    tuple))

(define (relation-ref rel keyfield key wantfield #:who [who 'relation-ref])
  (cond [(relation-find rel keyfield key #:who who)
         => (lambda (tuple)
              (vector-ref tuple (relation-field-index rel wantfield #:who who)))]
        [else #f]))

(define (relation-ref* rel keyfield key wantfields #:who [who 'relation-ref])
  (cond [(relation-find rel keyfield key #:who who)
         => (lambda (tuple)
              (map (lambda (wantfield)
                     (vector-ref tuple (relation-field-index rel wantfield #:who who)))
                   wantfields))]
        [else #f]))

(define (relation-column rel keyfield #:who [who 'relation-column])
  (define keyindex (relation-field-index rel keyfield #:who who))
  (for/vector ([tuple (in-vector (rel-tuples rel))])
    (vector-ref tuple keyindex)))



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


;; utils check delete them later
(sqrt 4)
(cbrt 27)
(shr 16 3)
(rotr 2048 3 32)
(rotl 2048 3 32)
(frac 450 1 32)
(bitwise-majority 6 9 10)
(u32+ 78)
(u32+ 32 33 45 1234567890 33331234567890)
(u64+ 32 33 45 1234567890 33331234567890)
(bitwise-majority 15 9 10)
