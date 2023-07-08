;; Copyright 2023-2025 Harald Glab-Plhak
;;
;; This library is free software: you can redistribute it and/or modify
;; it under the terms of the GNU Lesser General Public License as published
;; by the Free Software Foundation either version 3 of the License or
;; (at your option) any later version.
;; 
;; This library is distributed in the hope that it will be useful
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU Lesser General Public License for more details.
;; 
;; You should have received a copy of the GNU Lesser General Public License
;; along with this library.  If not see <http://www.gnu.org/licenses/>.

;; Used Code of C. K. Young as base
;;https://stackoverflow.com/questions/24093199/a-pure-scheme-implementation-r5rs-of-sha256
;; changed code to our needs based on NIST papers for sha

#lang racket/base
(require racket/list
  (only-in srfi/1 iota)
         (only-in srfi/60 rotate-bit-field)
          (only-in srfi/26 cut)
         (only-in srfi/43 vector-unfold)
         binaryio/integer
         rnrs/arithmetic/bitwise-6
         "basic-sig-utils.rkt"
         )
         
(provide (all-defined-out))
;; the table of primes to calculate
(define primes80 '(2 3 5 7 11 13 17 19 23 29 31 37 41 43 47 53 59 61 67 71 73
                   79 83 89 97 101 103 107 109 113 127 131 137 139 149 151 157
                   163 167 173 179 181 191 193 197 199 211 223 227 229 233 239
                   241 251 257 263 269 271 277 281 283 293 307 311 313 317 331
                   337 347 349 353 359 367 373 379 383 389 397 401 409))


;;; The init of the sha tables ... out of the primes

(define sha1-init '(#x67452301 #xefcdab89 #x98badcfe #x10325476 #xc3d2e1f0))
(define sha2-init (map (lambda (x) (frac (sqrt x) 64 64)) (take primes80 16)))
(define-values (sha512-init sha384-init) (split-at sha2-init 8))
(define sha256-init (map (cut arithmetic-shift <> -32) sha512-init))
(define sha224-init (map (cut frac <> 0 32) sha384-init))

(define sha1-const (map (lambda (x) (frac (sqrt x) 30 32)) '(2 3 5 10)))
(define sha512-const (map (lambda (x) (frac (cbrt x) 64 64)) primes80))
(define sha256-const (map (cut arithmetic-shift <> -32) (take sha512-const 64)))


;;; The compression functions.
(define (sha2-compress K Sum0 Sum1 fun0 fun1 mod+ getter hs)
  (define W (vector->list (apply vector-unfold
                                 (lambda (_ a b c d e f g h i j k l m n o p)
                                   (values a b c d e f g h i j k l m n o p
                                           (mod+ a (fun0 b) j (fun1 o))))
                                 (length K)
                                 (build-list 16 getter))))
  (define (loop k w a b c d e f g h)
    (if (null? k)
        (map mod+ hs (list a b c d e f g h))
        (let ((T1 (mod+ h (Sum1 e) (bitwise-if e f g) (car k) (car w)))
              (T2 (mod+ (Sum0 a) (bitwise-majority a b c))))
          (loop (cdr k) (cdr w) (mod+ T1 T2) a b c (mod+ d T1) e f g))))
  (apply loop K W hs))



(define (sha512-compress bv hs)  
  (define (shr x y) (arithmetic-shift x (- y)))
  (define (rotr64 x y) (rotr x y 64))
  (sha2-compress sha512-const
                 (lambda (x) (bitwise-xor (rotr64 x 28) (rotr64 x 34) (rotr64 x 39)))
                 (lambda (x) (bitwise-xor (rotr64 x 14) (rotr64 x 18) (rotr64 x 41)))
                 (lambda (x) (bitwise-xor (rotr64 x 1) (rotr64 x 8) (shr x 7)))
                 (lambda (x) (bitwise-xor (rotr64 x 19) (rotr64 x 61) (shr x 6)))
                 u64+ (cut bytevector-u64-ref bv <>) hs))

(define (sha256-compress bv hs)
  (define (rotr32 x y) (rotr x y 32))  
  (define (shr x y) (arithmetic-shift x (- y)))
  (sha2-compress sha256-const
                 (lambda (x) (bitwise-xor (rotr32 x 2) (rotr32 x 13) (rotr32 x 22)))
                 (lambda (x) (bitwise-xor (rotr32 x 6) (rotr32 x 11) (rotr32 x 25)))
                 (lambda (x) (bitwise-xor (rotr32 x 7) (rotr32 x 18) (shr x 3)))
                 (lambda (x) (bitwise-xor (rotr32 x 17) (rotr32 x 19) (shr x 10)))
                 u32+ (cut bytevector-u32-ref bv <>) hs))

(define (sha1-compress bv hs)
  (define (getter x) (bytevector-u32-ref bv x))
  (define (rotl32 x y) (rotl x y 0 32))
  (define W (vector->list (apply vector-unfold
                                 (lambda (_ a b c d e f g h i j k l m n o p)
                                   (values a b c d e f g h i j k l m n o p
                                           (rotl32 (bitwise-xor a c i n) 1)))
                                 80
                                 (build-list 16 getter))))
  (define (outer f k w a b c d e)
    (if (null? k)
        (map u32+ hs (list a b c d e))
        (let inner ((i 0) (w w) (a a) (b b) (c c) (d d) (e e))
          (if (< i 20)
              (let ((T (u32+ (rotl32 a 5) ((car f) b c d) e (car k) (car w))))
                (inner (+ i 1) (cdr w) T a (rotl32 b 30) c d))
              (outer (cdr f) (cdr k) w a b c d e)))))
  (apply outer (list bitwise-if bitwise-xor bitwise-majority bitwise-xor)
               sha1-const W hs))





(define (md-pad! bv offset count counter-size)
  (define block-size (bytes-length bv))
  (unless (negative? offset)
    (bytes-set! bv offset #x80))
  (let loop ((i (+ offset 1)))
    (when (< i block-size)
      (bytes-set! bv i 0)
      (loop (+ i 1))))
  (when count
    (bytevector-be-set! bv (- block-size counter-size) counter-size
                        (arithmetic-shift count 3))))

(define (hash-state->bytevector hs trunc word-size)
  (define result (make-bytes (* trunc word-size)))
  (for-each (lambda (h i)
              (bytevector-be-set! result i word-size h))
            hs (iota trunc 0 word-size))
  result)


;;; The Merkle-Damgård "driver" function.

(define (md-loop init compress block-size trunc word-size counter-size in)
  (define leftover (- block-size counter-size))
  (define bv (make-bytes block-size))
  (define pad! (cut md-pad! bv <> <> counter-size))
  (define hs->bv (cut hash-state->bytevector <> trunc word-size))

  (let loop ((count 0) (hs init))
    (define read-size (read-bytes! bv in))
    (cond ((eof-object? read-size)
           (pad! 0 count)
           (hs->bv (compress bv hs)))
          ((= read-size block-size)
           (loop (+ count read-size) (compress bv hs)))
          ((< read-size leftover)
           (pad! read-size (+ count read-size))
           (hs->bv (compress bv hs)))
          (else
           (pad! read-size #f)
           (let ((pen (compress bv hs)))
             (pad! -1 (+ count read-size))
             (hs->bv (compress bv pen)))))))



;; init functions

;;; SHA-512/t stuff.

(define sha512/t-init (map (cut bitwise-xor <> #xa5a5a5a5a5a5a5a5) sha512-init))
(define (make-sha512/t-init t)
  (define key (string->bytes/utf-8 (string-append "SHA-512/" (number->string t))))
  (define size (bytes-length key))
  (define bv (make-bytes 128))
  (subbytes bv 0 key)
  (md-pad! bv size size 16)
  (sha512-compress bv sha512/t-init))

(define (make-sha512/t t)
  (define init (make-sha512/t-init t))
  (define words (arithmetic-shift t -6))
  (if (zero? (bitwise-and t 63))
      (cut md-loop init sha512-compress 128 words 8 16 <>)
      (lambda (in)
        (subbytes
         (md-loop init sha512-compress 128 (ceiling words) 8 16 in)
         0 (arithmetic-shift t -3)))))
