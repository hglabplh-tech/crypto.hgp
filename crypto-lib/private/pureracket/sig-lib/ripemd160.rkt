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

#lang racket/base
(require (only-in srfi/1 iota)
         (only-in srfi/60 rotate-bit-field)
         binaryio/integer
         rnrs/arithmetic/bitwise-6
         "basic-sig-utils.rkt"         
         )

(provide (all-defined-out))

;=======================================================================
;; The following code is ported from a python library written in C --
;; https://github.com/Legrandin/pycryptodome.git
;=======================================================================

;;/* Ordering of message words.  Based on the permutations rho(i) and pi(i), defined as follows:
;; *
;; *  rho(i) := { 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8 }[i]  0 <= i <= 15
;; *
;; *  pi(i) := 9*i + 5 (mod 16)
;; *
;; *  Line  |  Round 1  |  Round 2  |  Round 3  |  Round 4  |  Round 5
;; * -------+-----------+-----------+-----------+-----------+-----------
;; *  left  |    id     |    rho    |   rho^2   |   rho^3   |   rho^4
;; *  right |    pi     |   rho pi  |  rho^2 pi |  rho^3 pi |  rho^4 pi
;; */

(define RL
  (relation
   #:heading
   ['index                         'numbers]
   #:tuples
   [0 (list->bytes '(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 ))]  ;; /* Round 1: id */
   [1 (list->bytes '(7 4 13 1 10 6 15 3 12 0 9 5 2 14 11 8 ))]  ;; /* Round 2: rho */
   [2 (list->bytes '(3 10 14 4 9 15 8 1 2 7 0 6 13 11 5 12 ))]  ;; /* Round 3: rho^2 */
   [3 (list->bytes '(1 9 11 10 0 8 12 4 13 3 7 15 14 5 6 2 ))]  ;; /* Round 4: rho^3 */
   [4 (list->bytes '(4 0 5 9 7 12 2 10 14 1 3 8 11 6 15 13 ))]  ;; /* Round 5: rho^4
   ))

(define (RL-ref index)
  (relation-ref RL 'index index 'numbers))

(define RR
  (relation
   #:heading
   ['index                         'numbers]
   #:tuples
   [0 (list->bytes '( 5 14 7 0 9 2 11 4 13 6 15 8 1 10 3 12 ))]   ;;/* Round 1: pi */
   [1 (list->bytes '( 6 11 3 7 0 13 5 10 14 15 8 12 4 9 1 2 ))]   ;;/* Round 2: rho pi */
   [2 (list->bytes '( 15 5 1 3 7 14 6 9 11 8 12 2 10 0 4 13 ))]   ;;/* Round 3: rho^2 pi */
   [3 (list->bytes '( 8 6 4 1 3 11 15 0 5 12 2 13 9 7 10 14 ))]   ;;/* Round 4: rho^3 pi */
   [4 (list->bytes '( 12 15 10 4 1 5 8 7 6 2 13 14 0 3 9 11 ))]   ;;/* Round 5: rho^4 pi */
   ))

(define (RR-ref index)
  (relation-ref RR 'index index 'numbers))

;;/*
;; * Shifts - Since we don't actually re-order the message words according to
;; * the permutations above (we could, but it would be slower), these tables
;; * come with the permutations pre-applied.
;; */

(define SL
  (relation
   #:heading
   ['index                         'numbers]
   #:tuples
   [0 (list->bytes '( 11 14 15 12 5 8 7 9 11 13 14 15 6 7 9 8))] ;;/* Round 1 */
   [1 (list->bytes '( 7 6 8 13 11 9 7 15 7 12 15 9 11 7 13 12))] ;;/* Round 2 */
   [2 (list->bytes '( 11 13 6 7 14 9 13 15 14 8 13 6 5 12 7 5))] ;;/* Round 3 */
   [3 (list->bytes '( 11 12 14 15 14 15 9 8 9 14 5 6 8 6 5 12))] ;;/* Round 4 */
   [4 (list->bytes '( 9 15 5 11 6 8 13 12 5 12 13 14 11 8 5 6))] ;;/* Round 5 */
   ))

(define (SL-ref index)
  (relation-ref SL 'index index 'numbers))

(define SR
  (relation
   #:heading
   ['index                         'numbers]
   #:tuples
   [0 (list->bytes '( 8 9 9 11 13 15 15 5 7 7 8 11 14 14 12 6))] ;;/* Round 1 */
   [1 (list->bytes '( 9 13 15 7 12 8 9 11 7 7 12 7 6 15 13 11))] ;;/* Round 2 */
   [2 (list->bytes '( 9 7 15 11 8 6 6 14 12 13 5 14 13 13 7 5))] ;;/* Round 3 */
   [3 (list->bytes '( 15 5 8 11 14 14 6 14 6 9 12 9 12 5 15 8))] ;;/* Round 4 */
   [4 (list->bytes '( 8 5 12 9 12 5 14 6 8 13 6 5 15 13 11 11))] ;;/* Round 5 */
   ))

(define (SR-ref index)
  (relation-ref SR 'index index 'numbers))

;;/* Boolean functions */

;;#define F1(x, y, z) ((x) ^ (y) ^ (z))

(define (bool-f1 x y z)
  (bitwise-xor x y z))

;;#define F2(x, y, z) (((x) & (y)) | (~(x) & (z)))

(define (bool-f2 x y z)
  (bitwise-ior (bitwise-and x y) (bitwise-and (bitwise-not x) z)))

;;#define F3(x, y, z) (((x) | ~(y)) ^ (z))

(define (bool-f3 x y z)
  (bitwise-xor (bitwise-ior x (bitwise-not y)) z))

;;#define F4(x, y, z) (((x) & (z)) | ((y) & ~(z)))

(define (bool-f4 x y z)
  (bitwise-ior (bitwise-and x z) (bitwise-and y (bitwise-not z))))

;;#define F5(x, y, z) ((x) ^ ((y) | ~(z)))

(define (bool-f5 x y z)
  (bitwise-xor x (bitwise-ior y (bitwise-not z))))


;;/* Round constants, left line */
(define KL
  (relation
   #:heading
   ['index                         'constant]
   #:tuples
   [0 #x00000000]    ;;/* Round 1: 0 */
   [1 #x5A827999]    ;;/* Round 2: floor(2**30 * sqrt(2)) */
   [2 #x6ED9EBA1]    ;;/* Round 3: floor(2**30 * sqrt(3)) */
   [3 #x8F1BBCDC]    ;;/* Round 4: floor(2**30 * sqrt(5)) */
   [4 #xA953FD4E]    ;;/* Round 5: floor(2**30 * sqrt(7)) */
   ))

(define (KL-ref index)
  (relation-ref KL 'index index 'constant))

;;/* Round constants, right line */
(define KR
  (relation
   #:heading
   ['index                         'constant]
   #:tuples
   [0 #x50A28BE6]    ;;/* Round 1: floor(2**30 * cubert(2)) */
   [1 #x5C4DD124]    ;;/* Round 2: floor(2**30 * cubert(3)) */
   [2 #x6D703EF3]    ;;/* Round 3: floor(2**30 * cubert(5)) */
   [3 #x7A6D76E9]    ;;/* Round 4: floor(2**30 * cubert(7)) */
   [4 #x00000000]    ;;/* Round 5: 0 */
   ))

(define (KR-ref index)
  (relation-ref KR 'index index 'constant))

(define T (box 0))

(define(make-regs-left al bl cl dl el)
  (make-hasheq 
   (cons 'AL  al) (cons 'BL bl) (cons 'CL cl) (cons 'DL dl) (cons 'EL el)))

(define (make-regs-right  ar br cr dr er)
  (make-hasheq 
   (cons 'AR  ar) (cons 'BR br) (cons 'CR cr) (cons 'DR dr) (cons 'ER er)))

(define (assign-reg-to-reg regs s t)  
    (hash-set regs t (hash-ref regs s #f)))

(define (rel-bytes-ref rel-ref index byte-ind)
  (let ([byte-vect (rel-ref index)])
    (bytes-ref byte-vect byte-ind)))

