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
         "endianess.rkt"
         "md-ctx.rkt"
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
   [0  '(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 )]  ;; /* Round 1: id */
   [1  '(7 4 13 1 10 6 15 3 12 0 9 5 2 14 11 8 )]  ;; /* Round 2: rho */
   [2  '(3 10 14 4 9 15 8 1 2 7 0 6 13 11 5 12 )]  ;; /* Round 3: rho^2 */
   [3  '(1 9 11 10 0 8 12 4 13 3 7 15 14 5 6 2 )]  ;; /* Round 4: rho^3 */
   [4  '(4 0 5 9 7 12 2 10 14 1 3 8 11 6 15 13 )]  ;; /* Round 5: rho^4
   ))

(define (RL-ref index)
  (relation-ref RL 'index index 'numbers))

(define RR
  (relation
   #:heading
   ['index                         'numbers]
   #:tuples
   [0  '( 5 14 7 0 9 2 11 4 13 6 15 8 1 10 3 12 )]   ;;/* Round 1: pi */
   [1  '( 6 11 3 7 0 13 5 10 14 15 8 12 4 9 1 2 )]   ;;/* Round 2: rho pi */
   [2  '( 15 5 1 3 7 14 6 9 11 8 12 2 10 0 4 13 )]   ;;/* Round 3: rho^2 pi */
   [3  '( 8 6 4 1 3 11 15 0 5 12 2 13 9 7 10 14 )]   ;;/* Round 4: rho^3 pi */
   [4  '( 12 15 10 4 1 5 8 7 6 2 13 14 0 3 9 11 )]   ;;/* Round 5: rho^4 pi */
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
   [0  '( 11 14 15 12 5 8 7 9 11 13 14 15 6 7 9 8)] ;;/* Round 1 */
   [1  '( 7 6 8 13 11 9 7 15 7 12 15 9 11 7 13 12)] ;;/* Round 2 */
   [2  '( 11 13 6 7 14 9 13 15 14 8 13 6 5 12 7 5)] ;;/* Round 3 */
   [3  '( 11 12 14 15 14 15 9 8 9 14 5 6 8 6 5 12)] ;;/* Round 4 */
   [4  '( 9 15 5 11 6 8 13 12 5 12 13 14 11 8 5 6)] ;;/* Round 5 */
   ))

(define (SL-ref index)
  (relation-ref SL 'index index 'numbers))

(define SR
  (relation
   #:heading
   ['index                         'numbers]
   #:tuples
   [0  '( 8 9 9 11 13 15 15 5 7 7 8 11 14 14 12 6)] ;;/* Round 1 */
   [1  '( 9 13 15 7 12 8 9 11 7 7 12 7 6 15 13 11)] ;;/* Round 2 */
   [2  '( 9 7 15 11 8 6 6 14 12 13 5 14 13 13 7 5)] ;;/* Round 3 */
   [3  '( 15 5 8 11 14 14 6 14 6 9 12 9 12 5 15 8)] ;;/* Round 4 */
   [4  '( 8 5 12 9 12 5 14 6 8 13 6 5 15 13 11 11)] ;;/* Round 5 */
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

(define(make-regs-left al bl cl dl el)
  (hasheq 
   'AL  al 'BL bl 'CL cl 'DL dl 'EL el))

(define (make-regs-right  ar br cr dr er)
  (make-hasheq 
   (list (cons 'AR  ar) (cons 'BR br) (cons 'CR cr) (cons 'DR dr) (cons 'ER er))))

(define (assign-reg-to-reg regs t s)  
  (hash-set regs t (hash-ref regs s #f)))

(define (set-reg regs sym val)
  (hash-set regs sym val))

(define (assign-regs regs reg-pairs-in)
  (let recur-regs ([reg-pairs reg-pairs-in]
                   [regs-out regs])
    (cond [(null? reg-pairs) regs-out]
          [else (let ([first-pair (car reg-pairs)])
                  (recur-regs
                   (cdr reg-pairs)
                   (assign-reg-to-reg regs-out (car first-pair) (cadr first-pair))))]))) 

(define (rel-list-ref rel-ref index list-index)
  (let ([list-of-int (rel-ref index)])
    (list-ref list-of-int list-index)))

(define regs-assign-left (list
                          (list 'AL 'EL)
                          (list 'EL 'DL)))

(define regs-assign-right (list
                           (list 'AR 'ER)
                           (list 'ER 'DR)))
(define (regs-ref regs register)
  (hash-ref regs register #f))

(define bool-funs-rel
  (relation
   #:heading
   ['index                         'fun-pair-lr]
   #:tuples
   [0 (list (list bool-f1 bool-f5))]    ;;/* Round 1*/
   [1 (list (list bool-f2 bool-f4))]    ;;/* Round 2:*/
   [2 (list (list bool-f3 bool-f3))]    ;;/* Round 3:*/
   [3 (list (list bool-f4 bool-f2))]    ;;/* Round 4:*/
   [4 (list (list bool-f5 bool-f1))]    ;;/* Round 5:*/
   ))

(define (bool-funs-ref index list-fun)
  (list-fun (relation-ref bool-funs-rel 'index index 'fun-pair-lr)))

(define (init-bufw hash-state)
  (let ([buffer (ripe-md-state-buffer hash-state)])
    (let fill-buf ([w 0]
                   [val-list null])
      (cond [(eq? w 16)
             (list->vector val-list)]
            [else (fill-buf
                   (add1 w)
                   (append val-list
                           (list
                            (bytes->32-little
                             (subbytes buffer (* w 4) (+ (* w 4) 4)))))
                   )])
      )))

(define (init-regs hash-state)
  (values
   (make-regs-left
    (vector-ref (ripe-md-state-hash hash-state) 0)
    (vector-ref (ripe-md-state-hash hash-state) 1)
    (vector-ref (ripe-md-state-hash hash-state) 2)
    (vector-ref (ripe-md-state-hash hash-state) 3)
    (vector-ref (ripe-md-state-hash hash-state) 4))
   (make-regs-right
    (vector-ref (ripe-md-state-hash hash-state) 0)
    (vector-ref (ripe-md-state-hash hash-state) 1)
    (vector-ref (ripe-md-state-hash hash-state) 2)
    (vector-ref (ripe-md-state-hash hash-state) 3)
    (vector-ref (ripe-md-state-hash hash-state) 4))))

(define (return-compress-state hash-state regs-left regs-right)
  (let* (
         [t (+ (vector-ref (ripe-md-state-hash hash-state) 1)
               (regs-ref regs-left 'CL) (regs-ref regs-right 'DR))]
         [hash-vect (list->vector (append (list t)
                                          (list (+ (vector-ref (ripe-md-state-hash hash-state) 2)
                                                   (regs-ref regs-left 'DL) (regs-ref regs-right 'ER)))
                                          (list (+ (vector-ref (ripe-md-state-hash hash-state) 3)
                                                   (regs-ref regs-left 'EL) (regs-ref regs-right 'AR)))
                                          (list (+ (vector-ref (ripe-md-state-hash hash-state) 4)
                                                   (regs-ref regs-left 'AL) (regs-ref regs-right 'BR)))
                                          (list (+ (vector-ref (ripe-md-state-hash hash-state) 0)
                                                   (regs-ref regs-left 'BL) (regs-ref regs-right 'CR)))))])
    (ripe-md-state hash-vect (ripe-md-state-length hash-state) (make-bytes 64 0) 0)
    ))



;;Initial values for the chaining variables.
;;This is just 0123456789ABCDEFFEDCBA9876543210F0E1D2C3 in little-endian. 
(define (init-ripe-md160)
  (let ([hash-vect (vector  #x67452301 #xEFCDAB89 #x98BADCFE #x10325476 #xC3D2E1F0 )]
        [buffer (make-bytes 64 0)])    
    (ripe-md-state hash-vect 0 buffer 0)))

;; make bufw as vector of integers then build the line call-with-values bufw reg-left reg-right t
(define (ripemd-compress-fun hash-state)
  ;; assignment from buffer to bufw
  (let ([bufw (init-bufw hash-state)]);; replace this
    ;; assignment from  hash state to registers
    (let-values ([(regs-left regs-right) (init-regs hash-state)])
      (let recur-round-of-calc ([round-of-calc 0]
                                [w 0]
                                [regs-l regs-left]
                                [regs-r regs-right])
        (cond [(eq? w 16)
               (cond [(eq? round-of-calc 5)
                      (return-compress-state hash-state regs-l regs-r)];; give back new state
                     [else recur-round-of-calc (add1 round-of-calc) 0 regs-l regs-r])]
                 
              [else 
               (let* ([sr-value (rel-list-ref SR-ref round-of-calc w)]
                      [sl-value (rel-list-ref SL-ref round-of-calc w)]
                      [rr-value (rel-list-ref RR-ref round-of-calc w)]
                      [rl-value (rel-list-ref RL-ref round-of-calc w)]
                      [kr-value (KR-ref round-of-calc)]
                      [kl-value (KL-ref round-of-calc)]
                      [tl (+ (rotl (u32+ sl-value) 
                                   (+ (regs-ref regs-l 'AL)
                                      ((bool-funs-ref round-of-calc car)
                                       (regs-ref regs-l 'BL)
                                       (regs-ref regs-l 'CL)
                                       (regs-ref regs-l 'DL))
                                      (vector-ref bufw rl-value)
                                      kl-value) 32)
                             (regs-ref regs-l 'EL))] ;; here add the lines for tl/tr 
                      [tr (+ (rotl (u32+ sr-value) 
                                   (+ (regs-ref regs-r 'AR)
                                      ((bool-funs-ref round-of-calc cadr)
                                       (regs-ref regs-r 'BR)
                                       (regs-ref regs-r 'CR)
                                       (regs-ref regs-r 'DR))
                                      (vector-ref bufw rr-value)
                                      kr-value) 32)
                             (regs-ref regs-r 'ER))])
                 (recur-round-of-calc
                  (add1 w)
                  (add1 round-of-calc)
                  (set-reg (assign-reg-to-reg
                            (set-reg
                             (assign-regs regs-l regs-assign-left)
                             'DL
                             (rotl (u32+ 10) (regs-ref regs-l 'CL) 32))
                            'CL 'BL)
                           'BL tl)                      
                  (set-reg (assign-reg-to-reg
                            (set-reg
                             (assign-regs regs-r regs-assign-right)
                             'DR
                             (rotl (u32+ 10) (regs-ref regs-r 'CR) 32))
                            'CR 'BR)
                           'BR tr)))])))))

(define (ripe-md-update hash-state data)  
  (let process-data ([h-state hash-state]
                     [data-len (bytes-length data)]                          
                     [buf-pos 0]
                     [data-pos 0]
                     )

    (let ([bytes-needed (- 64 buf-pos)])
      (cond [(>= bytes-needed data-len)
             (let* ([len-bits (* (+ data-len bytes-needed) 8)]
                    [data-pos-new (+ data-pos bytes-needed)]
                    [data-buffer (subbytes data data-pos data-pos-new)]
                    [buffer (bytes-append (ripe-md-state-buffer h-state)
                                          data-buffer)]
                    [h-state-comp (ripe-md-state (ripe-md-state-hash h-state) len-bits buffer buf-pos)])
               (process-data (ripemd-compress-fun h-state-comp)
                             (- data-len bytes-needed)
                             (+ buf-pos bytes-needed)
                             data-pos-new))]
            [else
             (let*  ([data-pos-new (+ data-pos data-len)]
                     [data-buffer (subbytes data data-pos data-pos-new)]
                     [buffer (bytes-append (ripe-md-state-buffer h-state)
                                           data-buffer)])
               (ripe-md-state (ripe-md-state-hash h-state) (* (+ data-len bytes-needed) 8) buffer data-pos-new))]))))
                   
                            
(define (ripe-md-final hash-state)
  ;; append padding
  (let* ([buffer (bytes-append (ripe-md-state-buffer hash-state) #"#x80")]
         [buf-pos (add1 (ripe-md-state-bufpos hash-state))]
         [h-state-new (cond [(> buf-pos 56)
                             ;; call compress
                             (let ([h-state (ripe-md-state  (ripe-md-state-hash hash-state)
                                                            (ripe-md-state-length hash-state)
                                                            buffer
                                                            64)])
                               (ripemd-compress-fun h-state))]
                            [else (ripe-md-state  (ripe-md-state-hash hash-state)
                                                  (ripe-md-state-length hash-state)
                                                  buffer
                                                  buf-pos)])])
    (let* ([buffer-new (bytes-append (subbytes (- (bytes-length
                                                   (ripe-md-state-buffer h-state-new)) 8))
                                     (64->bytes-little (u64+ (ripe-md-state-length h-state-new))))]
           [h-state-compress (ripe-md-state (ripe-md-state-hash h-state-new)
                                            (ripe-md-state-length h-state-new)
                                            buffer 64)]
           [h-state-final (ripemd-compress-fun h-state-compress)])
      (let ([hash-vect (ripe-md-state-hash h-state-final)])
        (let loop-digest ([digest (32->bytes-little
                                   (vector-ref hash-vect 0))]
                          [index 1])
          (cond [(< index 5)
                 (loop-digest
                  (bytes-append digest (32->bytes-little
                                        (vector-ref hash-vect index)))
                  (add1 index))]
                [else digest]))))))
                        
      
      
           
                                
    
          
    
    
  
