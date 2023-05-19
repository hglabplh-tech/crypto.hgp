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
   
