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

(struct md-ctx (
                alg-id
                init-proc-by-alg-id
                update-proc-by-alg-id
                md-final-proc-by-alg-id
                state-by-alg-id))
                


(struct ripe-md-state (
    hash               ;;/* The current hash state */
    length             ;;/* Total number of _bits_ (not bytes) added to the
                       ;;    hash.  This includes bits that have been buffered
                         ;;  but not not fed through the compression function yet. */
    buffer
    bufpos             ;;/* number of bytes currently in the buffer */
))

(ripe-md-state (list #x45 #x6754 #x4546 #x89686) 5 #x8568758698689 10)

