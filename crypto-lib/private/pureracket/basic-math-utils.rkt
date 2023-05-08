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
         (only-in srfi/60 bitwise-if rotate-bit-field)
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