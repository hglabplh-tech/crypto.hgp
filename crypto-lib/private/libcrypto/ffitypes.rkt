;; Copyright 2023-2024 Harald Glab-Plhak
;; Copyright 2012-2018 Ryan Culpepper
;; Copyright 2007-2009 Dimitris Vyzovitis <vyzo at media.mit.edu>
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
(require ffi/unsafe
         ffi/unsafe/define
         ffi/unsafe/alloc
         ffi/unsafe/atomic
         openssl/libcrypto
         "ffi.rkt"
         "../common/error.rkt")
(provide (all-defined-out))

(define-cstruct _asn1_string_st (
    [length _int]
    [type _int]
    [data _bytes]
    
     ;; The value of the following field depends on the type being held.  It
     ;; is mostly being used for BIT_STRING so if the input data has a
     ;;non-zero 'unused bits' value, it will be handled correctly
    
    [flags _long]))

(define (get-member name struct)
  (assoc name struct))
  
         