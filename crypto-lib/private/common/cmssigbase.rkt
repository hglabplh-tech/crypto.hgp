;; Copyright 2013-2022 Ryan Culpepper
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
(require racket/class
         racket/match
         asn1
         binaryio/integer
         base64
         "catalog.rkt"
         "interfaces.rkt"
         "common.rkt"
         "error.rkt"
         "base256.rkt"
         "asn1.rkt"
         "../../util/bech32.rkt")
(provide (all-defined-out))

(define cms-sign-impl-base%
  (class* impl-base% (cms-sign<%>)
    (inherit about get-spec get-factory)
    (super-new)
    (define/public (cms-sign-sure cert-bytes cert-stack pkey-bytes data-bytes flags) #f)
    (define/public (cms-init-signing cert-bytes pkey-bytes cert-stack data-bytes flags) #f)
    (define/public (cms-add-cert cert-bytes) #f)
    (define/public (cms-signerinfo-sign) #f)
    (define/public (cms-add-signer cert-bytes pkey-bytes digest-name flags) #f)
    (define/public (cms-sign-finalize data-bytes flags) #f)
    (define/public (get-cms-content-info ) #f)
    (define/public (get-cms-content-info/DER) #f)
    (define/public (cms-sign-receipt cert-bytes pkey-bytes flags) #f)
    ))

