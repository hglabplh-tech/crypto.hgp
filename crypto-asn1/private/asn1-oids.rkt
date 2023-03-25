;; Copyright 2023-2025 Harald Glab-Plhak
;; 
;; This library is free software: you can redistribute it and/or modify
;; it under the terms of the GNU Lesser General Public License as published
;; by the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.
;; us
;; This library is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU Lesser General Public License for more details.
;; 
;; You should have received a copy of the GNU Lesser General Public License
;; along with this library.  If not, see <http://www.gnu.org/licenses/>.

#lang racket/base
(require asn1          
         "basesig-asn1.rkt")
         
(provide (all-defined-out))
;; signed attributes OIDS
(define id-smime-capabilities (build-OID rsadsi (pkcs 1) 9 15))
;;{iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1)
;;pkcs-9(9) 15}
;;dsigned attributes Object ID's incomplete
(define id-content-type (build-OID rsadsi (pkcs 1) 9 3))
(define id-message-digest (build-OID rsadsi (pkcs 1) 9 4))
(define id-signing-time (build-OID rsadsi (pkcs 1) 9 5))
(define id-counter-signature (build-OID rsadsi (pkcs 1) 9 6))