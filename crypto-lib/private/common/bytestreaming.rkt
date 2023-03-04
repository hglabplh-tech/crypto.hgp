;; Copyright 2023-2025 Harald Glab-Plhak
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
(require racket/class)
(provide (all-defined-out))

(define eof-stream '())
(define bytes-stream%
  (class object%
    (field (buffer '())
           (read-list '()))
    (super-new)

    (define/public (write-bytes bytes-in)
      (write-bytes-range bytes-in 0 (bytes-length bytes-in)))
    
    (define/public (write-bytes-range bytes-in offset length)
      (let ([intern-bytes (make-bytes length 0)])
        (bytes-copy! intern-bytes 0 bytes-in 0 length)
        (set-field! buffer this
                    (append
                     (get-field buffer this)
                     (bytes->list intern-bytes)))
        (set-field! read-list this buffer)
        
        ))

    (define/public (read-range len)
      (cond [(null? read-list) (list->bytes eof-stream)]
      [ else (let* ([intern-list (get-field read-list this)]
                    [bytes-to-read (cond [(<= len (length intern-list) ) len]
                                         [else (length intern-list)])]
                    [bytes-read-list
                     (let read ([lst '()] [index bytes-to-read])
                       (cond [(= index 0) lst]
                             [else (cond

                                     [(null? (list-tail intern-list (- bytes-to-read index))) lst]
                                     [(read (append lst
                                                    (list (car (list-tail intern-list (- bytes-to-read index)))))
                                            (- index 1))])]))]
                    )
        (set-field! read-list this (list-tail read-list bytes-to-read))
               (list->bytes bytes-read-list))]))

    (define/public (reset)
      (set-field! read-list this buffer))

    (define/public (get-bytes)
      (list->bytes buffer))
    ))

(define copy-stream (lambda (in-proc from out-proc)
  (cond [(and (procedure? in-proc)
              (procedure? out-proc)
              (eq? (procedure-arity in-proc) 1)
              (eq? (procedure-arity out-proc) 2))
         (let copying ([read-values (in-proc from)])
           (cond [(not read-values) #t]
                 [else (out-proc (car read-values) (cadr read-values))
                       (copying (in-proc from))]))]
        [else (error "parameters mismatch")])))

