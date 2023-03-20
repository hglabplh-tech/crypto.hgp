#lang racket/base
(provide (all-defined-out))
(define find-value-element (lambda (content  varargs)
                             (let recur-find-value ([content-to-work content]
                                                    [args varargs])
                               (cond [(null? args) content-to-work])
                               (let* (
                                      [element (car args)]
                                      [found-content (cond [(hash? content-to-work) (hash-ref content-to-work element #f)]
                                                           [else (cond [(not (andmap pair? content-to-work))
                                                                        content-to-work]
                                                                       [(assoc element content-to-work)
                                                                        (cadr(assoc element content-to-work))]
                                                                       [else #f])])])
                                 (cond [found-content
                                        (cond [(null? (cdr args))
                                               found-content]
                                              [else (recur-find-value found-content (cdr args))])]
                                       [else content-to-work])))))
                                                  
(define find-value-element-proc (lambda varargs
  (lambda (content)
    (find-value-element content  varargs))))

