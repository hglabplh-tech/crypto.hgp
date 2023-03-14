#lang racket/base
(require crypto crypto/libcrypto racket/match)

(crypto-factories libcrypto-factory)

(define cipher-name "AES-256-CBC")

(define symetric-key (get-symmetric-key cipher-name))

;; up to now only check if the entry is really exported 
(cms-sign-simple "")
(cms-init-signing "")
(cms-add-signing-cert "")
(write-CMS/BER "")
