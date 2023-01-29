#lang scribble/doc
@(require scribble/manual
          scribble/basic
          scribble/eval
          racket/list
          racket/class
          racket/runtime-path
          crypto/private/common/catalog
          (for-label racket/base
                     racket/contract
                     racket/random
                     crypto))

@(define-runtime-path log-file "eval-logs/digest.rktd")
@(define the-eval (make-log-based-eval log-file 'replay))
@(the-eval '(require crypto crypto/libcrypto))
@(the-eval '(crypto-factories (list libcrypto-factory)))

@title[#:tag "digest"]{Message Digests}

A message digest function (sometimes called a cryptographic hash
function) maps variable-length, potentially long messages to
fixed-length, relatively short digests. Different digest functions, or
algorithms, compute digests of different sizes and have different
characteristics that may affect their security.

The HMAC construction combines a digest function together with a
secret key to form an authenticity and integrity mechanism
@cite{HMAC}.

This library provides both high-level, all-at-once digest operations
and low-level, incremental operations.

@(begin
   (define (rktquote s) @racket[(quote @#,(racketvalfont (format "~a" s)))])
   (define (get-size di) (or (send di get-size) +inf.0))
   (define (get-sort-string di)
     (define str (format "~a" (send di get-spec)))
     (string-append (cond [(regexp-match? #rx"^sha3-" str) "3"]
                          [(regexp-match? #rx"^sha[0-9]" str) "1"]
                          [else "9"])
                    str)))

@defproc[(digest-spec? [v any/c]) boolean?]{

Returns @racket[#t] if @racket[v] represents a digest specifier, @racket[#f]
otherwise.

A digest specifier is a symbol, which is interpreted as the name of a
digest. The following table lists valid digest names:
@tabular[
#:sep @hspace[2]
#:column-properties '(left right)
(cons
 (list @bold{Digests} @bold{Size})
 (let ()
   (define all-infos (sort (hash-values known-digests) < #:key get-size))
   (define by-size (group-by get-size all-infos))
   (for/list ([group (in-list by-size)])
     (list @elem[(add-between (for/list ([di (in-list (sort group string<? #:key get-sort-string))])
                                (rktquote (send di get-spec)))
                              ", ")]
           @elem[(format "~a" (or (send (car group) get-size) "varies"))]))))
]
Not every digest name above necessarily has an available implementation,
depending on the cryptography providers installed.

Future versions of this library may add other forms of digest
specifiers.
}

@defproc[(digest-impl? [v any/c]) boolean?]{

Returns @racket[#t] if @racket[v] represents a digest implementation,
@racket[#f] otherwise.
}

@defproc[(get-digest [di digest-spec?]
                     [factories (or/c crypto-factory? (listof crypto-factory?))
                                (crypto-factories)])
         (or/c digest-impl? #f)]{

Returns an implementation of digest @racket[di] from the given
@racket[factories]. If no factory in @racket[factories] implements
@racket[di], returns @racket[#f].
}

@defproc[(digest-size [di (or/c digest-spec? digest-impl? digest-ctx?)])
         exact-positive-integer?]{

Returns the size in bytes of the digest computed by the algorithm
represented by @racket[di].

@examples[#:eval the-eval
(digest-size 'sha1)
(digest-size 'sha256)
]
}

@defproc[(digest-block-size [di (or/c digest-spec? digest-impl? digest-ctx?)])
         exact-positive-integer?]{

Returns the size in bytes of the digest's internal block size. This
information is usually not needed by applications, but some
constructions (such as HMAC) are defined in terms of a digest
function's block size.

@examples[#:eval the-eval
(digest-block-size 'sha1)
]
}

@defproc[(digest-security-strength [di (or/c digest-spec? digest-impl? digest-ctx?)]
                                   [cr? boolean?])
         (or/c #f security-strength/c)]{

Returns the @tech{security strength} rating of the digest algorithm
represented by @racket[di], or @racket[#f] if the rating is
unknown. The result may be @racket[0] for algorithms considered
insecure.

If @racket[cr?] is true, the result reflects @racket[di]'s strength in
contexts requiring collision resistance (such as digital signatures);
if @racket[cr?] is false, the result reflects @racket[di]'s strength
assuming collision resistance is not required (such as with HMAC).

@examples[#:eval the-eval
(digest-security-strength 'sha1 #t)
(digest-security-strength 'sha1 #f)
(digest-security-strength 'sha384 #t)
]

@history[#:added "1.8"]}

@defproc[(generate-hmac-key [di (or/c digest-spec? digest-impl?)])
         bytes?]{

Generate a random secret key appropriate for HMAC using digest
@racket[di]. The length of the key is @racket[(digest-size di)].

The random bytes are generated with @racket[crypto-random-bytes].
}


@section{High-level Digest Functions}

@defproc[(digest [di (or/c digest-spec? digest-impl?)]
                 [input input/c]
                 [#:key key (or/c bytes? #f) #f])
         bytes?]{

Computes the digest of @racket[input] using the digest function
represented by @racket[di]. See @racket[input/c] for accepted values
and their conversion rules to bytes.

If @racket[di] supports keys (eg, the BLAKE2 family of digests), then
@racket[key] is used as the digest key if it is a byte string; if
@racket[key] is @racket[#f], the digest is used in unkeyed mode. If
@racket[di] does not support keys (this is true for most digests),
then @racket[key] must be @racket[#f] or else an error is raised.

@examples[#:eval the-eval
(digest 'sha1 "Hello world!")
(digest 'sha256 "Hello world!")
]
}

@defproc[(hmac [di (or/c digest-spec? digest-impl?)]
               [key bytes?]
               [input input/c])
         bytes?]{

Like @racket[digest], but computes the HMAC of @racket[input] using
digest @racket[di] and the secret key @racket[key]. The @racket[key]
may be of any length, but @racket[(digest-size di)] is a typical
key length @cite{HMAC}.
}

@section{Low-level Digest Functions}

@defproc[(make-digest-ctx [di (or/c digest-spec? digest-impl?)]
                          [#:key key (or/c bytes? #f) #f])
         digest-ctx?]{

Creates a digest context for the digest function represented by
@racket[di]. A digest context can be incrementally updated with
message data.

@examples[#:eval the-eval
(define dctx (make-digest-ctx 'sha1))
(digest-update dctx "Hello ")
(digest-update dctx "world!")
(digest-final dctx)
]
}

@defproc[(digest-ctx? [v any/c]) boolean?]{

Returns @racket[#t] if @racket[v] is a digest context, @racket[#f]
otherwise.
}

@defproc[(digest-update [dctx digest-ctx?]
                        [input input/c])
         void?]{

Updates @racket[dctx] with the message data corresponding to
@racket[input]. The @racket[digest-update] function can be called
multiple times, in which case @racket[dctx] computes the digest of the
concatenated inputs.
}

@defproc[(digest-final [dctx digest-ctx?])
         bytes?]{

Returns the digest of the message accumulated in @racket[dctx] so far
and closes @racket[dctx]. Once @racket[dctx] is closed, any further
operation performed on it will raise an exception.
}

@defproc[(digest-copy [dctx digest-ctx?])
         (or/c digest-ctx? #f)]{

Returns a copy of @racket[dctx], or @racket[#f] is the implementation
does not support copying. Use @racket[digest-copy] (or
@racket[digest-peek-final]) to efficiently compute digests for
messages with a common prefix.
}

@defproc[(digest-peek-final [dctx digest-ctx?])
         bytes?]{

Returns the digest without closing @racket[dctx], or @racket[#f] if
@racket[dctx] does not support copying.
}

@defproc[(make-hmac-ctx [di (or/c digest-spec? digest-impl?)]
                        [key bytes?])
         digest-ctx?]{

Like @racket[make-digest-ctx], but creates an HMAC context
parameterized over the digest @racket[di] and using the secret key
@racket[key].
}

@bibliography[
#:tag "digest-bibliography"

@bib-entry[#:key "HMAC"
           #:title "RFC 2104: HMAC: Keyed-Hashing for Message Authentication"
           #:url "http://www.ietf.org/rfc/rfc2104.txt"]

]

@(close-eval the-eval)
