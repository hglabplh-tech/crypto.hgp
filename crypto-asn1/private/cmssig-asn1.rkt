;; Copyright 2014-2019 Ryan Culpepper
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
;;=======================================================================================
;; CMS signature (former pkcs7) definitions to build the asn1 signature structures for serialize / deserialice
;;========================================================================================

;;=======================================================================================
;; the OIDs for cms signatures
;;=======================================================================================
 (define id-cms-contentInfo (build-OID rsadsi  1 9 16 1 6))

 (define id-cms-akey-package (build-OID 2 16 840 1 101 2 1 2 78 5))

 (define id-cms-data (build-OID rsadsi (pkcs 1) 7 1))

 (define id-cms-signed-data (build-OID rsadsi (pkcs 1) 7 2))

 (define id-cms-enveloped-data (build-OID rsadsi (pkcs 1) 7 3))

 (define id-cms-digest-data (build-OID rsadsi (pkcs 1) 7 5))

 (define id-cms-encrypted-data (build-OID rsadsi (pkcs 1) 7 6))

 (define id-cms-auth-data (build-OID rsadsi (pkcs 1) 9 16 1 2))

 (define id-cms-auth-enveloped-data (build-OID rsadsi (pkcs 1) 9 16 1 23))

 (define id-cms-auth-compressed-data (build-OID rsadsi (pkcs 1) 9 16 1 9))

;;=====================================================================================
;; the ASN1 structures for CMS signatures
;;=====================================================================================

 (define ContentInfo (SEQUENCE 
        (contentType ContentType)
        (content #:explicit 0  ANY )))

 (define ContentType OBJECT-IDENTIFIER)


 (define SignerIdentifier  (CHOICE
        (issuerAndSerialNumber IssuerAndSerialNumber)
         (subjectKeyIdentifier SubjectKeyIdentifier) ))

 (define SignedData (SEQUENCE 
        (version CMSVersion)
        (digestAlgorithms DigestAlgorithmIdentifiers)
        (encapContentInfo EncapsulatedContentInfo)
        (certificates #:implicit 0 CertificateSet #:optional)
        (crls #:implicit 1 RevocationInfoChoices #:optional)
        (signerInfos SignerInfos)))

  (define DigestAlgorithmIdentifiers (SET-OF DigestAlgorithmIdentifier))

  (dedfine SignerInfos (SET-OF SignerInfo))

  (define EncapsulatedContentInfo (SEQUENCE           
        (eContentType ContentType)
        (eContent #:explicigt 0  OCTET-STRING #:optional)))


  (define SignedAttributes (SET-OF CmsAttribute))

  (define UnsignedAttributes (SET-OF CmsAttribute))  

  (define CmsAttribute (SEQUENCE 
        (attrType OBJECT-IDENTIFIER)
        (attrValues (SET-OF AttributeValue))))

  

  (define SignatureValue OCTET-STRING)

  (define SubjectKeyIdentifier OCTET-STRING)

  (define IssuerAndSerialNumber (SEQUENCE
                                 (issuer Name)
                                 (serialNumber INTEGER)))



(define RelativeDistinguishedName (SET-OF AttributeTypeAndValue))

(define RDNSequence (SEQUENCE-OF RelativeDistinguishedName))
(define DistinguishedName RDNSequence)
(define Name (CHOICE (rdnSequence RDNSequence)))

(define CMSVersion INTEGER)
;;{ v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }

(define DigestAlgorithmIdentifier AlgorithmIdentifier)
(define SignatureAlgorithmIdentifier AlgorithmIdentifier)

(define SignerInfo (SEQUENCE
        (version CMSVersion)
        (sid SignerIdentifier)
        (digestAlgorithm DigestAlgorithmIdentifier)
        (signedAttrs #:implicit 1 SignedAttributes #:optional)
        (signatureAlgorithm SignatureAlgorithmIdentifier)
        (signature SignatureValue)
        (unsignedAttrs #:implicit 2 UnsignedAttributes #:optional)))