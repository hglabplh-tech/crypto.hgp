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
         "basesig-asn1.rkt" "attrcert-asn1.rkt")
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

  (define-asn1-type RevocationInfoChoices (SET-OF RevocationInfoChoice))

  (define-asn1-type RevocationInfoChoice (CHOICE
        (crl CertificateList)
        (other #:implicit 1 OtherRevocationInfoFormat)))

 (define-asn1-type OtherRevocationInfoFormat  (SEQUENCE
        (otherRevInfoFormat OBJECT-IDENTIFIER)
        (otherRevInfo ANY)))

 (define-asn1-type CertificateChoices  (CHOICE 
     (certificate Certificate)
     (extendedCertificate #:explicit 0 ExtendedCertificate)  ;;-- Obsolete
     (v1AttrCert #:implicit 1  AttributeCertificate)        ;;-- Obsolete
     (v2AttrCert #:implicit 2 AttributeCertificateV2)
     (other #:implicit 3 OtherCertificateFormat)))

  (define AttributeCertificateV2 AttributeCertificate)

  (define-asn1-type OtherCertificateFormat (SEQUENCE 
     (otherCertFormat OBJECT-IDENTIFIER)
     (otherCert ANY)))

  (define-asn1-type CertificateSet (SET-OF CertificateChoices))

  (define DigestAlgorithmIdentifiers (SET-OF DigestAlgorithmIdentifier))

  (define SignerInfos (SET-OF SignerInfo))

  (define EncapsulatedContentInfo (SEQUENCE           
        (eContentType ContentType)
        (eContent #:explicit 0  OCTET-STRING #:optional)))

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

(define-asn1-type UnauthAttributes (SET-OF Attribute))

(define RelativeDistinguishedName (SET-OF AttributeTypeAndValue))

(define RDNSequence (SEQUENCE-OF RelativeDistinguishedName))
(define DistinguishedName RDNSequence)
(define Name (CHOICE (rdnSequence RDNSequence)))

(define CMSVersion INTEGER)
;;{ v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }

(define DigestAlgorithmIdentifier AlgorithmIdentifier)
(define SignatureAlgorithmIdentifier AlgorithmIdentifier)

(define-asn1-type SignerInfo (SEQUENCE
        (version CMSVersion)
        (sid SignerIdentifier)
        (digestAlgorithm DigestAlgorithmIdentifier)
        (signedAttrs #:implicit 1 SignedAttributes #:optional)
        (signatureAlgorithm SignatureAlgorithmIdentifier)
        (signature SignatureValue)
        (unsignedAttrs #:implicit 2 UnsignedAttributes #:optional)))
 

;;Certificate definitions
(define Validity (SEQUENCE (notBefore GeneralizedTime) (notAfter GeneralizedTime)))
(define-asn1-type Certificate
  (SEQUENCE
   (tbsCertificate TBSCertificate)
   (signatureAlgorithm AlgorithmIdentifier/DER)
   (signature BIT-STRING #:optional)))

(define-asn1-type TBSCertificate
  (SEQUENCE
   (version #:explicit 0 Version #:default v1)
   (serialNumber CertificateSerialNumber)
   (signature AlgorithmIdentifier/DER)
   (issuer Name)
   (validity Validity)
   (subject Name)
   (subjectPublicKeyInfo ANY/DER)
   (issuerUniqueID #:implicit 1 UniqueIdentifier #:optional)
   (subjectUniqueID #:implicit 2 UniqueIdentifier #:optional)
   (extensions #:explicit 3 Extensions #:optional)))



(define Version INTEGER)
(define v1 0)
(define v2 1)
(define v3 2)

(define CertificateSerialNumber INTEGER)

(define-asn1-type CertificateList
  (SEQUENCE
   (tbsCertList ANY/DER)
   (signatureAlgorithm (AlgorithmIdentifier SIGNING))
   (signature BIT-STRING)))

(define SIGNING
  (relation
   #:heading
   ['oid                    'pk  'digest 'params  'params-presence]
   #:tuples
   ;; From RFC 5912:
   [md5WithRSAEncryption    'rsa 'md5    NULL     'required]
   [sha1WithRSAEncryption   'rsa 'sha1   NULL     'required]
   [sha224WithRSAEncryption 'rsa 'sha224 NULL     'required]
   [sha256WithRSAEncryption 'rsa 'sha256 NULL     'required]
   [sha384WithRSAEncryption 'rsa 'sha384 NULL     'required]
   [sha512WithRSAEncryption 'rsa 'sha512 NULL     'required]
   [id-RSASSA-PSS           'rsa #f      RSASSA-PSS-params 'required]
   [dsa-with-sha1           'dsa 'sha1   NULL     'absent]
   [id-dsa-with-sha224      'dsa 'sha224 NULL     'absent]
   [id-dsa-with-sha256      'dsa 'sha256 NULL     'absent]
   [id-dsa-with-sha384      'dsa 'sha384 NULL     'absent]
   [id-dsa-with-sha512      'dsa 'sha512 NULL     'absent]
   [ecdsa-with-SHA1         'ec  'sha1   NULL     'absent]
   [ecdsa-with-SHA224       'ec  'sha224 NULL     'absent]
   [ecdsa-with-SHA256       'ec  'sha256 NULL     'absent]
   [ecdsa-with-SHA384       'ec  'sha384 NULL     'absent]
   [ecdsa-with-SHA512       'ec  'sha512 NULL     'absent]

   ;; From RFC 8410:
   [id-Ed25519              'eddsa #f    #f       'absent]
   [id-Ed448                'eddsa #f    #f       'absent]
   ))

(define-asn1-type ExtendedCertificateOrCertificate (CHOICE
     (certificate Certificate)
     (extendedCertificate #:implicit 0 ExtendedCertificate)))

 (define-asn1-type ExtendedCertificate (SEQUENCE 
     (extendedCertificateInfo ExtendedCertificateInfo)
     (signatureAlgorithm SignatureAlgorithmIdentifier)
     (signature Signature)))

  (define-asn1-type ExtendedCertificateInfo (SEQUENCE 
     (version CMSVersion)
     (certificate Certificate)
     (attributes UnauthAttributes)))

   (define-asn1-type Signature BIT-STRING)
