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
(require asn1 asn1/util/names
         "asn1-oids.rkt"
         "basesig-asn1.rkt"
         )
         
(provide (all-defined-out))

;;==================================================================================================
;; The ObjectID's for attribute and extended certificates
;;==================================================================================================


;;==================================================================================================
;; structures forf Attribute cedrtificates
;;==================================================================================================

;;==================================================================================================
;;Attribute certificate V2

(define Time (CHOICE (utcTime UTCTime) (generalTime GeneralizedTime)))
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


  (define-asn1-type AttributeCertificate (SEQUENCE 
                   (acinfo               AttributeCertificateInfo)
                   (signatureAlgorithm   (AlgorithmIdentifier SIGNING))
                   (signatureValue       BIT-STRING)))

  (define-asn1-type AttributeCertificateInfo (SEQUENCE
                (version        AttCertVersion)
                (holder         Holder)
                (issuer         AttCertIssuer)
                (signature      (AlgorithmIdentifier SIGNING))
                (erialNumber   CertificateSerialNumber)
                (attrCertValidityPeriod   AttCertValidityPeriod)
                (attributes     (SEQUENCE-OF NameAttribute))
                (issuerUniqueID UniqueIdentifier #:optional)
                (extensions     Extensions #:optional)))

  ;; the version is always v2  
  (define v2 1)
  (define-asn1-type AttCertVersion INTEGER)

  (define-asn1-type Holder (SEQUENCE
                   (baseCertificateID #:explicit 0 IssuerSerial #:optional)                            
                   (entityName        #:explicit 1 GeneralNames #:optional)                     
                   (objectDigestInfo  #:explicit 2 ObjectDigestInfo #:optional)))

  (define-asn1-type ObjectDigestInfo  (SEQUENCE 
                   (digestedObjectType  (WRAP-NAMES ENUMERATED
                                         (list
                                          (cons 'publicKey 0)
                                          (cons 'publicKeyCert 1)
                                          (cons 'otherObjectTypes 2))))
                       (otherObjectTypeID   OBJECT-IDENTIFIER #:optional)
                   (digestAlgorithm     (AlgorithmIdentifier SIGNING))
                   (objectDigest        BIT-STRING)))

  (define-asn1-type AttCertIssuer (CHOICE
                   (v1Form   #:implicit 0 GeneralNames)
                   (v2Form   #:implicit 1 V2Form-seq)))

  

 (define-asn1-type V2Form-seq  (SEQUENCE
                   (issuerName         GeneralNames)
                   (baseCertificateID   #:explicit 0 IssuerSerial  #:optional)
                   (objectDigestInfo    #:explicit 1 ObjectDigestInfo #:optional)))
                      ;;-- issuerName MUST be present in this profile
                      ;;-- baseCertificateID and objectDigestInfo MUST
                      ;;-- NOT be present in this profile
             

 (define-asn1-type IssuerSerial (SEQUENCE
                   (issuer         GeneralNames)
                   (serial         CertificateSerialNumber)
                   (issuerUID      UniqueIdentifier #:optional)))
             

 (define-asn1-type AttCertValidityPeriod (SEQUENCE 
                   (notBeforeTime Time)
                   (notAfterTime   Time)))

 (define-asn1-type Targets (SEQUENCE-OF Target))

 (define-asn1-type Target  (CHOICE 
                   (targetName     GeneralName)
                   (targetGroup    GeneralName)
                   (targetCert     TargetCert)))
             

 (define-asn1-type TargetCert   (SEQUENCE 
                   (targetCertificate  IssuerSerial)
                   (targetName         GeneralName #:optional)
                   (certDigestInfo     ObjectDigestInfo #:optional)))
             

 (define-asn1-type IetfAttrSyntax (SEQUENCE
                  (policyAuthority #:explicit 0 GeneralNames    #:optional)
                  (values         (SEQUENCE-OF (CHOICE 
                                     (octets    OCTET-STRING)
                                     (oid       OBJECT-IDENTIFIER)
                                     (string    UTF8String))))))
             

 (define-asn1-type SvceAuthInfo (SEQUENCE 
                   (service       GeneralName)
                   (ident         GeneralName)
                   (authInfo      OCTET-STRING #:optional)))
             

 (define-asn1-type RoleSyntax (SEQUENCE
                   (roleAuthority #:explicit 0 GeneralNames #:optional)
                   (roleName      #:explicit 1 GeneralName)))
             

 (define-asn1-type Clearance  (SEQUENCE 
                   (policyId    #:explicit 0 OBJECT-IDENTIFIER)
                   (classList    #:explicit 1 ClassList #:default 1)
                   (securityCategorie                   
                                  #:explicit 2 (SET-OF SecurityCategory) #:optional)))
             

  (define-asn1-type ClassList  (WRAP-NAMES BIT-STRING
                            (list
                               (cons 'unmarked     0)
                               (cons 'unclassified 1)
                               (cons 'restricted   2)
                               (cons 'confidential 3)
                               (cons 'secret       4)
                               (cons 'topSecret    5))))
             


  (define-asn1-type SecurityCategory (SEQUENCE 
                   (type      #:implicit 0 OBJECT-IDENTIFIER)
                   (value     #:explicit 1 ANY)))

  (define-asn1-type  AAControls (SEQUENCE 
                   (pathLenConstraint INTEGER #:optional)
                   (permittedAttrs    #:explicit 0 AttrSpec #:optional)
                   (excludedAttrs     #:explicit 1 AttrSpec #:optional)
                   (permitUnSpecified BOOLEAN #:default #t)))
             

  (define-asn1-type AttrSpec (SEQUENCE-OF OBJECT-IDENTIFIER))

  (define-asn1-type ACClearAttrs  (SEQUENCE 
                   (acIssuer          GeneralName)
                   (acSerial          INTEGER)
                   (attrs             (SEQUENCE-OF NameAttribute))))
             


;==================================================================================================
;;Attribute certificate V1

 (define v1 1)

 (define-asn1-type AttributeCertificateV1  (SEQUENCE 
     (acInfo AttributeCertificateInfoV1)
     (signatureAlgorithm (AlgorithmIdentifier SIGNING))
     (signature BIT-STRING)))

  (define-asn1-type AttributeCertificateInfoV1 (SEQUENCE 
     (version INTEGER #:default v1)
     (subject (CHOICE 
       (baseCertificateID  #:explicit 0 IssuerSerial)
         ;;-- associated with a Public Key Certificate
       (subjectName #:explicit 1 GeneralNames)))
         ;;-- associated with a name
     (issuer GeneralNames)
     (signature (AlgorithmIdentifier SIGNING))
     (serialNumber CertificateSerialNumber)
     (attCertValidityPeriod AttCertValidityPeriod)
     (attributes (SEQUENCE-OF Attribute))
     (issuerUniqueID UniqueIdentifier #:optional)
     (extensions Extensions #:optional)))

;;================================================================================================
;; X509 Certificate definition


(define Validity (SEQUENCE (notBefore Time) (notAfter Time)))
(define SubjectPublicKeyInfo/DER ANY/DER)

(define-asn1-type Certificate
  (SEQUENCE
   (tbsCertificate TBSCertificate)
   (signatureAlgorithm AlgorithmIdentifier/DER);;AlgorithmIdentifier/DER)
   (signatureValue BIT-STRING)))

(define-asn1-type TBSCertificate
  (SEQUENCE
   (version #:explicit 0 Version #:default v1)
   (serialNumber CertificateSerialNumber)
   (signature AlgorithmIdentifier/DER)
   (issuer CertName)
   (validity Validity)
   (subject CertName)
   (subjectPublicKeyInfo SubjectPublicKeyInfo/DER)
   (issuerUniqueID #:implicit 1 UniqueIdentifier #:optional)
   (subjectUniqueID #:implicit 2 UniqueIdentifier #:optional)
   (extensions #:explicit 3 Extensions #:optional)))



(define Version INTEGER)

(define v3 2)

;;==================================================================================================
;; ExtendedCertificate defrinition

;;Certificate definitions
(define DigestAlgorithmIdentifier (AlgorithmIdentifier SIGNING))
(define SignatureAlgorithmIdentifier (AlgorithmIdentifier SIGNING))
(define-asn1-type UnauthAttributes (SET-OF Attribute))

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


(define-asn1-type CertificateList
  (SEQUENCE
   (tbsCertList ANY/DER)
   (signatureAlgorithm (AlgorithmIdentifier SIGNING))
   (signature BIT-STRING)))



   


