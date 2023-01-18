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
         "basesig-asn1.rkt")
         
(provide (all-defined-out))

;;==================================================================================================
;; The ObjectID's for attribute and extended certificates
;;==================================================================================================


;;==================================================================================================
;; structures forf Attribute cedrtificates
;;==================================================================================================

  (define-asn1-type AttributeCertificate (SEQUENCE 
                   (acinfo               AttributeCertificateInfo)
                   (signatureAlgorithm   AlgorithmIdentifier)
                   (signatureValue       BIT-STRING)))

  (define-asn1-type AttributeCertificateInfo (SEQUENCE
                (version        AttCertVersion)
                (holder         Holder)
                (issuer         AttCertIssuer)
                (signature      AlgorithmIdentifier)
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
                   (digestedObjectType  (ENUMERATED
                                         (list
                                          (cons 'publicKey 0)
                                          (cons 'publicKeyCert 1)
                                          (cons 'otherObjectTypes 2))))
                       (otherObjectTypeID   OBJECT-IDENTIFIER #:optional)
                   (digestAlgorithm     AlgorithmIdentifier)
                   (objectDigest        BIT-STRING)))

  (define-asn1-type AttCertIssuer (CHOICE
                   (v1Form   GeneralNames)
                   (v2Form   V2Form)))

  

 (define-asn1-type V2Form  (SEQUENCE
                   (issuerName         GeneralNames #:optional)
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
                   (notBeforeTime  GeneralizedTime)
                   (notAfterTime   GeneralizedTime)))

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
             


