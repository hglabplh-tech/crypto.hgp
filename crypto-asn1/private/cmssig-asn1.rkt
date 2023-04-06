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
         "basesig-asn1.rkt"
         "certificates-asn1.rkt"
         "asn1-oids.rkt")
(provide (all-defined-out)
         Name GeneralName
         GeneralNames
         UnauthAttributes
         relation-ref
         relation)
;;=======================================================================================
;; CMS signature (former pkcs7) definitions to build the asn1 signature structures for serialize / deserialice
;;========================================================================================
;;FIXME : add the latest definitions too and change a few definitions to fit the latest specification changes
;;=======================================================================================      


;;algorithm and other identifiers..... and primitive definitions

(define MessageDigest OCTET-STRING)

(define-asn1-type Parameters (CHOICE
                              (octet-string OCTET-STRING)
                              (int-val INTEGER)))

(define SigningTime  Time)

(define-asn1-type SMIMECapability (SEQUENCE 
                                   [capabilityID OBJECT-IDENTIFIER]
                                   [parameters Parameters #:optional])) ;; have to add #:dependent instead of ANY  !!!FIXME!!!



(define-asn1-type SMIMECapabilities (SEQUENCE-OF SMIMECapability))

    



(define ContentEncryptionAlgorithmIdentifier AlgorithmIdentifier/DER)

(define KeyEncryptionAlgorithmIdentifier  AlgorithmIdentifier/DER)

(define KeyDerivationAlgorithmIdentifier AlgorithmIdentifier/DER)

(define MessageAuthenticationCodeAlgorithm AlgorithmIdentifier/DER)

(define DefaultAlgorithm AlgorithmIdentifier/DER)


;;FIXME!! add specific Algorithm Identifier types
;;
;;=====================================================================================
;; the ASN1 structures for CMS signatures
;;=====================================================================================

(define-asn1-type CounterSignature SignerInfo)



(define (ContentInfoValue attr-oid)
  (or (relation-ref CONTENTINFO-VALUES 'oid attr-oid 'type) ANY))

(define-asn1-type ContentInfo (SEQUENCE 
                               (contentType ContentType)        
                               (content #:explicit 0 #:dependent (ContentInfoValue contentType))))

(define ContentType OBJECT-IDENTIFIER)


(define-asn1-type SignerIdentifier  (CHOICE
                                     (issuerAndSerialNumber IssuerAndSerialNumber)
                                     (subjectKeyIdentifier SubjectKeyIdentifier) ))

(define-asn1-type SignerInfo (SEQUENCE
                              (version CMSVersion)
                              (sid SignerIdentifier)
                              (digestAlgorithm AlgorithmIdentifier/DER)
                              (signedAttrs #:implicit 0 SignedAttributes #:optional)
                              (signatureAlgorithm AlgorithmIdentifier/DER)
                              (signature SignatureValue)
                              (unsignedAttrs #:implicit 1 UnsignedAttributes #:optional)))


(define-asn1-type RevocationInfoChoices (SET-OF RevocationInfoChoice))

(define-asn1-type RevocationInfoChoice (CHOICE
                                        (crl CertificateList)
                                        (other #:implicit 1 OtherRevocationInfoFormat)))

(define-asn1-type OtherRevocationInfoFormat  (SEQUENCE
                                              (otherRevInfoFormat OBJECT-IDENTIFIER)
                                              (otherRevInfo #:dependent (ANY otherRevInfoFormat))))

(define-asn1-type CertificateChoices  (CHOICE 
                                       (certificate Certificate)
                                       (extendedCertificate #:explicit 0 ExtendedCertificate)  ;;-- Obsolete but used in the field up to now
                                       (v1AttrCert #:implicit 1  AttributeCertificateV1)        ;;-- Obsolete but used in the field up to now
                                       (v2AttrCert #:implicit 2 AttributeCertificateV2)
                                       (other #:implicit 3 OtherCertificateFormat)))

(define AttributeCertificateV2 AttributeCertificate)

(define-asn1-type OtherCertificateFormat (SEQUENCE 
                                          (otherCertFormat OBJECT-IDENTIFIER)
                                          (otherCert ANY)))

(define-asn1-type CertificateSet (SET-OF CertificateChoices))

(define-asn1-type  DigestAlgorithmIdentifiers (SET-OF AlgorithmIdentifier/DER))

(define SignerInfos (SET-OF SignerInfo))

(define-asn1-type AuthAttributes (SET-OF Attribute))
 

(define-asn1-type MessageAuthenticationCode OCTET-STRING)
(define-asn1-type EncryptedContent OCTET-STRING)

(define-asn1-type UnprotectedAttributes (SET-OF Attribute))





(define-asn1-type EncryptedKey OCTET-STRING)

(define-asn1-type EncapsulatedContentInfo (SEQUENCE         ;;next to get delete this after coding  
                                           (eContentType ContentType)
                                           (eContent #:explicit 0  OCTET-STRING #:optional)))

(define-asn1-type smime-cap-attr-type      (SET-OF SMIMECapabilities))
(define-asn1-type content-attr-type        (SET-OF OBJECT-IDENTIFIER))
(define-asn1-type md-attr-type             (SET-OF OCTET-STRING))
(define-asn1-type signing-time-attr-type   (SET-OF Time))
(define-asn1-type counter-sig-attr-type    (SET-OF CounterSignature))

(define CMS-ATTRIBUTES
  (relation
   #:heading
   ['oid                         'type]
   #:tuples
   [id-smime-capabilities        smime-cap-attr-type]
   [id-content-type              content-attr-type]
   [id-message-digest            md-attr-type]
   [id-signing-time              signing-time-attr-type ]
   [id-counter-signature         counter-sig-attr-type]
   
   ))

 

(define (CmsAttributeValue attr-oid)
  (or (relation-ref CMS-ATTRIBUTES 'oid attr-oid 'type) ANY))

(define-asn1-type CmsAttribute (SEQUENCE 
                                (attrType OBJECT-IDENTIFIER)
                                (attrValues #:dependent
                                            (CmsAttributeValue attrType))))

(define SignedAttributes (SET-OF CmsAttribute))

(define UnsignedAttributes (SET-OF CmsAttribute))  

 

  

(define SignatureValue OCTET-STRING)

(define SubjectKeyIdentifier OCTET-STRING)

(define IssuerAndSerialNumber (SEQUENCE
                               (issuer CertName)
                               (serialNumber INTEGER)))






(define DistinguishedName RDNSequence)



;;{ v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }




 


(define-asn1-type OriginatorInfo (SEQUENCE 
                                  (certs #:implicit 0 CertificateSet #:optional)
                                  (crls  #:implicit 1 RevocationInfoChoices #:optional)))

(define EncryptedContentInfo (SEQUENCE 
                              (contentType ContentType)
                              (contentEncryptionAlgorithm AlgorithmIdentifier/DER)
                              (encryptedContent #:implicit 0 EncryptedContent #:optional)))


(define-asn1-type KeyTransRecipientInfo (SEQUENCE 
                                         (version CMSVersion)  ;;-- always set to 0 or 2
                                         (rid RecipientIdentifier)
                                         (keyEncryptionAlgorithm AlgorithmIdentifier/DER)
                                         (encryptedKey EncryptedKey)))

(define-asn1-type RecipientIdentifier (CHOICE 
                                       (issuerAndSerialNumber IssuerAndSerialNumber)
                                       (subjectKeyIdentifier #:explicit 0 SubjectKeyIdentifier)))

(define-asn1-type KeyAgreeRecipientInfo (SEQUENCE 
                                         (version CMSVersion)  ;;-- always set to 3
                                         (originator #:explicit 0 OriginatorIdentifierOrKey)
                                         (ukm #:explicit 1 UserKeyingMaterial #:optional)
                                         (keyEncryptionAlgorithm AlgorithmIdentifier/DER)
                                         (recipientEncryptedKeys RecipientEncryptedKeys)))

(define-asn1-type UserKeyingMaterial OCTET-STRING)

(define-asn1-type RecipientEncryptedKeys (SEQUENCE-OF RecipientEncryptedKey))

(define-asn1-type RecipientEncryptedKey (SEQUENCE
                                         (rid KeyAgreeRecipientIdentifier)
                                         (encryptedKey EncryptedKey)))

(define-asn1-type KeyAgreeRecipientIdentifier (CHOICE 
                                               (issuerAndSerialNumber IssuerAndSerialNumber)
                                               (rKeyId #:implicit 0 RecipientKeyIdentifier)))
        

(define-asn1-type RecipientKeyIdentifier (SEQUENCE 
                                          (subjectKeyIdentifier SubjectKeyIdentifier)
                                          (date GeneralizedTime #:optional)
                                          (other OtherKeyAttribute #:optional)))

  


(define-asn1-type OriginatorIdentifierOrKey (CHOICE 
                                             (issuerAndSerialNumber IssuerAndSerialNumber)
                                             (subjectKeyIdentifier #:explicit 0 SubjectKeyIdentifier)
                                             (originatorKey #:explicit 1 OriginatorPublicKey)))

(define-asn1-type OriginatorPublicKey (SEQUENCE
                                       (algorithm AlgorithmIdentifier/DER)
                                       (publicKey BIT-STRING)))

(define-asn1-type KEKRecipientInfo (SEQUENCE 
                                    (version CMSVersion)  ;;-- always set to 4
                                    (kekid KEKIdentifier)
                                    (keyEncryptionAlgorithm AlgorithmIdentifier/DER)
                                    (encryptedKey EncryptedKey)))

(define-asn1-type KEKIdentifier (SEQUENCE 
                                 (keyIdentifier OCTET-STRING)
                                 (date GeneralizedTime #:optional)
                                 (other OtherKeyAttribute #:optional)))

(define-asn1-type OtherKeyAttribute (SEQUENCE 
                                     (keyAttrId OBJECT-IDENTIFIER)
                                     (keyAttr #:dependent (ANY keyAttrId) #:optional))) ;;DEFINED BY keyAttrId OPTIONAL }

(define-asn1-type PasswordRecipientInfo (SEQUENCE 
                                         (version CMSVersion)   ;;-- Always set to 0
                                         (keyDerivationAlgorithm #:explicit 0 AlgorithmIdentifier/DER
                                                                 #:optional)
                                         (keyEncryptionAlgorithm AlgorithmIdentifier/DER)
                                         (encryptedKey EncryptedKey)))

(define-asn1-type OtherRecipientInfo (SEQUENCE
                                      (oriType OBJECT-IDENTIFIER)
                                      (oriValue #:dependent (ANY oriType)))) ;;DEFINED BY oriType

(define-asn1-type RecipientInfo (CHOICE
                                 (ktri KeyTransRecipientInfo)
                                 (kari #:explicit 1 KeyAgreeRecipientInfo)
                                 (kekri #:explicit 2 KEKRecipientInfo)
                                 (pwri #:explicit 3 PasswordRecipientInfo)
                                 (ori #:explicit 4 OtherRecipientInfo)))
(define-asn1-type RecipientInfos (SET-OF RecipientInfo))

(define-asn1-type AuthenticatedData  (SEQUENCE 
                                      (version CMSVersion)
                                      (originatorInfo #:implicit 0 OriginatorInfo #:optional)
                                      (recipientInfos RecipientInfos)
                                      (macAlgorithm MessageAuthenticationCodeAlgorithm)
                                      (digestAlgorithm #:explicit 1 AlgorithmIdentifier/DER #:optional)
                                      (encapContentInfo EncapsulatedContentInfo)
                                      (authAttrs #:implicit 2 AuthAttributes #:optional)
                                      (mac MessageAuthenticationCode)
                                      (unauthAttrs #:implicit 3 UnauthAttributes #:optional)))

(define-asn1-type EnvelopedData (SEQUENCE
                                 (version CMSVersion)
                                 (originatorInfo #:implicit 0 OriginatorInfo #:optional)
                                 (recipientInfos RecipientInfos)
                                 (encryptedContentInfo EncryptedContentInfo)
                                 (unprotectedAttrs #:implicit 1 UnprotectedAttributes #:optional)))

(define-asn1-type SignedData (SEQUENCE 
                              (version CMSVersion)
                              (digestAlgorithms DigestAlgorithmIdentifiers)
                              (encapContentInfo EncapsulatedContentInfo)
                              (certificates #:implicit 0 CertificateSet #:optional)
                              (crls #:implicit 1 RevocationInfoChoices #:optional)
                              (signerInfos SignerInfos)))

(define-asn1-type EncryptedData (SEQUENCE 
                                 [version CMSVersion]
                                 [encryptedContentInfo EncryptedContentInfo]
                                 [unprotectedAttrs #:implicit 1 UnprotectedAttributes #:optional]))

(define CONTENTINFO-VALUES
  (relation
   #:heading
   ['oid                         'type]
   #:tuples
   [id-cms-enveloped-data        EnvelopedData]
   [id-cms-signed-data           SignedData]
   [id-cms-encrypted-data        EncryptedData]   
   ))

 

