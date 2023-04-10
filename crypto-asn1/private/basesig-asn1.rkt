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
         "error.rkt"
         "asn1-oids.rkt")
(provide (all-defined-out)
         relation-ref)

;; define relations

(struct rel (heading tuples) #:transparent)
(define (relation* heading tuples)
  (define nfields (vector-length heading))
  (for ([tuple (in-vector tuples)])
    (unless (= (vector-length tuple) nfields)
      (error 'relation "wrong number of fields\n  expected: ~s fields\n  tuple: ~e"
             nfields tuple)))
  (rel heading tuples))
(define-syntax-rule (relation #:heading [field ...] #:tuples [value ...] ...)
  (relation* (vector field ...) (vector (vector value ...) ...)))

(define (relation-field-index rel keyfield #:who [who 'relation-field-index])
  (or (for/first ([field (in-vector (rel-heading rel))]
                  [index (in-naturals)]
                  #:when (equal? field keyfield))
        index)
      (error who "field not found in relation\n  field: ~e\n  heading: ~e"
             keyfield (rel-heading rel))))

(define (relation-find rel keyfield key #:who [who 'relation-find])
  (define keyindex (relation-field-index rel keyfield #:who who))
  (for/first ([tuple (in-vector (rel-tuples rel))]
              #:when (equal? (vector-ref tuple keyindex) key))
    tuple))

(define (relation-ref rel keyfield key wantfield #:who [who 'relation-ref])
  (cond [(relation-find rel keyfield key #:who who)
         => (lambda (tuple)
              (vector-ref tuple (relation-field-index rel wantfield #:who who)))]
        [else #f]))

(define (relation-ref* rel keyfield key wantfields #:who [who 'relation-ref])
  (cond [(relation-find rel keyfield key #:who who)
         => (lambda (tuple)
              (map (lambda (wantfield)
                     (vector-ref tuple (relation-field-index rel wantfield #:who who)))
                   wantfields))]
        [else #f]))

(define (relation-column rel keyfield #:who [who 'relation-column])
  (define keyindex (relation-field-index rel keyfield #:who who))
  (for/vector ([tuple (in-vector (rel-tuples rel))])
    (vector-ref tuple keyindex)))



(define CertificateSerialNumber INTEGER)

;; ============================================================
;; Object Identifiers










(define-asn1-type HashAlgorithm (AlgorithmIdentifier HASH))

(define MASKGEN
  (relation
   #:heading
   ['oid 'params]
   #:tuples
   [id-mgf1 HashAlgorithm]))

(define-asn1-type MaskGenAlgorithm (AlgorithmIdentifier MASKGEN))

(define RSASSA-PSS-params
  (let* ([sha1Identifier (hasheq 'algorithm id-sha1 'parameters #f)]
         [mgf1SHA1Identifier (hasheq 'algorithm id-mgf1 'parameters sha1Identifier)])
    (SEQUENCE
     [hashAlgorithm    #:explicit 0 HashAlgorithm #:default sha1Identifier]
     [maskGenAlgorithm #:explicit 1 MaskGenAlgorithm #:default mgf1SHA1Identifier]
     [saltLength       #:explicit 2 INTEGER #:default 20]
     [trailerField     #:explicit 3 INTEGER #:default 1])))

(module+ pss-params
  (require "util.rkt")
  ;; The CA/B Baseline Recommendations give the following AlgorithmIdentifiers
  ;; for RSA-PSS. This module extracts the RSASSA-PSS-params.
  (define AlgId (SEQUENCE [a OBJECT-IDENTIFIER] [p RSASSA-PSS-params]))
  (define (pss-params algid-hex)
    (define algid-der (hex->bytes algid-hex))
    #;(hash-ref (bytes->asn1/DER AlgId algid-der) 'p)
    (bytes->asn1/DER AlgId algid-der))
  (hasheq 'sha256 (pss-params "304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a203020120")
          'sha384 (pss-params "304106092a864886f70d01010a3034a00f300d06096086480165030402020500a11c301a06092a864886f70d010108300d06096086480165030402020500a203020130")
          'sha512 (pss-params "304106092a864886f70d01010a3034a00f300d06096086480165030402030500a11c301a06092a864886f70d010108300d06096086480165030402030500a203020140")))

;; Per CA/B Baseline Recommendations, the following PSS configurations are supported:
(define PSS-configs
  '())

(define sha224WithRSAEncryption (build-OID pkcs-1 14))
(define sha256WithRSAEncryption (build-OID pkcs-1 11))
(define sha384WithRSAEncryption (build-OID pkcs-1 12))
(define sha512WithRSAEncryption (build-OID pkcs-1 13))

;; from CryptographicMessageSyntaxAlgorithms-2009 (1.2.840.113549.1.9.160.37)

;; (define rsaEncryption (build-OID pkcs-1 1))
;; (define id-alg-ESDH (build-OID pkcs-9 (smime 16) (alg 3) 5))
;; (define id-alg-SSDH (build-OID pkcs-9 (smime 16) (alg 3) 10))
;; (define id-alg-CMS3DESwrap (build-OID pkcs-9 (smime 16) (alg 3) 6))
;; (define id-alg-CMSRC2wrap (build-OID pkcs-9 (smime 16) (alg 3) 7))
(define des-ede3-cbc (build-OID rsadsi (encryptionAlgorithm 3) 7))
;; (define rc2-cbc (build-OID rsadsi (encryptionAlgorithm 3) 2))
;; (define id-PBKDF2 (build-OID rsadsi (pkcs 1) (pkcs-5 5) 12))

(define hMAC-SHA1
  (OID (iso 1) (identified-organization 3) (dod 6) (internet 1) (security 5)
       (mechanisms 5) 8 1 2))

;; from CMSAesRsaesOaep-2009 (1.2.840.113549.1.9.16.0.38)

;; (define aes (build-OID nistAlgorithms 1))
;; (define id-aes128-CBC (build-OID aes 2))
;; (define id-aes192-CBC (build-OID aes 22))
;; (define id-aes256-CBC (build-OID aes 42))
;; (define id-aes128-wrap (build-OID aes 5))
;; (define id-aes192-wrap (build-OID aes 25))
;; (define id-aes256-wrap (build-OID aes 45))

;; CMS-AES-CCM-and-AES-GCM-2009 (1.2.840.113549.1.9.16.0.44)

;; (define aes (build-OID nistAlgorithms 1))
;; (define id-aes128-CCM (build-OID aes 7))
;; (define id-aes192-CCM (build-OID aes 27))
;; (define id-aes256-CCM (build-OID aes 47))
;; (define id-aes128-GCM (build-OID aes 6))
;; (define id-aes192-GCM (build-OID aes 26))
;; (define id-aes256-GCM (build-OID aes 46))



;; from HMAC-2010 (1.3.6.1.5.5.7.0.74)

;; (define digestAlgorithm (build-OID rsadsi 2))
;; (define id-hmacWithSHA224 (build-OID digestAlgorithm 8))
;; (define id-hmacWithSHA256 (build-OID digestAlgorithm 9))
;; (define id-hmacWithSHA384 (build-OID digestAlgorithm 10))
;; (define id-hmacWithSHA512 (build-OID digestAlgorithm 11))

;; from NIST-AES (2.16.840.1.101.3.4.0.1)





(define-asn1-type -SomeString
  (CHOICE  
   (printableString  PrintableString)
   (universalString  UniversalString)
   (utf8String   UTF8String)
   (bmpString  BMPString)))
(define X520name -SomeString)
(define X520CommonName -SomeString)
(define X520LocalityName -SomeString)
(define X520StateOrProvinceName -SomeString)
(define X520OrganizationName -SomeString)
(define X520OrganizationalUnitName -SomeString)
(define X520Title -SomeString)
(define X520Pseudonym -SomeString)
(define DirectoryString -SomeString)
(define X520dnQualifier PrintableString)
(define X520countryName PrintableString)
(define X520SerialNumber PrintableString)
(define DomainComponent IA5String)
(define EmailAddress IA5String)



;; ============================================================
;; ASN1 Helpers

;; Helper for embedding DER into larger structures
(define ANY/DER
  (WRAP ANY
        #:encode (lambda (v) (bytes->asn1/DER ANY v))
        #:decode (lambda (v) (asn1->bytes/DER ANY v))))

;; BIT-STRING-containing : (U ASN1-Type #f) -> ASN1-Type
(define (BIT-STRING-containing type)
  (cond [type
         (WRAP BIT-STRING
               #:encode (lambda (v) (bit-string (asn1->bytes/DER type v) 0))
               #:decode (lambda (v) (bytes->asn1/DER type (bit-string-bytes v))))]
        [else
         (WRAP BIT-STRING
               #:encode (lambda (v) (bit-string v 0))
               #:decode (lambda (v) (bit-string-bytes v)))]))

;; OCTET-STRING-containing : (U ASN1-Type #f) -> ASN1-Type
(define (OCTET-STRING-containing type)
  (cond [type
         (WRAP OCTET-STRING
               #:encode (lambda (v) (asn1->bytes/DER type v))
               #:decode (lambda (v) (bytes->asn1/DER type v)))]
        [else OCTET-STRING]))

;; useful for giving SEQUENCE w/ optional fields a fixed shape for match
(define (ensure-keys h keys)
  (for/fold ([h h]) ([key (in-list keys)])
    (if (hash-has-key? h key) h (hash-set h key #f))))


;; Type definitions
(define ATTRIBUTES
  (relation
   #:heading
   ['oid                         'type]
   #:tuples
   [id-at-name                   X520name]
   [id-at-surname                X520name]
   [id-at-givenName              X520name]
   [id-at-initials               X520name]
   [id-at-generationQualifier    X520name]
   [id-at-commonName             X520CommonName]
   [id-at-localityName           X520LocalityName]
   [id-at-stateOrProvinceName    X520StateOrProvinceName]
   [id-at-organizationName       X520OrganizationName]
   [id-at-organizationalUnitName X520OrganizationalUnitName]
   [id-at-title                  X520Title]
   [id-at-dnQualifier            X520dnQualifier]
   [id-at-countryName            X520countryName]
   [id-at-serialNumber           X520SerialNumber]
   [id-at-pseudonym              X520Pseudonym]
   [id-domainComponent           DomainComponent]
   ;; Legacy attributes
   [id-emailAddress              EmailAddress]))

(define-asn1-type AuthorityKeyIdentifier
  (SEQUENCE
   (keyIdentifier #:implicit 0 KeyIdentifier #:optional)
   (authorityCertIssuer #:implicit 1 GeneralNames #:optional)
   (authorityCertSerialNumber #:implicit 2 CertificateSerialNumber #:optional)))
(define-asn1-type KeyIdentifier OCTET-STRING)
(define-asn1-type SubjectKeyIdentifier KeyIdentifier)

;; Value, etc definitions
(define id-ce (OID (joint-iso-ccitt 2) (ds 5) 29))
(define id-ce-authorityKeyIdentifier (build-OID id-ce 35))
(define id-ce-subjectKeyIdentifier (build-OID id-ce 14))
(define id-ce-keyUsage (build-OID id-ce 15))
(define id-ce-privateKeyUsagePeriod (build-OID id-ce 16))
(define id-ce-certificatePolicies (build-OID id-ce 32))
(define anyPolicy (build-OID id-ce-certificatePolicies 0))
(define id-ce-policyMappings (build-OID id-ce 33))
(define id-ce-subjectAltName (build-OID id-ce 17))
(define id-ce-issuerAltName (build-OID id-ce 18))
(define id-ce-subjectDirectoryAttributes (build-OID id-ce 9))
(define id-ce-basicConstraints (build-OID id-ce 19))
(define id-ce-nameConstraints (build-OID id-ce 30))
(define id-ce-policyConstraints (build-OID id-ce 36))
(define id-ce-cRLDistributionPoints (build-OID id-ce 31))
(define id-ce-extKeyUsage (build-OID id-ce 37))
(define anyExtendedKeyUsage (build-OID id-ce-extKeyUsage 0))
(define id-kp-serverAuth (build-OID id-kp 1))
(define id-kp-clientAuth (build-OID id-kp 2))
(define id-kp-codeSigning (build-OID id-kp 3))
(define id-kp-emailProtection (build-OID id-kp 4))
(define id-kp-timeStamping (build-OID id-kp 8))
(define id-kp-OCSPSigning (build-OID id-kp 9))
(define id-ce-inhibitAnyPolicy (build-OID id-ce 54))
(define id-ce-freshestCRL (build-OID id-ce 46))
(define id-pe-authorityInfoAccess (build-OID id-pe 1))
(define id-pe-subjectInfoAccess (build-OID id-pe 11))
(define id-ce-cRLNumber (build-OID id-ce 20))
(define id-ce-issuingDistributionPoint (build-OID id-ce 28))
(define id-ce-deltaCRLIndicator (build-OID id-ce 27))
(define id-ce-cRLReasons (build-OID id-ce 21))
(define id-ce-certificateIssuer (build-OID id-ce 29))
(define id-ce-holdInstructionCode (build-OID id-ce 23))
(define holdInstruction (OID (joint-iso-itu-t 2) (member-body 2) (us 840) (x9cm 10040) 2))
(define id-holdinstruction-none (build-OID holdInstruction 1))
(define id-holdinstruction-callissuer (build-OID holdInstruction 2))
(define id-holdinstruction-reject (build-OID holdInstruction 3))
(define id-ce-invalidityDate (build-OID id-ce 24))



(define common-name 1)
(define teletex-common-name 2)
(define teletex-organization-name 3)
(define teletex-personal-name 4)
(define teletex-organizational-unit-names 5)
(define pds-name 7)
(define physical-delivery-country-name 8)
(define postal-code 9)
(define physical-delivery-office-name 10)
(define physical-delivery-office-number 11)
(define extension-OR-address-components 12)
(define physical-delivery-personal-name 13)
(define physical-delivery-organization-name 14)
(define extension-physical-delivery-address-components 15)
(define unformatted-postal-address 16)
(define street-address 17)
(define post-office-box-address 18)
(define poste-restante-address 19)
(define unique-postal-name 20)
(define local-postal-attributes 21)
(define extended-network-address 22)
(define terminal-type 23)
(define teletex-domain-defined-attributes 6)



(define KeyUsage
  (WRAP-NAMES BIT-STRING
   (list
    (cons 'digitalSignature 0)
    (cons 'nonRepudiation 1)
    (cons 'keyEncipherment 2)
    (cons 'dataEncipherment 3)
    (cons 'keyAgreement 4)
    (cons 'keyCertSign 5)
    (cons 'cRLSign 6)
    (cons 'encipherOnly 7)
    (cons 'decipherOnly 8))))

(define PrivateKeyUsagePeriod
  (SEQUENCE
   (notBefore #:implicit 0 GeneralizedTime #:optional)
   (notAfter #:implicit 1 GeneralizedTime #:optional)))

(define-asn1-type PolicyInformation
  (SEQUENCE
   (policyIdentifier CertPolicyId)
   (policyQualifiers (SEQUENCE-OF PolicyQualifierInfo) #:optional)))
(define-asn1-type CertPolicyId OBJECT-IDENTIFIER)
(define-asn1-type PolicyQualifierInfo
  (SEQUENCE
   (policyQualifierId PolicyQualifierId)
   (qualifier #:dependent (relation-ref POLICY-QUALIFIERS 'oid policyQualifierId 'type))))
(define-asn1-type PolicyQualifierId OBJECT-IDENTIFIER)

(define-asn1-type CertificatePolicies (SEQUENCE-OF PolicyInformation))
(define CPSuri IA5String)

(define-asn1-type UserNotice
  (SEQUENCE (noticeRef NoticeReference #:optional) (explicitText DisplayText #:optional)))
(define-asn1-type NoticeReference
  (SEQUENCE (organization DisplayText) (noticeNumbers (SEQUENCE-OF INTEGER))))
(define-asn1-type DisplayText
  (CHOICE
   (ia5String  IA5String)
   (visibleString VisibleString)
   (bmpString  BMPString)
   (utf8String  UTF8String)))

(define-asn1-type PolicyMappings
  (SEQUENCE-OF
   (SEQUENCE (issuerDomainPolicy CertPolicyId) (subjectDomainPolicy CertPolicyId))))

(define-asn1-type SubjectAltName GeneralNames)
(define-asn1-type GeneralNames (SEQUENCE-OF GeneralName))
(define-asn1-type GeneralName
  (CHOICE
   (otherName #:implicit 0 AnotherName)
   (rfc822Name #:implicit 1 IA5String)
   (dNSName #:implicit 2 IA5String)
   (x400Address #:implicit 3 ORAddress)
   (directoryName #:explicit 4 Name)
   (ediPartyName #:implicit 5 EDIPartyName)
   (uniformResourceIdentifier #:implicit 6 IA5String)
   (iPAddress #:implicit 7 OCTET-STRING)
   (registeredID #:implicit 8 OBJECT-IDENTIFIER)
   ;;/* Old names */
   (ip #:implicit 9 OCTET-STRING);  /* iPAddress */
   (dirn #:implicit 10 Name) ;; */
   (ia5 #:implicit 11 IA5String);;/* rfc822Name, dNSName,
                                 ;;* uniformResourceIdentifier */
   (rid #:implicit 12 OBJECT-IDENTIFIER)       ;;/* registeredID */
   (other #:implicit 13 ORAddress)     ;; /* x400Address */
         	#:extensible not-defined-general-name))
;; FIXME!!! here we have to find the missing definitions to have it clear extensible is only a dirty fix
(define-asn1-type AnotherName
  (SEQUENCE
   (type-id OBJECT-IDENTIFIER)
   (value #:explicit 0 (begin ANY #| DEFINED BY type-id |#))))
(define-asn1-type EDIPartyName
  (SEQUENCE
   (nameAssigner #:explicit 0 DirectoryString #:optional)
   (partyName #:explicit 1 DirectoryString)))
(define-asn1-type Name GeneralNames)

(define-asn1-type IssuerAltName GeneralNames)
(define-asn1-type SubjectDirectoryAttributes (SEQUENCE-OF Attribute))
(define-asn1-type BasicConstraints
  (SEQUENCE (cA BOOLEAN #:default #f) (pathLenConstraint INTEGER #:optional)))
(define-asn1-type NameConstraints
  (SEQUENCE
   (permittedSubtrees #:implicit 0 GeneralSubtrees #:optional)
   (excludedSubtrees #:implicit 1 GeneralSubtrees #:optional)))
(define-asn1-type GeneralSubtrees (SEQUENCE-OF GeneralSubtree))
(define-asn1-type GeneralSubtree
  (SEQUENCE
   (base GeneralName)
   (minimum #:implicit 0 BaseDistance #:default 0)
   (maximum #:implicit 1 BaseDistance #:optional)))
(define-asn1-type BaseDistance INTEGER)
(define-asn1-type PolicyConstraints
  (SEQUENCE
   (requireExplicitPolicy #:implicit 0 SkipCerts #:optional)
   (inhibitPolicyMapping #:implicit 1 SkipCerts #:optional)))
(define-asn1-type SkipCerts INTEGER)
(define-asn1-type CRLDistributionPoints (SEQUENCE-OF DistributionPoint))
(define-asn1-type DistributionPoint
  (SEQUENCE
   (distributionPoint #:explicit 0 DistributionPointName #:optional)
   (reasons #:implicit 1 ReasonFlags #:optional)
   (cRLIssuer #:implicit 2 GeneralNames #:optional)))
(define-asn1-type DistributionPointName
  (CHOICE
   (fullName #:implicit 0 GeneralNames)
   (nameRelativeToCRLIssuer #:implicit 1 RelativeDistinguishedName)))
(define-asn1-type ReasonFlags
  (WRAP-NAMES BIT-STRING
   (list
    (cons 'unused 0)
    (cons 'keyCompromise 1)
    (cons 'cACompromise 2)
    (cons 'affiliationChanged 3)
    (cons 'superseded 4)
    (cons 'cessationOfOperation 5)
    (cons 'certificateHold 6)
    (cons 'privilegeWithdrawn 7)
    (cons 'aACompromise 8))))
(define-asn1-type ExtKeyUsageSyntax (SEQUENCE-OF KeyPurposeId))
(define-asn1-type KeyPurposeId OBJECT-IDENTIFIER)
(define-asn1-type InhibitAnyPolicy SkipCerts)
(define-asn1-type FreshestCRL CRLDistributionPoints)
(define-asn1-type AuthorityInfoAccessSyntax (SEQUENCE-OF AccessDescription))
(define-asn1-type AccessDescription
  (SEQUENCE (accessMethod OBJECT-IDENTIFIER) (accessLocation GeneralName)))
(define-asn1-type SubjectInfoAccessSyntax (SEQUENCE-OF AccessDescription))
(define-asn1-type CRLNumber INTEGER)
(define-asn1-type IssuingDistributionPoint
  (SEQUENCE
   (distributionPoint #:explicit 0 DistributionPointName #:optional)
   (onlyContainsUserCerts #:implicit 1 BOOLEAN #:default #f)
   (onlyContainsCACerts #:implicit 2 BOOLEAN #:default #f)
   (onlySomeReasons #:implicit 3 ReasonFlags #:optional)
   (indirectCRL #:implicit 4 BOOLEAN #:default #f)
   (onlyContainsAttributeCerts #:implicit 5 BOOLEAN #:default #f)))
(define-asn1-type BaseCRLNumber CRLNumber)
(define-asn1-type CRLReason
  (WRAP-NAMES ENUMERATED
   (list
    (cons 'unspecified 0)
    (cons 'keyCompromise 1)
    (cons 'cACompromise 2)
    (cons 'affiliationChanged 3)
    (cons 'superseded 4)
    (cons 'cessationOfOperation 5)
    (cons 'certificateHold 6)
    (cons 'removeFromCRL 8)
    (cons 'privilegeWithdrawn 9)
    (cons 'aACompromise 10))))
(define-asn1-type CertificateIssuer GeneralNames)


(define-asn1-type HoldInstructionCode OBJECT-IDENTIFIER)
(define-asn1-type InvalidityDate GeneralizedTime)

(define EXTENSIONS
  (relation
   #:heading
   ['oid                              'type]
   #:tuples
   [id-ce-authorityKeyIdentifier      AuthorityKeyIdentifier]
   [id-ce-subjectKeyIdentifier        SubjectKeyIdentifier]
   [id-ce-keyUsage                    KeyUsage]
   [id-ce-certificatePolicies         CertificatePolicies]
   [id-ce-policyMappings              PolicyMappings]
   [id-ce-subjectAltName              SubjectAltName]
   [id-ce-issuerAltName               IssuerAltName]
   [id-ce-subjectDirectoryAttributes  SubjectDirectoryAttributes]
   [id-ce-basicConstraints            BasicConstraints]
   [id-ce-nameConstraints             NameConstraints]
   [id-ce-policyConstraints           PolicyConstraints]
   [id-ce-extKeyUsage                 ExtKeyUsageSyntax]
   [id-ce-cRLDistributionPoints       CRLDistributionPoints]
   [id-ce-inhibitAnyPolicy            InhibitAnyPolicy]
   [id-ce-freshestCRL                 CRLDistributionPoints]
   [id-pe-authorityInfoAccess         AuthorityInfoAccessSyntax]
   [id-pe-subjectInfoAccess           SubjectInfoAccessSyntax]
   ;; for CRLs only
   [id-ce-cRLNumber                   CRLNumber]
   [id-ce-deltaCRLIndicator           CRLNumber]
   [id-ce-issuingDistributionPoint    IssuingDistributionPoint]
   [id-ce-freshestCRL                 FreshestCRL]
   [id-ce-cRLReasons                  CRLReason]
   [id-ce-invalidityDate              InvalidityDate]
   [id-ce-certificateIssuer           CertificateIssuer]
   ))


(define Extension
  (SEQUENCE
   (extnID OBJECT-IDENTIFIER)
   (critical BOOLEAN #:default #f)
   (extnValue #:dependent (OCTET-STRING-containing
                           (relation-ref EXTENSIONS 'oid extnID 'type)))))

(define Extensions (SEQUENCE-OF Extension))


(define UniqueIdentifier BIT-STRING)

(define AttributeType OBJECT-IDENTIFIER)

(define (NameAttributeValue attr-oid)
  (or (relation-ref ATTRIBUTES 'oid attr-oid 'type) ANY))

(define (AttributeValue attr-oid)
  (or (relation-ref ATTRIBUTES 'oid attr-oid 'type) ANY))

(define NameAttribute
  (SEQUENCE
   (type AttributeType)
   (values #:dependent (SET-OF (AttributeValue type)))))
(define AttributeTypeAndValue
  (SEQUENCE
   (type AttributeType)
   (value #:dependent (NameAttributeValue type))))



(define Attribute
  (SEQUENCE
   (type AttributeType)
   (values #:dependent (SET-OF (AttributeValue type)))))









;;==============================================================
;; Miscelaneous definitions
;;==============================================================
;; from PKIX1Explicit-2009 (1.3.6.1.5.5.7.0.51)



(define POLICY-QUALIFIERS
  (relation
   #:heading
   ['oid            'type]
   #:tuples
   [id-qt-cps       CPSuri]
   [id-qt-unotice   UserNotice]))
(define-asn1-type ORAddress
  (SEQUENCE
   (built-in-standard-attributes BuiltInStandardAttributes)
   (built-in-domain-defined-attributes BuiltInDomainDefinedAttributes #:optional)
   (extension-attributes ExtensionAttributes #:optional)))

(define-asn1-type BuiltInStandardAttributes
  (SEQUENCE
   (country-name CountryName #:optional)
   (administration-domain-name AdministrationDomainName #:optional)
   (network-address #:implicit 0 NetworkAddress #:optional)
   (terminal-identifier #:implicit 1 TerminalIdentifier #:optional)
   (private-domain-name #:explicit 2 PrivateDomainName #:optional)
   (organization-name #:implicit 3 OrganizationName #:optional)
   (numeric-user-identifier #:implicit 4 NumericUserIdentifier #:optional)
   (personal-name #:implicit 5 PersonalName #:optional)
   (organizational-unit-names #:implicit 6 OrganizationalUnitNames #:optional)))

(define CountryName
  (TAG #:explicit #:application 1
       (CHOICE
        (x121-dcc-code NumericString)
        (iso-3166-alpha2-code PrintableString))))
(define AdministrationDomainName
  (TAG #:explicit #:application 2
       (CHOICE
        (numeric NumericString)
        (printable PrintableString))))
(define-asn1-type NetworkAddress X121Address)
(define X121Address NumericString)
(define TerminalIdentifier PrintableString)
(define PrivateDomainName
  (CHOICE (numeric NumericString) (printable PrintableString)))
(define OrganizationName PrintableString)
(define NumericUserIdentifier NumericString)
(define PersonalName
  (SET
   (surname #:implicit 0 PrintableString)
   (given-name #:implicit 1 PrintableString #:optional)
   (initials #:implicit 2 PrintableString #:optional)
   (generation-qualifier #:implicit 3 PrintableString #:optional)))

(define-asn1-type OrganizationalUnitNames (SEQUENCE-OF OrganizationalUnitName))
(define OrganizationalUnitName PrintableString)
(define RelativeDistinguishedName (SET-OF AttributeTypeAndValue))
(define RDNSequence (SEQUENCE-OF RelativeDistinguishedName))
(define-asn1-type CertName (CHOICE ;;-- only one possibility for now --
     [rdnSequence  RDNSequence]))


(define-asn1-type BuiltInDomainDefinedAttributes (SEQUENCE-OF BuiltInDomainDefinedAttribute))
(define BuiltInDomainDefinedAttribute
  (SEQUENCE (type PrintableString) (value PrintableString)))
(define-asn1-type ExtensionAttributes (SET-OF ExtensionAttribute))
(define-asn1-type ExtensionAttribute
  (SEQUENCE
   (extension-attribute-type #:implicit 0 INTEGER)
   (extension-attribute-value
    #:explicit 1 (begin ANY #| DEFINED BY extension-attribute-type |#))))



;; References
;; - RFC 5911 (CMS), 5912 (PKIX), 6268 (more CMS+PKIX)
;;   - updated asn1 modules for previous RFCs:
;;     - 3370, 3565, 3851, 3852, 4108, 4998, 5035, 5083, 5084, 5275
;;     - 2560, 2986, 3279, 3852, 4055, 4210, 4211, 5055, 5272, 5280, 5755
;;     - 3274, 3779, 6019, 4073, 4231, 4334, 5083, 5652, 5752
;; - RFC 5915: EC private key structure
;; - RFC 5958: PKCS #8 private key info
;; - RFC 7693: BLAKE2
;; - RFC 7914: scrypt
;; - RFC 8018: PKCS #5 password-based cryptography
;; - RFC 8103: Chacha20-Poly1305
;; - RFC 8410: {Ed,X}{25519,448}
;; - RFC 8692: PSS and ECDSA using SHAKEs
;; - NIST: AES, SHA2, SHA3
;;   - https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
;; - PKCS #3: DH
;;   - ftp://ftp.rsasecurity.com/pub/pkcs/ascii/pkcs-3.asc


;; ================================================================================
;; UTILITIES
;; ================================================================================


;; ============================================================
;; Relations


;; ================================================================================
;; ASN1 for Cryptography
;; ================================================================================



;; ============================================================
;; Types and Relations

;; ------------------------------------------------------------
;; PK Basic types

;; -- RSA

(define RSAPublicKey
  (SEQUENCE [modulus         INTEGER] ;; n
            [publicExponent  INTEGER])) ;; e

(define OtherPrimeInfo
  (SEQUENCE [prime             INTEGER] ;; ri
            [exponent          INTEGER] ;; di
            [coefficient       INTEGER])) ;; ti

(define OtherPrimeInfos
  (SEQUENCE-OF OtherPrimeInfo)) ;; SIZE(1..MAX)

(define RSAPrivateKey
  (SEQUENCE [version           INTEGER]
            [modulus           INTEGER] ;; n
            [publicExponent    INTEGER] ;; e
            [privateExponent   INTEGER] ;; d
            [prime1            INTEGER] ;; p
            [prime2            INTEGER] ;; q
            [exponent1         INTEGER] ;; d mod (p-1)
            [exponent2         INTEGER] ;; d mod (q-1)
            [coefficient       INTEGER] ;; (inverse of q) mod p
            [otherPrimeInfos   OtherPrimeInfos #:optional]))

(define RSA:Version:two-prime 0)
(define RSA:Version:multi 1) ;; version must be multi if otherPrimeInfos present

;; -- DSA

(define DSAPublicKey INTEGER) ;; public key, y

(define Dss-Parms
  (SEQUENCE [p   INTEGER]
            [q   INTEGER]
            [g   INTEGER]))

(define Dss-Sig-Value
  (SEQUENCE [r   INTEGER]
            [s   INTEGER]))

;; used by OpenSSL
(define DSAPrivateKey
  (SEQUENCE [version INTEGER] ;; = 0
            [p INTEGER]
            [q INTEGER]
            [g INTEGER]
            [y INTEGER]
            [x INTEGER]))

;; -- DH

(define DHPublicKey INTEGER) ;; public key, y = g^x mod p

(define ValidationParms
  (SEQUENCE [seed          BIT-STRING]
            [pgenCounter   INTEGER]))

(define DomainParameters
  (SEQUENCE [p       INTEGER] ;; odd prime, p=jq +1
            [g       INTEGER] ;; generator, g
            [q       INTEGER] ;; factor of p-1
            [j       INTEGER #:optional] ;; subgroup factor, j>= 2
            [validationParms  ValidationParms #:optional]))

(define DHParameter
  (SEQUENCE [prime INTEGER]
            [base INTEGER]
            [privateValueLength INTEGER #:optional]))

;; -- EC

;; EcpkParameters = SEC1 ECDomainParameters
;; ECParameters = SEC1 SpecifiedECDomain

(define ECDSA-Sig-Value
  (SEQUENCE [r     INTEGER]
            [s     INTEGER]))

(define EcpkParameters
  (CHOICE [namedCurve    OBJECT-IDENTIFIER]
          #; [ecParameters  ECParameters]
          #; [implicitlyCA  NULL]))

(define ECPoint OCTET-STRING)

(define ECPrivateKey
  (SEQUENCE [version        INTEGER] ;; ecPrivkeyVer1
            [privateKey     OCTET-STRING]
            [parameters #:explicit 0 EcpkParameters #:optional]
            [publicKey  #:explicit 1 (BIT-STRING-containing #f) #:default #f]))

(define ecPrivkeyVer1 1)

;; -- Misc

(define Attributes (SET-OF ANY/DER))

;; ------------------------------------------------------------
;; PK Algorithm Identifiers and Relations

(define (AlgorithmIdentifier rel [typefield 'params])
  (define (get-type algorithm)
    (or (relation-ref rel 'oid algorithm typefield)
        (WRAP ANY
              #:encode (lambda (v)
                         (internal-error "unknown algorithm OID: ~e" algorithm))
              #:decode (lambda (v) 'unknown))))
  (WRAP (SEQUENCE [algorithm              OBJECT-IDENTIFIER]
                  [parameters #:dependent (get-type algorithm) #:optional])))


(define AlgorithmIdentifier/DER
  (WRAP (SEQUENCE [algorithm  OBJECT-IDENTIFIER]
                  [parameters ANY/DER #:optional])))


(define PUBKEY
  ;; for SubjectPublicKeyInfo, PrivateKeyInfo, OneAsymmetricKey
  (relation
   #:heading
   ['oid            'params           'pubkey       'privkey]
   ;; pubkey=type means BER-encode pubkey as type, then wrap in bitstring;
   ;;   #f means pubkey is bytestring (ECPoint), wrap in bitstring w/o BER
   ;;   see BIT-STRING-containing
   #:tuples
   ;; From RFC 5912:
   [rsaEncryption   NULL #|absent|#   RSAPublicKey  RSAPrivateKey]
   [id-dsa          Dss-Parms         DSAPublicKey  INTEGER]
   ;; DH: PKIX says use dhpublicnumber; OpenSSL uses PKCS#3 OID
   [dhpublicnumber  DomainParameters  DHPublicKey   INTEGER]
   [dhKeyAgreement  DHParameter       DHPublicKey   INTEGER]
   ;; Special case!: the bitstring's octets are ECPoint, not a
   ;; BER-encoding of ECPoint
   [id-ecPublicKey  EcpkParameters    #f            ECPrivateKey]

   ;; From RFC 8410:
   ;; No wrapping for public key.
   [id-Ed25519      NULL #|absent|#   #f            OCTET-STRING]
   [id-Ed448        NULL #|absent|#   #f            OCTET-STRING]
   [id-X25519       NULL #|absent|#   #f            OCTET-STRING]
   [id-X448         NULL #|absent|#   #f            OCTET-STRING]
   ))

(define CURVES
  (let ()
    (define id-brainpool
      (OID (iso 1) (identified-organization 3) (teletrust 36) (algorithm 3)
           (signature-algorithm 3) (ecSign 2) 8 1 (versionOne 1)))
    (define c-TwoCurve (build-OID ansi-X9-62 (curves 3) (characteristicTwo 0)))
    (define primeCurve (build-OID ansi-X9-62 (curves 3) (prime 1)))
    ;; Note: Names correspond with canonical names (cf catalog, curve-aliases).
    ;; References: Curves from RFC 5480 (http://www.ietf.org/rfc/rfc5480.txt)
    ;; and SEC2 (http://www.secg.org/sec2-v2.pdf).
    (relation
     #:heading
     ['name      'oid]
     #:tuples
     ;; -- Prime-order fields --
     ['secp192k1 (build-OID certicom (curve 0) 31)]
     ['secp192r1 (build-OID ansi-X9-62 (curves 3) (prime 1) 1)]
     ['secp224k1 (build-OID certicom (curve 0) 32)]
     ['secp224r1 (build-OID certicom (curve 0) 33)]
     ['secp256k1 (build-OID certicom (curve 0) 10)]
     ['secp256r1 (build-OID ansi-X9-62 (curves 3) (prime 1) 7)]
     ['secp384r1 (build-OID certicom (curve 0) 34)]
     ['secp521r1 (build-OID certicom (curve 0) 35)]
     ;; -- Characteristic 2 fields --
     ['sect163k1 (build-OID certicom (curve 0) 1)]
     ['sect163r1 (build-OID certicom (curve 0) 2)]
     ['sect163r2 (build-OID certicom (curve 0) 15)]
     ['sect233k1 (build-OID certicom (curve 0) 26)]
     ['sect233r1 (build-OID certicom (curve 0) 27)]
     ['sect239k1 (build-OID certicom (curve 0) 3)]
     ['sect283k1 (build-OID certicom (curve 0) 16)]
     ['sect283r1 (build-OID certicom (curve 0) 17)]
     ['sect409k1 (build-OID certicom (curve 0) 36)]
     ['sect409r1 (build-OID certicom (curve 0) 37)]
     ['sect571k1 (build-OID certicom (curve 0) 38)]
     ['sect571r1 (build-OID certicom (curve 0) 39)]
     ;; Brainpool named curves
     ;; References: https://tools.ietf.org/html/rfc5639
     ['brainpoolP160r1 (build-OID id-brainpool 1)]
     ['brainpoolP160t1 (build-OID id-brainpool 2)]
     ['brainpoolP192r1 (build-OID id-brainpool 3)]
     ['brainpoolP192t1 (build-OID id-brainpool 4)]
     ['brainpoolP224r1 (build-OID id-brainpool 5)]
     ['brainpoolP224t1 (build-OID id-brainpool 6)]
     ['brainpoolP256r1 (build-OID id-brainpool 7)]
     ['brainpoolP256t1 (build-OID id-brainpool 8)]
     ['brainpoolP320r1 (build-OID id-brainpool 9)]
     ['brainpoolP320t1 (build-OID id-brainpool 10)]
     ['brainpoolP384r1 (build-OID id-brainpool 11)]
     ['brainpoolP384t1 (build-OID id-brainpool 12)]
     ['brainpoolP512r1 (build-OID id-brainpool 13)]
     ['brainpoolP512t1 (build-OID id-brainpool 14)]
     ;; Named Elliptic Curves in ANSI X9.62.
     ['c2pnb163v1 (build-OID c-TwoCurve  1)]
     ['c2pnb163v2 (build-OID c-TwoCurve  2)]
     ['c2pnb163v3 (build-OID c-TwoCurve  3)]
     ['c2pnb176w1 (build-OID c-TwoCurve  4)]
     ['c2tnb191v1 (build-OID c-TwoCurve  5)]
     ['c2tnb191v2 (build-OID c-TwoCurve  6)]
     ['c2tnb191v3 (build-OID c-TwoCurve  7)]
     ['c2onb191v4 (build-OID c-TwoCurve  8)]
     ['c2onb191v5 (build-OID c-TwoCurve  9)]
     ['c2pnb208w1 (build-OID c-TwoCurve 10)]
     ['c2tnb239v1 (build-OID c-TwoCurve 11)]
     ['c2tnb239v2 (build-OID c-TwoCurve 12)]
     ['c2tnb239v3 (build-OID c-TwoCurve 13)]
     ['c2onb239v4 (build-OID c-TwoCurve 14)]
     ['c2onb239v5 (build-OID c-TwoCurve 15)]
     ['c2pnb272w1 (build-OID c-TwoCurve 16)]
     ['c2pnb304w1 (build-OID c-TwoCurve 17)]
     ['c2tnb359v1 (build-OID c-TwoCurve 18)]
     ['c2pnb368w1 (build-OID c-TwoCurve 19)]
     ['c2tnb431r1 (build-OID c-TwoCurve 20)]
     ['prime192v1 (build-OID primeCurve  1)]
     ['prime192v2 (build-OID primeCurve  2)]
     ['prime192v3 (build-OID primeCurve  3)]
     ['prime239v1 (build-OID primeCurve  4)]
     ['prime239v2 (build-OID primeCurve  5)]
     ['prime239v3 (build-OID primeCurve  6)]
     ['prime256v1 (build-OID primeCurve  7)])))

(define (curve-oid->name oid)
  (relation-ref CURVES 'oid oid 'name))
(define (curve-name->oid name)
  (relation-ref CURVES 'name name 'oid))

;; ------------------------------------------------------------

(define AlgorithmIdentifier/PUBKEY (AlgorithmIdentifier PUBKEY))


(define (SPKI-PublicKey alg)
  (define alg-oid (hash-ref alg 'algorithm))
  (BIT-STRING-containing (relation-ref PUBKEY 'oid alg-oid 'pubkey)))

(define PrivateKeyInfo
  (SEQUENCE [version                   INTEGER]
            [privateKeyAlgorithm       AlgorithmIdentifier/PUBKEY]
            [privateKey #:dependent    (PrivateKey privateKeyAlgorithm)]
            [attributes #:implicit 0   Attributes #:optional]))

(define OneAsymmetricKey
  (SEQUENCE [version                   INTEGER]
            [privateKeyAlgorithm       AlgorithmIdentifier/PUBKEY]
            [privateKey #:dependent    (PrivateKey privateKeyAlgorithm)]
            [attributes #:implicit 0   Attributes #:optional]
            [publicKey  #:implicit 1   #:dependent (SPKI-PublicKey privateKeyAlgorithm)
                        #:default #f]))

(define (PrivateKey alg)
  (define alg-oid (hash-ref alg 'algorithm))
  (cond [(relation-ref PUBKEY 'oid alg-oid 'privkey)
         => (lambda (type)
              (WRAP OCTET-STRING
                    #:encode (lambda (v) (asn1->bytes/DER type v))
                    #:decode (lambda (v) (bytes->asn1/DER type v))))]
        [else OCTET-STRING]))


;; ------------------------------------------------------------
;; PKCS #5 Types and Relations

(define GCMParameters
  (SEQUENCE [aes-nonce          OCTET-STRING] ;; 12 octets
            [aes-ICVlen         INTEGER #:default 12]))

(define algid-hmacWithSHA1
  (hasheq 'algorithm id-hmacWithSHA1))

(define PBKDF2-PRFs
  (relation
   #:heading
   ['oid                 'params  'digest]
   #:tuples
   [id-hmacWithSHA1      NULL     'sha1]
   [id-hmacWithSHA224    NULL     'sha224]
   [id-hmacWithSHA256    NULL     'sha256]
   [id-hmacWithSHA384    NULL     'sha384]
   [id-hmacWithSHA512    NULL     'sha512]
   [id-hmacWithSHA512-224 NULL    'sha512/224]
   [id-hmacWithSHA512-256 NULL    'sha512/256]
   ;; Not "standard"!
   [id-hmacWithSHA3-224  NULL     'sha3-224]
   [id-hmacWithSHA3-256  NULL     'sha3-256]
   [id-hmacWithSHA3-384  NULL     'sha3-384]
   [id-hmacWithSHA3-512  NULL     'sha3-512]
   ))

(define PBKDF2-params
  (SEQUENCE
   [salt                OCTET-STRING] ;; actually, CHOICE with PBKDF2-SaltSources
   [iterationCount      INTEGER]
   [keyLength           INTEGER #:optional]
   [prf                 (AlgorithmIdentifier PBKDF2-PRFs)
                        #:default algid-hmacWithSHA1]))

(define scrypt-params ;; from scrypt-0
  (SEQUENCE
   [salt                OCTET-STRING]
   [costParameter       INTEGER]
   [blockSize           INTEGER]
   [parallelizationParameter INTEGER]
   [keyLength           INTEGER #:optional]))

;; -- PBES2

(define PBES2-KDFs
  (relation
   #:heading
   ['oid        'params]
   #:tuples
   [id-PBKDF2   PBKDF2-params]
   [id-scrypt   scrypt-params]))

(define PBES2-Encs
  (relation
   #:heading
   ['oid           'params       'spec]
   #:tuples
   [des-ede3-cbc   OCTET-STRING  '((des-ede3 cbc) 24)]
   [aes128-CBC-PAD OCTET-STRING  '((aes cbc) 16)]
   [aes192-CBC-PAD OCTET-STRING  '((aes cbc) 24)]
   [aes256-CBC-PAD OCTET-STRING  '((aes cbc) 32)]
   ;; Not "standard"!
   [id-aes128-GCM  GCMParameters '((aes gcm) 16)]
   [id-aes192-GCM  GCMParameters '((aes gcm) 24)]
   [id-aes256-GCM  GCMParameters '((aes gcm) 32)]
   [id-alg-AEADChaCha20Poly1305 OCTET-STRING '((chacha20-poly1305 stream) 32)]
   ))

(define PBES2-params
  (SEQUENCE
   [keyDerivationFunc   (AlgorithmIdentifier PBES2-KDFs)]
   [encryptionScheme    (AlgorithmIdentifier PBES2-Encs)]))

;; ------------------------------------------------------------
;; PKCS #8 (https://tools.ietf.org/html/rfc5208)

(define KeyEncryptionAlgorithms
  (relation
   #:heading
   ['oid        'params]
   #:tuples
   [id-PBES2    PBES2-params]))

(define EncryptedPrivateKeyInfo
  (SEQUENCE
   [encryptionAlgorithm  (AlgorithmIdentifier KeyEncryptionAlgorithms)]
   [encryptedData        OCTET-STRING]))

;; ============================================================

(define HASH ;; HashAlgs : DIGEST-ALGORITHM
  (relation
   #:heading
   ['oid          'digest     'params 'params-presence]
   #:tuples
   ;; RFC 5912
   [id-md5        'md5        NULL 'preferredAbsent]
   [id-sha1       'sha1       NULL 'preferredAbsent]
   [id-sha224     'sha224     NULL 'preferredAbsent]
   [id-sha256     'sha256     NULL 'preferredAbsent]
   [id-sha384     'sha384     NULL 'preferredAbsent]
   [id-sha512     'sha512     NULL 'preferredAbsent]

   ;; RFC 8692
   [id-shake128   'shake128   NULL 'absent] ;; output 32 bytes
   [id-shake256   'shake256   NULL 'absent] ;; output 64 bytes

   ;; NIST
   [id-sha512-224 'sha512/224 NULL 'preferredAbsent]
   [id-sha512-256 'sha512/256 NULL 'preferredAbsent]
   [id-sha3-224   'sha3-224   NULL 'preferredAbsent]
   [id-sha3-256   'sha3-256   NULL 'preferredAbsent]
   [id-sha3-384   'sha3-384   NULL 'preferredAbsent]
   [id-sha3-512   'sha3-512   NULL 'preferredAbsent]
   [id-shake128-len 'shake128 INTEGER 'present]
   [id-shake256-len 'shake256 INTEGER 'present]

   ;; RFC 7693 (BLAKE2)
   [id-blake2b160 'blake2b-160 NULL 'preferredAbsent]
   [id-blake2b256 'blake2b-256 NULL 'preferredAbsent]
   [id-blake2b384 'blake2b-384 NULL 'preferredAbsent]
   [id-blake2b512 'blake2b-512 NULL 'preferredAbsent]
   [id-blake2s128 'blake2s-128 NULL 'preferredAbsent]
   [id-blake2s160 'blake2s-160 NULL 'preferredAbsent]
   [id-blake2s224 'blake2s-224 NULL 'preferredAbsent]
   [id-blake2s256 'blake2s-256 NULL 'preferredAbsent]
   ))



(define CMSVersion INTEGER)