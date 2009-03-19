enum GPOPolicy
{
  AllowSignatureOnlyKeys,
  AllowCertificatesWithNoEKU,
  AllowTimeInvalidCertificates,
  AllowIntegratedUnblock,
  ReverseSubject,
  X509HintsNeeded,
  IntegratedUnblockPromptString,
  CertPropEnabledString,
  CertPropRootEnabledString,
  RootsCleanupOption,
  FilterDuplicateCertificates,
  ForceReadingAllCertificates,
  scforceoption,
} ;


DWORD GetPolicyValue(GPOPolicy Policy);
