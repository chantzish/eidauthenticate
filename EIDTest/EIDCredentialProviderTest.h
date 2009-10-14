void Menu_CREDENTIALUID();
void Menu_CREDENTIALUID_ADMIN();
void Menu_CREDENTIALUID_ONLY_EID();
void menu_CREDENTIALUID_OldBehavior();
void menu_CRED_COM();
void menu_ResetPasswordWizard();

enum AuthenticationType
{
	LSA,
	SSPI,
	CredSSP,
};

void SetAuthentication(AuthenticationType type);