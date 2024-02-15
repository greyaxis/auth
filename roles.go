package auth

type Role string

const (
	RoleAuthorizedPerson      Role = "authorized_person"
	RoleReferralAssociate     Role = "referral_associate"
	RoleDigiGoldPartner       Role = "digi_gold_partner"
	RoleCustomer              Role = "customer"
	RoleAdmin                 Role = "admin"
	RoleDigitalBackOfficeUser Role = "role_digital_back_office_user"
)
