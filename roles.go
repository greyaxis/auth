package auth

type Role string

const (
	RoleAuthorizedPerson  Role = "authorized_person"
	RoleReferralAssociate Role = "referral_associate"
	RoleCustomer          Role = "customer"
	RoleAdmin             Role = "admin"
	RoleDBOAdmin          Role = "dbo_admin"
)
