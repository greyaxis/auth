package auth

type Role string

const (
	RoleAuthorizedPerson      Role = "authorized_person"
	RoleReferralAssociate     Role = "referral_associate"
	RoleDigiGoldPartner       Role = "digi_gold_partner"
	RoleCustomer              Role = "customer"
	RoleAdmin                 Role = "admin"
	RolePublic                Role = "public"
	RoleDigitalBackOfficeUser Role = "role_digital_back_office_user"
)

func HasPermission(userRole Role, accessibleRoles []Role) bool {
	for _, role := range accessibleRoles {
		if userRole == role {
			return true
		}
	}
	return false
}
