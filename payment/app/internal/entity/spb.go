package entity

type SPBPaymentStatus string

const (
	SPBPaymentStatusNotStarted SPBPaymentStatus = "NTST"
	SPBPaymentStatusStarted    SPBPaymentStatus = "RCVD"
	SPBPaymentStatusPaid       SPBPaymentStatus = "ACWP"
	SPBPaymentStatusRejected   SPBPaymentStatus = "RJCT"
)

type CardPaymentStatus string

const (
	CardPaymentStatusRegistered             CardPaymentStatus = "REGISTERED"              // 0 - заказ зарегистрирован, но не оплачен
	CardPaymentStatusAuthorizedPending      CardPaymentStatus = "AUTHORIZED_PENDING"      // 1 - заказ только авторизован и еще не завершен
	CardPaymentStatusAuthorizedCompleted    CardPaymentStatus = "AUTHORIZED_COMPLETED"    // 2 - заказ авторизован и завершен
	CardPaymentStatusAuthorizationCancelled CardPaymentStatus = "AUTHORIZATION_CANCELLED" // 3 - авторизация отменена
	CardPaymentStatusRefunded               CardPaymentStatus = "REFUNDED"                // 4 - по транзакции была проведена операция возврата
	CardPaymentStatusACSInitiated           CardPaymentStatus = "ACS_INITIATED"           // 5 - инициирована авторизация через ACS банка-эмитента
	CardPaymentStatusAuthorizationDeclined  CardPaymentStatus = "AUTHORIZATION_DECLINED"  // 6 - авторизация отклонена
	CardPaymentStatusWaitingPayment         CardPaymentStatus = "WAITING_PAYMENT"         // 7 - ожидание оплаты заказа
	CardPaymentStatusIntermediateCompleted  CardPaymentStatus = "INTERMEDIATE_COMPLETED"  // 8 - промежуточное завершение для многократного частичного завершения
)

func (s SPBPaymentStatus) String() string {
	return string(s)
}

type SPBLink struct {
	QrcID     string           `json:"qrcId"`
	Payload   string           `json:"payload"`
	Status    SPBPaymentStatus `json:"status"`
	Image     Image            `json:"image"`
	OrderID   string           `json:"orderId"`
	RequestID string           `json:"requestId"`
}

type Image struct {
	MediaType string `json:"mediaType"`
	Content   string `json:"content"`
}
