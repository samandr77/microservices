package repository

const (
	selectTx = `SELECT 
		id,
		name,
		number,
		client_id,
		client_guid,
		amount,
		payment_method,
		status,
		qrc_id,
		invoice_url,
		created_by,
		created_at, 
		updated_at 
	FROM transactions`
)
