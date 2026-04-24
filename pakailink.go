package pakailink

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/morkid/hc"
	"github.com/morkid/pakailink/internal"
)

// Config is the configuration for the PakaiLink client.
type Config struct {
	BaseURL            string    // Base URL
	PrivateKey         string    // Private Key
	PublicKey          string    // Public Key
	PartnerID          string    // Partner ID
	ClientKey          string    // Client Key
	ClientSecret       string    // Client Secret
	ChannelID          string    // Channel ID
	AccountNumber      string    // Account Number
	CallbackURLForVA   string    // Callback URL for VA
	CallbackURLForQRIS string    // Callback URL for QRIS
	QRISMerchantID     string    // QRIS Merchant ID
	QRISStoreID        string    // QRIS Store ID
	HTTPConfig         hc.Config // HTTP Config
}

// Bank is the bank code for PakaiLink.
type Bank string

var (
	// BankBCA code: 014
	BankBCA = Bank("014")
	// BankBRI code: 002
	BankBRI = Bank("002")
	// BankBNI code: 009
	BankBNI = Bank("009")
	// BankBSI code: 427
	BankBSI = Bank("427")
	// BankBTN code: 010
	BankBTN = Bank("010")
	// BankCIMB code: 022
	BankCIMB = Bank("022")
	// BankMandiri code: 008
	BankMandiri = Bank("008")
)

// VARequest is the request for creating a virtual account.
type VARequest struct {
	ID            string  `json:"id" format:"uuid"`
	CustomerID    string  `json:"customer_id" example:"131857418122353"`
	CustomerName  string  `json:"customer_name" example:"Pembayaran Test "`
	CustomerPhone string  `json:"customer_phone" example:"081999999999"`
	Amount        float64 `json:"amount" example:"100000.0"`
	Currency      string  `json:"currency" example:"IDR"`
	BankCode      Bank    `json:"bank_code" example:"014"`
	CallbackURL   string  `json:"callback_url" example:"http://callback/url"`
}

// ToMap converts the VARequest to a map.
func (v *VARequest) ToMap() map[string]any {
	if v.CallbackURL == "" {
		v.CallbackURL = "http://callback/url"
	}

	return map[string]any{
		"partnerReferenceNo":  v.ID,
		"customerNo":          v.CustomerID,
		"virtualAccountName":  v.CustomerName,
		"virtualAccountPhone": v.CustomerPhone,
		"totalAmount": Balance{
			Currency: v.Currency,
			Value:    &DecimalFloat{big.NewFloat(v.Amount)},
		},
		"additionalInfo": AdditionalInfo{
			CallbackURL: v.CallbackURL,
			BankCode:    v.BankCode,
		},
	}
}

// VAResponse is the response for creating a virtual account.
type VAResponse struct {
	BaseResponse
	VirtualAccountData VAData `json:"virtualAccountData"`
}

// VAData is the data for the virtual account.
type VAData struct {
	AdditionalInfo     AdditionalInfo `json:"additionalInfo"`
	CustomerNo         string         `json:"customerNo" example:"131857418122353"`
	ExpiredDate        time.Time      `json:"expiredDate" example:"2022-01-01T00:00:00+07:00"`
	PartnerReferenceNo string         `json:"partnerReferenceNo" example:"vg9QJ0oABHXufO1tkV2UhroVpBFX3L9nkn9T"`
	TotalAmount        Balance        `json:"totalAmount" example:"100000.0"`
	VirtualAccountNo   string         `json:"virtualAccountNo" example:"391072020012345"`
}

// AdditionalInfo is the additional information for the virtual account.
type AdditionalInfo struct {
	CallbackURL  string   `json:"callbackUrl,omitempty" example:"http://callback/url"`
	Callback     string   `json:"callback,omitempty" example:"http://callback/url"`
	BankCode     Bank     `json:"bankCode,omitempty" example:"014"`
	ReferenceNo  string   `json:"referenceNo,omitempty" example:"131857418122353"`
	NominalPaid  *Balance `json:"nominalPaid,omitempty"`
	ServiceFee   *Balance `json:"serviceFee,omitempty"`
	TotalPaid    *Balance `json:"totalPaid,omitempty"`
	TotalReceive *Balance `json:"totalReceive,omitempty"`
	MDR          *Balance `json:"mdr,omitempty"`
	CustomerData string   `json:"customerData,omitempty" example:"DOMPAY SANDBOX"`
	RRN          string   `json:"rrn,omitempty" example:"1234567890"`
	Issuer       string   `json:"issuer,omitempty" example:""`
	Payor        string   `json:"payor,omitempty" example:""`
}

// BaseResponse is the base response for all API responses.
type BaseResponse struct {
	ResponseCode    string `json:"responseCode" example:"2001100"`
	ResponseMessage string `json:"responseMessage" example:"Successful"`
}

// ErrorResponse is the error response for all API errors.
type ErrorResponse struct {
	BaseResponse
	AdditionalInfo json.RawMessage `json:"additionalInfo" example:"Invalid response"`
}

// Balance is the balance response.
type Balance struct {
	Currency string        `json:"currency" example:"IDR"`
	Value    *DecimalFloat `json:"value" example:"100000.00"`
}

// QRISResponse is the response for creating a QRIS.
type QRISResponse struct {
	BaseResponse
	Amount             Balance `json:"amount"`
	MerchantName       string  `json:"merchantName" example:"DOMPAY SANDBOX"`
	PartnerReferenceNo string  `json:"partnerReferenceNo" example:"3586be11-1fbe-4e7c-a0da-8c70e0677535"`
	QRContent          string  `json:"qrContent" example:"923023-2943.CO.SANBOX.WWW7233535800110000063204021012126070280303UKE51440014ID.CO.QRIS.WWW0215LQ12309846890140303UKE6294010900000004602120812345678900517LINKQUPAYREQ105160609test qris0709LI726MIGG99140002000104852453033605405255676008SIDOARJO520459995915"`
	ReferenceNo        string  `json:"referenceNo" example:"QRA177692990601690604684815"`
	StoreID            string  `json:"storeID" example:"STORE22"`
	TerminalID         string  `json:"terminalID" example:"ID1024361878720"`
	ValidityPeriod     string  `json:"validityPeriod" example:"20260424153826"`
}

// GetExpirationTime Get QRIS Code expiration time
func (q *QRISResponse) GetExpirationTime() (exp *time.Time) {
	t, err := time.Parse("20060102150405", q.ValidityPeriod)
	if err == nil {
		exp = &t
	}

	return exp
}

// DecimalFloat is the decimal float response.
type DecimalFloat struct {
	*big.Float
}

// MarshalJSON converts the DecimalFloat to a JSON string.
func (d *DecimalFloat) MarshalJSON() ([]byte, error) {
	floatVal, _ := d.Float64()
	return fmt.Appendf(nil, `"%.2f"`, floatVal), nil
}

// UnmarshalJSON converts a JSON string to a DecimalFloat.
func (d *DecimalFloat) UnmarshalJSON(data []byte) (err error) {
	str := string(data)
	str = str[1 : len(str)-1] // Remove quotes
	f, _, err := big.ParseFloat(str, 10, 2, big.ToNearestEven)
	if err == nil {
		d.Float = f
	}

	return
}

// AccountInfoResponse is the response from the account info endpoint.
type AccountInfoResponse struct {
	ActiveBalance Balance `json:"activeBalance"`
	BalanceType   string  `json:"balanceType" example:"Balance"`
	FreezeBalance Balance `json:"freezeBalance"`
	HoldBalance   Balance `json:"holdBalance"`
	Status        string  `json:"status" example:"0001"`
}

// BalanceResponse is the response from the balance endpoint.
type BalanceResponse struct {
	BaseResponse
	ReferenceNo        string                `json:"referenceNo" example:"INQ175307299959777708712406"`
	PartnerReferenceNo string                `json:"partnerReferenceNo" example:"vg9QJ0oABHXufO1tkV2UhroVpBFX3L9nkn9T"`
	AccountNo          string                `json:"accountNo" example:"0310122755265432"`
	Name               string                `json:"name" example:"Merchant Internal"`
	AccountInfo        []AccountInfoResponse `json:"accountInfo"`
}

// TransactionStatusResponse is the response from the VA status endpoint.
type TransactionStatusResponse struct {
	BaseResponse
	AdditionalInfo             AdditionalInfo `json:"additionalInfo"`
	Amount                     Balance        `json:"amount"`
	LatestTransactionStatus    string         `json:"latestTransactionStatus,omitempty" example:"01"`
	OriginalExternalID         string         `json:"originalExternalId,omitempty" example:"06ffceaf-365c-4150-bf14-c8b0906e7106"`
	OriginalPartnerReferenceNo string         `json:"originalPartnerReferenceNo,omitempty" example:"06ffceaf-365c-4150-bf14-c8b0906e7106"`
	OriginalReferenceNo        string         `json:"originalReferenceNo,omitempty" example:"9755794030382667748"`
	PaidTime                   string         `json:"paidTime,omitempty" format:"date-time"`
	ResponseCode               string         `json:"responseCode,omitempty" example:"2003300"`
	ResponseMessage            string         `json:"responseMessage,omitempty" example:"Successful"`
	ServiceCode                string         `json:"serviceCode,omitempty" example:"35"`
	TransactionDate            time.Time      `json:"transactionDate,omitzero" format:"date-time"`
	TransactionStatusDesc      string         `json:"transactionStatusDesc,omitempty" example:"Initiated"`
}

// IsPaid checks if the transaction is paid.
func (t *TransactionStatusResponse) IsPaid() bool {
	return t.GetPaidTime() != nil
}

// GetPaidTime returns the paid time if the transaction is paid, otherwise returns nil.
func (t *TransactionStatusResponse) GetPaidTime() (paidTime *time.Time) {
	if t.PaidTime != "" {
		var err error
		var paidAt time.Time
		paidAt, err = time.Parse(time.RFC3339, t.PaidTime)
		if err == nil {
			paidTime = &paidAt
		}
	}

	return
}

// CallbackData is the data from the callback.
type CallbackData struct {
	TransactionData CallbackDataDetail `json:"transactionData"`
}

// CallbackDataDetail is the detail of the callback data.
type CallbackDataDetail struct {
	BaseResponse
	AdditionalInfo             AdditionalInfo `json:"additionalInfo"`
	CallbackType               string         `json:"callbackType" example:"payment"`
	CreditBalance              Balance        `json:"creditBalance"`
	CustomerNo                 string         `json:"customerNo" example:"CUST00000000001"`
	FeeAmount                  Balance        `json:"feeAmount"`
	PaidAmount                 Balance        `json:"paidAmount"`
	PartnerReferenceNo         string         `json:"partnerReferenceNo" example:"b5a4294d-0ce9-4cfc-bc64-028996947eff"`
	PaymentFlagReason          Reason         `json:"paymentFlagReason"`
	PaymentFlagStatus          string         `json:"paymentFlagStatus" example:"00"`
	ReferenceNo                string         `json:"referenceNo" example:"VAI177701711033881604990215"`
	VirtualAccountName         string         `json:"virtualAccountName" example:"Harmony - Pembayaran Test "`
	VirtualAccountNo           string         `json:"virtualAccountNo" example:"0198230123809091"`
	VirtualAccountTrxType      string         `json:"virtualAccountTrxType" example:"C"`
	Amount                     Balance        `json:"amount"`
	CreatedTime                string         `json:"createdTime,omitempty"`
	FinishedTime               time.Time      `json:"finishedTime,omitempty"`
	LatestTransactionStatus    string         `json:"latestTransactionStatus,omitempty" example:"00"`
	OriginalExternalID         string         `json:"originalExternalId,omitempty" example:"6e893132-5159-4589-aa29-22e0250ceef0"`
	OriginalPartnerReferenceNo string         `json:"originalPartnerReferenceNo,omitempty" example:"6e893132-5159-4589-aa29-22e0250ceef0"`
	OriginalReferenceNo        string         `json:"originalReferenceNo,omitempty" example:"8326154965638343026"`
	ServiceCode                string         `json:"serviceCode,omitempty" example:"52"`
	TransactionStatusDesc      string         `json:"transactionStatusDesc,omitempty" example:"payment_success"`
}

// Reason is the reason for the payment flag.
type Reason struct {
	English   string `json:"english" example:"Success"`
	Indonesia string `json:"indonesia" example:"Sukses"`
}

// accessToken is the access token response.
type accessToken struct {
	AccessToken string `json:"accessToken"`
}

// PakaiLink is the main struct for the PakaiLink API.
type PakaiLink struct {
	Config     Config
	httpClient *http.Client
}

// CreateVA creates a virtual account.
func (p *PakaiLink) CreateVA(req VARequest) (va VAData, err error) {
	req.CallbackURL = p.Config.CallbackURLForVA

	var res *http.Response
	res, err = p.request("/snap/v1.0/transfer-va/create-va", req.ToMap(), req.ID)
	if err == nil {
		out := unmarshalResponse(res, VAResponse{})
		va = out.VirtualAccountData
	}

	return
}

// GetVAStatus gets the status of a virtual account.
func (p *PakaiLink) GetVAStatus(id string) (va TransactionStatusResponse, err error) {
	var res *http.Response
	reqMap := map[string]any{
		"originalPartnerReferenceNo": id,
	}
	res, err = p.request("/snap/v1.0/transfer-va/create-va-status", reqMap, uuid.NewString())
	if err == nil {
		va = unmarshalResponse(res, TransactionStatusResponse{})
	}

	return
}

// CreateQRIS Create QRIS MPM Code
func (p *PakaiLink) CreateQRIS(id string, amount float64, expiredAt ...time.Time) (qris QRISResponse, err error) {
	expiration := ""
	if len(expiredAt) > 0 {
		expiration = expiredAt[0].Format(time.RFC3339)
	}

	req := map[string]any{
		"merchantId":         p.Config.QRISMerchantID,
		"storeId":            p.Config.QRISStoreID,
		"terminalId":         "ID" + randomNumber(12),
		"partnerReferenceNo": id,
		"amount": Balance{
			Value:    &DecimalFloat{big.NewFloat(amount)},
			Currency: "IDR",
		},
		"validityPeriod": expiration,
		"additionalInfo": AdditionalInfo{
			CallbackURL: p.Config.CallbackURLForQRIS,
		},
	}

	var res *http.Response
	res, err = p.request("/snap/v1.0/qr/qr-mpm-generate", req, id)
	if err == nil {
		qris = unmarshalResponse(res, QRISResponse{})
	}

	return
}

// GetQRISStatus gets the status of a QRIS transaction.
func (p *PakaiLink) GetQRISStatus(id string) (qris TransactionStatusResponse, err error) {
	var res *http.Response
	reqMap := map[string]any{
		"originalPartnerReferenceNo": id,
	}
	res, err = p.request("/snap/v1.0/qr/qr-mpm-status", reqMap, uuid.NewString())
	if err == nil {
		qris = unmarshalResponse(res, TransactionStatusResponse{})
	}

	return
}

// GetBalance gets the balance.
func (p *PakaiLink) GetBalance() (balance float64, err error) {
	id := uuid.NewString()

	req := map[string]any{
		"partnerReferenceNo": id,
		"accountNo":          p.Config.AccountNumber,
		"balanceTypes":       []string{"BALANCE"},
	}

	var res *http.Response
	res, err = p.request("/snap/v1.0/balance-inquiry", req, id)
	if err == nil {
		bal := unmarshalResponse(res, BalanceResponse{})
		for _, v := range bal.AccountInfo {
			if v.BalanceType == "Balance" && v.ActiveBalance.Value != nil {
				balance, _ = v.ActiveBalance.Value.Float64()
				break
			}
		}
	}

	return
}

// ValidateSignature validates the signature.
func (p *PakaiLink) ValidateSignature(signature, body string) error {
	return internal.SHA256WithRSAValidate(p.Config.PublicKey, body, signature)
}

func (p *PakaiLink) getToken() (token string, err error) {
	tstamp := time.Now().Format(time.RFC3339Nano)
	var req *http.Request
	var res *http.Response

	uri := fmt.Sprintf("%s%s", p.Config.BaseURL, "/snap/v1.0/access-token/b2b")
	req, err = http.NewRequest(
		"POST", uri, strings.NewReader(`{"grantType":"client_credentials"}`))

	if err == nil {
		req.Header.Add("X-TIMESTAMP", tstamp)
		req.Header.Add("Content-type", "application/json;charset=utf-8")
		req.Header.Add("X-CLIENT-KEY", p.Config.ClientKey)
		strAuthSig := ""
		strAuthSig, err = internal.SHA256WithRSA(
			p.Config.PrivateKey, p.Config.ClientKey+"|"+tstamp)

		req.Header.Add("X-SIGNATURE", strAuthSig)

		if err == nil {
			res, err = p.client().Do(req)
		}

		if err == nil {
			out := unmarshalResponse(res, accessToken{})
			token = out.AccessToken
		}
	}

	return
}

func (p *PakaiLink) request(path string, body any, requestID string) (res *http.Response, err error) {
	date := time.Now()
	tstamp := date.Format(time.RFC3339Nano)

	var jsonBody []byte
	var req *http.Request

	jsonBody, err = json.Marshal(body)

	if err == nil {
		uri := fmt.Sprintf("%s%s", p.Config.BaseURL, path)
		req, err = http.NewRequest("POST", uri, bytes.NewReader(jsonBody))
	}

	var token string

	if err == nil {
		token, err = p.getToken()
	}

	var sig string

	if err == nil {
		sig, err = GenerateTransactionSignature("POST", path, token, jsonBody, tstamp, p.Config.ClientSecret)
	}

	if err == nil {

		req.Header.Add("Content-type", "application/json;charset=utf-8")
		req.Header.Add("Authorization", "Bearer "+token)
		req.Header.Add("X-EXTERNAL-ID", requestID)
		req.Header.Add("CHANNEL-ID", p.Config.ChannelID)
		req.Header.Add("X-PARTNER-ID", p.Config.PartnerID)
		req.Header.Add("X-TIMESTAMP", tstamp)
		req.Header.Add("X-SIGNATURE", sig)

		res, err = p.client().Do(req)
	}

	if res != nil && res.StatusCode >= 400 {

		bodyBytes, _ := io.ReadAll(res.Body)
		res.Body.Close()
		res.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		out := map[string]any{}
		err = json.Unmarshal(bodyBytes, &out)

		if err != nil {
			re := regexp.MustCompile("}{")
			if re.Match(bodyBytes) {
				var errResponses struct {
					Errors []ErrorResponse `json:"errors"`
				}
				bodyString := string(bodyBytes)
				bodyString = fmt.Sprintf(`{"errors":[%s]}`, strings.ReplaceAll(bodyString, "}{", "},{"))
				e := json.Unmarshal([]byte(bodyString), &errResponses)
				if e == nil {
					out["errors"] = errResponses.Errors
				} else {
					json.Unmarshal([]byte(bodyString), &out)
				}
			}
		}

		err = NewHTTPLog(
			"CREATE_VA",
			req.Method,
			req.URL.String(),
			body,
			out,
			res.StatusCode,
			req.Header,
		)
	}

	return
}

func (p *PakaiLink) client() *http.Client {
	if p.httpClient == nil {
		p.httpClient = hc.New(p.Config.HTTPConfig)
	}

	return p.httpClient
}

// New creates a new PakaiLink instance.
func New(config Config) *PakaiLink {
	return &PakaiLink{Config: config}
}

// HTTPLog is the log for HTTP requests.
type HTTPLog struct {
	Tag          string            `json:"tag"`
	URL          string            `json:"url"`
	Method       string            `json:"method"`
	StatusCode   int               `json:"status_code"`
	Headers      map[string]string `json:"headers"`
	RequestBody  any               `json:"request_body"`
	ResponseBody any               `json:"response_body"`
}

// Error returns the error message.
func (z *HTTPLog) Error() string {
	return fmt.Sprintf("%v", z.ResponseBody)
}

// New creates a new HTTPLog.
func (z *HTTPLog) New(tag, method, url string, req, res any, status int, headers http.Header) *HTTPLog {
	z.Tag = tag
	z.Method = method
	z.URL = url
	z.RequestBody = req
	z.ResponseBody = res
	z.StatusCode = status

	if headers != nil {
		header := map[string]string{}
		for k, v := range headers {
			header[k] = strings.Join(v, ",")
		}
		z.Headers = header
	}

	return z
}

// NewHTTPLog creates a new HTTPLog.
func NewHTTPLog(tag, method, url string, req, res any, status int, headers http.Header) *HTTPLog {
	httpLog := new(HTTPLog)
	return httpLog.New(tag, method, url, req, res, status, headers)
}

// GenerateTransactionSignature generates a transaction signature.
func GenerateTransactionSignature(
	method string,
	endpoint string,
	accessToken string,
	requestBody any,
	timestamp string,
	secretKey string,
) (sig string, err error) {
	var jsonBody []byte

	if str, ok := requestBody.(string); ok {
		jsonBody = []byte(str)
	} else if bte, ok := requestBody.([]byte); ok {
		jsonBody = bte
	} else {
		jsonBody, err = json.Marshal(requestBody)
	}

	if err == nil {
		hash := sha256.Sum256(jsonBody)
		hashHex := hex.EncodeToString(hash[:])
		stringToSign := strings.Join([]string{
			method,
			endpoint,
			accessToken,
			strings.ToLower(hashHex),
			timestamp,
		}, ":")

		mac := hmac.New(sha512.New, []byte(secretKey))
		mac.Write([]byte(stringToSign))

		sig = base64.StdEncoding.EncodeToString(mac.Sum(nil))
	}

	return
}

func unmarshalResponse[T any](res *http.Response, out T) T {
	var err error
	var body []byte
	body, err = io.ReadAll(res.Body)
	if err == nil {
		defer res.Body.Close()
		json.Unmarshal(body, &out)
	}

	return out
}

// randomNumber generates a random number with the specified length.
func randomNumber(len int) string {
	return fmt.Sprintf("%d", rand.Intn(10^len))
}
