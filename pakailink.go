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
	BaseURL          string    // Base URL
	PrivateKey       string    // Private Key
	PublicKey        string    // Public Key
	PartnerID        string    // Partner ID
	ClientKey        string    // Client Key
	ClientSecret     string    // Client Secret
	ChannelID        string    // Channel ID
	AccountNumber    string    // Account Number
	CallbackURLForVA string    // Callback URL for VA
	HTTPConfig       hc.Config // HTTP Config
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
	ID            uuid.UUID `json:"id" format:"uuid"`
	CustomerID    string    `json:"customer_id" example:"131857418122353"`
	CustomerName  string    `json:"customer_name" example:"Pembayaran Test "`
	CustomerPhone string    `json:"customer_phone" example:"081999999999"`
	Amount        float64   `json:"amount" example:"100000.0"`
	Currency      string    `json:"currency" example:"IDR"`
	BankCode      Bank      `json:"bank_code" example:"014"`
	CallbackURL   string    `json:"callback_url" example:"http://callback/url"`
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
		"additionalInfo": AdditionalVaInfo{
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
	AdditionalInfo     AdditionalVaInfo `json:"additionalInfo"`
	CustomerNo         string           `json:"customerNo" example:"131857418122353"`
	ExpiryDate         time.Time        `json:"expiryDate" example:"2022-01-01T00:00:00+07:00"`
	PartnerReferenceNo string           `json:"partnerReferenceNo" example:"vg9QJ0oABHXufO1tkV2UhroVpBFX3L9nkn9T"`
	TotalAmount        Balance          `json:"totalAmount" example:"100000.0"`
	VirtualAccountNo   string           `json:"virtualAccountNo" example:"391072020012345"`
}

// AdditionalVaInfo is the additional information for the virtual account.
type AdditionalVaInfo struct {
	CallbackURL string `json:"callbackUrl,omitempty" example:"http://callback/url"`
	BankCode    Bank   `json:"bankCode,omitempty" example:"014"`
	ReferenceNo string `json:"referenceNo,omitempty" example:"131857418122353"`
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
	res, err = p.request("/snap/v1.0/transfer-va/create-va", req.ToMap(), req.ID.String())
	if err == nil {
		out := unmarshalResponse(res, VAResponse{})
		va = out.VirtualAccountData
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
