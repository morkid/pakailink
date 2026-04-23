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
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/morkid/hc"
	"github.com/morkid/pakailink/internal"
)

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
	HttpConfig       hc.Config // HTTP Config
}

type PakaiLinkBank string

var (
	BANK_BCA     = PakaiLinkBank("014")
	BANK_BRI     = PakaiLinkBank("002")
	BANK_BNI     = PakaiLinkBank("009")
	BANK_BSI     = PakaiLinkBank("427")
	BANK_BTN     = PakaiLinkBank("010")
	BANK_CIMB    = PakaiLinkBank("022")
	BANK_MANDIRI = PakaiLinkBank("008")
)

type VARequest struct {
	ID            uuid.UUID     `json:"id" format:"uuid"`
	CustomerID    string        `json:"customer_id" example:"131857418122353"`
	CustomerName  string        `json:"customer_name" example:"Pembayaran Test "`
	CustomerPhone string        `json:"customer_phone" example:"081999999999"`
	Amount        float64       `json:"amount" example:"100000.0"`
	Currency      string        `json:"currency" example:"IDR"`
	BankCode      PakaiLinkBank `json:"bank_code" example:"014"`
	CallbackURL   string        `json:"callback_url" example:"http://callback/url"`
}

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
			Value:    v.Amount,
		},
		"additionalInfo": AdditionalVaInfo{
			CallbackURL: v.CallbackURL,
			BankCode:    v.BankCode,
		},
	}
}

type VAResponse struct {
	BaseResponse
	VirtualAccountData VAData `json:"virtualAccountData"`
}

type VAData struct {
	AdditionalInfo     AdditionalVaInfo `json:"additionalInfo"`
	CustomerNo         string           `json:"customerNo" example:"131857418122353"`
	ExpiryDate         time.Time        `json:"expiryDate" example:"2022-01-01T00:00:00+07:00"`
	PartnerReferenceNo string           `json:"partnerReferenceNo" example:"vg9QJ0oABHXufO1tkV2UhroVpBFX3L9nkn9T"`
	TotalAmount        Balance          `json:"totalAmount" example:"100000.0"`
	VirtualAccountNo   string           `json:"virtualAccountNo" example:"391072020012345"`
}

type AdditionalVaInfo struct {
	CallbackURL string        `json:"callback_url,omitempty" example:"http://callback/url"`
	BankCode    PakaiLinkBank `json:"bank_code,omitempty" example:"014"`
	ReferenceNo string        `json:"reference_no,omitempty" example:"131857418122353"`
}

type BaseResponse struct {
	ResponseCode    string `json:"responseCode" example:"2001100"`
	ResponseMessage string `json:"responseMessage" example:"Successful"`
}

type ErrorResponse struct {
	BaseResponse
	AdditionalInfo json.RawMessage `json:"additionalInfo" example:"Invalid response"`
}

type Balance struct {
	Currency string  `json:"currency" example:"IDR"`
	Value    float64 `json:"value" example:"100000.0"`
}

// AccountInfoResponse is the response from the account info endpoint.
// Example:
//
//	{
//		"activeBalance": {
//			"currency": "IDR",
//			"value": "85280.00"
//		},
//		"balanceType": "Balance",
//		"freezeBalance": {
//			"currency": "IDR",
//			"value": "0.00"
//		},
//		"holdBalance": {
//			"currency": "IDR",
//			"value": "0.00"
//		},
//		"status": "0001"
//	}
type AccountInfoResponse struct {
	ActiveBalance Balance `json:"activeBalance"`
	BalanceType   string  `json:"balanceType" example:"Balance"`
	FreezeBalance Balance `json:"freezeBalance"`
	HoldBalance   Balance `json:"holdBalance"`
	Status        string  `json:"status" example:"0001"`
}

type BalanceResponse struct {
	BaseResponse
	ReferenceNo        string                `json:"referenceNo" example:"INQ175307299959777708712406"`
	PartnerReferenceNo string                `json:"partnerReferenceNo" example:"vg9QJ0oABHXufO1tkV2UhroVpBFX3L9nkn9T"`
	AccountNo          string                `json:"accountNo" example:"0310122755265432"`
	Name               string                `json:"name" example:"Merchant Internal"`
	AccountInfo        []AccountInfoResponse `json:"accountInfo"`
}

type PakaiLink struct {
	Config     Config
	httpClient *http.Client
}

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

func (p *PakaiLink) GetBalance() (balance float64) {
	id := uuid.NewString()

	req := map[string]any{
		"partnerReferenceNo": id,
		"accountNumber":      p.Config.AccountNumber,
		"balanceType":        []string{"BALANCE"},
	}

	res, err := p.request("/snap/v1.0/balance-inquiry", req, id)
	if err == nil {
		bal := unmarshalResponse(res, BalanceResponse{})
		for _, v := range bal.AccountInfo {
			if v.BalanceType == "Balance" {
				balance = v.ActiveBalance.Value
				break
			}
		}
	}

	return
}

func (p *PakaiLink) ValidateSignature(signature, body string) error {
	return internal.SHA256WithRSAValidate(p.Config.PublicKey, body, signature)
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
	var authReq *http.Request

	if err == nil {
		uri := fmt.Sprintf("%s%s", p.Config.BaseURL, "/snap/v1.0/access-token/b2b")
		authReq, err = http.NewRequest(
			"POST", uri, strings.NewReader(`{"grantType":"client_credentials"}`))
	}

	if err == nil {
		authReq.Header.Add("X-TIMESTAMP", tstamp)
		authReq.Header.Add("Content-type", "application/json;charset=utf-8")
		authReq.Header.Add("X-CLIENT-KEY", p.Config.ClientKey)
		strAuthSig := ""
		strAuthSig, err = internal.SHA256WithRSA(
			p.Config.PrivateKey, p.Config.ClientKey+"|"+tstamp)

		authReq.Header.Add("X-SIGNATURE", strAuthSig)

		var authRes *http.Response
		if err == nil {
			authRes, err = p.client().Do(authReq)
		}

		var out []byte
		if err == nil {
			out, err = io.ReadAll(authRes.Body)
		}

		jsonOut := struct {
			AccessToken string `json:"accessToken"`
		}{}

		if err == nil {
			err = json.Unmarshal(out, &jsonOut)
		}

		if err == nil {
			token = jsonOut.AccessToken
		}
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
		p.httpClient = hc.New(p.Config.HttpConfig)
	}

	return p.httpClient
}

func New(config Config) *PakaiLink {
	return &PakaiLink{Config: config}
}

type HttpLog struct {
	Tag          string            `json:"tag"`
	URL          string            `json:"url"`
	Method       string            `json:"method"`
	StatusCode   int               `json:"status_code"`
	Headers      map[string]string `json:"headers"`
	RequestBody  any               `json:"request_body"`
	ResponseBody any               `json:"response_body"`
}

func (z *HttpLog) Error() string {
	return fmt.Sprintf("%v", z.ResponseBody)
}

func (z *HttpLog) New(tag, method, url string, req, res any, status int, headers http.Header) *HttpLog {
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

func NewHTTPLog(tag, method, url string, req, res any, status int, headers http.Header) *HttpLog {
	httpLog := new(HttpLog)
	return httpLog.New(tag, method, url, req, res, status, headers)
}

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
