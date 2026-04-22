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
	CustomerName  string        `json:"customer_name" example:"John Doe"`
	CustomerPhone string        `json:"customer_phone" example:"08191298123211"`
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
		"totalAmount": map[string]any{
			"value":    v.Amount,
			"currency": v.Currency,
		},
		"additionalInfo": map[string]any{
			"callbackUrl": v.CallbackURL,
			"bankCode":    v.BankCode,
		},
	}
}

type PakaiLink struct {
	Config     Config
	httpClient *http.Client
}

func (p *PakaiLink) CreateVA(req VARequest) {
	req.CallbackURL = p.Config.CallbackURLForVA

	p.request("/snap/v1.0/transfer-va/create-va", req, req.ID.String())
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
				bodyString := string(bodyBytes)
				bodyString = fmt.Sprintf(`{"errors":[%s]}`, strings.ReplaceAll(bodyString, "}{", "},{"))
				json.Unmarshal([]byte(bodyString), &out)
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

func (p *PakaiLink) signature(method, path string, body any, date time.Time) string {
	var output string
	jsonBody, err := json.Marshal(body)
	if err == nil {
		forms := []string{
			method,
			path,
			internal.SHA256Hex(string(jsonBody)),
			date.Format(time.RFC3339Nano),
		}
		strSign, err := internal.SHA256WithRSA(
			p.Config.PrivateKey, strings.Join(forms, ":"))
		if err == nil {
			output = strSign
		}
	}

	return output
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
