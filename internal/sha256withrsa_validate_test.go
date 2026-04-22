package internal

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/utils"
)

type JsonWithSignatureExample struct {
	Message string `json:"message"`
}

func TestSHA256WithRSAValidate(t *testing.T) {
	publicKey := PUBLIC_KEY
	input := "test input"
	signature, err := SHA256WithRSA(RSAKEY, input)
	utils.AssertEqual(t, nil, err)

	err = SHA256WithRSAValidate(publicKey, input, signature)
	utils.AssertEqual(t, nil, err)

	// test using fiber app
	app := fiber.New()
	// Middleware to validate the signature
	app.Use(func(c *fiber.Ctx) error {
		signature := c.Get("X-Signature")
		rawBody := string(c.Body())

		err := SHA256WithRSAValidate(publicKey, rawBody, signature)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"message": "invalid signature",
			})
		}

		return c.Next()
	})
	// Test Endpoint
	app.Post("/test", func(c *fiber.Ctx) error {
		var payload JsonWithSignatureExample
		if err := c.BodyParser(&payload); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"message": "invalid request",
			})
		}

		if payload.Message != "hello world" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"message": "invalid payload",
			})
		}

		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"message": "success",
		})
	})

	message := `{"message": "hello world"}`
	httpSignature, err := SHA256WithRSA(RSAKEY, message)
	utils.AssertEqual(t, nil, err)

	req, err := http.NewRequest("POST", "/test", strings.NewReader(message))
	utils.AssertEqual(t, nil, err)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Signature", httpSignature)

	res, err := app.Test(req, 500)
	utils.AssertEqual(t, nil, err)
	utils.AssertEqual(t, 200, res.StatusCode)

	req, err = http.NewRequest("POST", "/test", strings.NewReader(message))
	utils.AssertEqual(t, nil, err)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Signature", signature)

	res, err = app.Test(req, 500)
	utils.AssertEqual(t, nil, err)
	utils.AssertEqual(t, fiber.StatusUnauthorized, res.StatusCode)

}
