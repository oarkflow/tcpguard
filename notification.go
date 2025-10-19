package tcpguard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
)

// NotificationSender interface for different notification channels
type NotificationSender interface {
	Send(ctx context.Context, payload *NotificationPayload) error
	Name() string
}

// NotificationPayload contains the processed notification data
type NotificationPayload struct {
	Channel string
	Topic   string
	Message string
	Details map[string]string
	// Context data for notifications
	ClientIP   string
	Endpoint   string
	UserID     string
	ActionType string
	RuleName   string
	Timestamp  time.Time
}

// NotificationRegistry manages notification senders
type NotificationRegistry struct {
	senders map[string]NotificationSender
	mu      sync.RWMutex
}

// NewNotificationRegistry creates a new notification registry
func NewNotificationRegistry(credentials *Credentials) *NotificationRegistry {
	registry := &NotificationRegistry{
		senders: make(map[string]NotificationSender),
	}
	// Register built-in senders
	registry.Register(&LogNotificationSender{})
	registry.Register(&WebhookNotificationSender{
		client:      &http.Client{Timeout: 10 * time.Second},
		credentials: credentials,
	})
	registry.Register(&SlackNotificationSender{
		client:      &http.Client{Timeout: 10 * time.Second},
		credentials: credentials,
	})
	registry.Register(&EmailNotificationSender{
		credentials: credentials,
	})
	return registry
}

// Register adds a notification sender
func (nr *NotificationRegistry) Register(sender NotificationSender) {
	nr.mu.Lock()
	defer nr.mu.Unlock()
	nr.senders[sender.Name()] = sender
}

// Get retrieves a notification sender
func (nr *NotificationRegistry) Get(channel string) (NotificationSender, bool) {
	nr.mu.RLock()
	defer nr.mu.RUnlock()
	sender, exists := nr.senders[channel]
	return sender, exists
}

// SendNotification processes and sends a notification
func (nr *NotificationRegistry) SendNotification(ctx context.Context, notification *Notification, meta ActionMeta, actionType, ruleName string) error {
	if notification == nil {
		return nil
	}

	// Get the appropriate sender
	sender, exists := nr.Get(notification.Channel)
	if !exists {
		return fmt.Errorf("notification channel '%s' not registered", notification.Channel)
	}

	// Create notification payload
	payload := &NotificationPayload{
		Channel:    notification.Channel,
		Topic:      notification.Topic,
		Message:    notification.Message,
		Details:    notification.Details,
		ClientIP:   meta.ClientIP,
		Endpoint:   meta.Endpoint,
		UserID:     meta.UserID,
		ActionType: actionType,
		RuleName:   ruleName,
		Timestamp:  time.Now(),
	}

	// Replace placeholders
	payload.Topic = replacePlaceholders(payload.Topic, payload)
	payload.Message = replacePlaceholders(payload.Message, payload)

	if payload.Details != nil {
		processedDetails := make(map[string]string)
		for key, value := range payload.Details {
			processedKey := replacePlaceholders(key, payload)
			processedValue := replacePlaceholders(value, payload)
			processedDetails[processedKey] = processedValue
		}
		payload.Details = processedDetails
	}

	// Send notification asynchronously to avoid blocking request processing
	go func() {
		sendCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		if err := sender.Send(sendCtx, payload); err != nil {
			// Log error but don't fail the action
			fmt.Printf("[Notification Error] Failed to send notification via %s: %v\n", notification.Channel, err)
		}
	}()

	return nil
}

// replacePlaceholders replaces placeholders in a string with actual values
func replacePlaceholders(template string, payload *NotificationPayload) string {
	replacer := strings.NewReplacer(
		"{{clientIP}}", payload.ClientIP,
		"{{endpoint}}", payload.Endpoint,
		"{{userID}}", payload.UserID,
		"{{actionType}}", payload.ActionType,
		"{{ruleName}}", payload.RuleName,
		"{{timestamp}}", payload.Timestamp.Format(time.RFC3339),
		"{{channel}}", payload.Channel,
		"{{topic}}", payload.Topic,
		"{{message}}", payload.Message,
	)
	return replacer.Replace(template)
}

// LogNotificationSender logs notifications to stdout/stderr
type LogNotificationSender struct{}

func (s *LogNotificationSender) Name() string {
	return "log"
}

func (s *LogNotificationSender) Send(ctx context.Context, payload *NotificationPayload) error {
	logMsg := fmt.Sprintf("[NOTIFICATION] Channel=%s Topic=%s Message=%s ClientIP=%s Endpoint=%s UserID=%s ActionType=%s RuleName=%s Timestamp=%s",
		payload.Channel,
		payload.Topic,
		payload.Message,
		payload.ClientIP,
		payload.Endpoint,
		payload.UserID,
		payload.ActionType,
		payload.RuleName,
		payload.Timestamp.Format(time.RFC3339),
	)

	if len(payload.Details) > 0 {
		detailsJSON, _ := json.Marshal(payload.Details)
		logMsg += fmt.Sprintf(" Details=%s", string(detailsJSON))
	}

	fmt.Println(logMsg)
	return nil
}

// WebhookNotificationSender sends notifications to HTTP webhooks
type WebhookNotificationSender struct {
	client      *http.Client
	credentials *Credentials
}

func (s *WebhookNotificationSender) Name() string {
	return "webhook"
}

func (s *WebhookNotificationSender) Send(ctx context.Context, payload *NotificationPayload) error {
	url, err := s.getWebhookURL(payload.Topic)
	if err != nil {
		return err
	}

	// Prepare webhook payload
	webhookPayload := map[string]interface{}{
		"channel":    payload.Channel,
		"message":    payload.Message,
		"clientIP":   payload.ClientIP,
		"endpoint":   payload.Endpoint,
		"userID":     payload.UserID,
		"actionType": payload.ActionType,
		"ruleName":   payload.RuleName,
		"timestamp":  payload.Timestamp.Format(time.RFC3339),
		"details":    payload.Details,
	}

	jsonData, err := json.Marshal(webhookPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create webhook request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "TCPGuard-Notification/1.0")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned non-2xx status code: %d", resp.StatusCode)
	}

	return nil
}

func (s *WebhookNotificationSender) getWebhookURL(key string) (string, error) {
	if s.credentials == nil || s.credentials.Notifications == nil {
		return "", fmt.Errorf("webhook credentials not configured")
	}
	webhookCreds, exists := s.credentials.Notifications["webhook"]
	if !exists {
		return "", fmt.Errorf("webhook credentials not found")
	}
	url, exists := webhookCreds[key]
	if !exists {
		return "", fmt.Errorf("webhook URL for key '%s' not found", key)
	}
	urlStr, ok := url.(string)
	if !ok {
		return "", fmt.Errorf("webhook URL for key '%s' is not a string", key)
	}
	return urlStr, nil
}

// SlackNotificationSender sends notifications to Slack
type SlackNotificationSender struct {
	client      *http.Client
	credentials *Credentials
}

func (s *SlackNotificationSender) Name() string {
	return "slack"
}

func (s *SlackNotificationSender) Send(ctx context.Context, payload *NotificationPayload) error {
	url, err := s.getSlackWebhookURL(payload.Topic)
	if err != nil {
		return err
	}

	// Build Slack message with rich formatting
	slackPayload := map[string]interface{}{
		"text": payload.Message,
		"blocks": []map[string]interface{}{
			{
				"type": "header",
				"text": map[string]string{
					"type": "plain_text",
					"text": fmt.Sprintf("🚨 Security Alert: %s", payload.ActionType),
				},
			},
			{
				"type": "section",
				"text": map[string]string{
					"type": "mrkdwn",
					"text": payload.Message,
				},
			},
			{
				"type": "section",
				"fields": []map[string]string{
					{"type": "mrkdwn", "text": fmt.Sprintf("*Client IP:*\n%s", payload.ClientIP)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Endpoint:*\n%s", payload.Endpoint)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*User ID:*\n%s", payload.UserID)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Rule:*\n%s", payload.RuleName)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Action:*\n%s", payload.ActionType)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Time:*\n%s", payload.Timestamp.Format(time.RFC3339))},
				},
			},
		},
	}

	// Add details if present
	if len(payload.Details) > 0 {
		var detailsText string
		for key, value := range payload.Details {
			detailsText += fmt.Sprintf("• *%s:* %s\n", key, value)
		}
		slackPayload["blocks"] = append(slackPayload["blocks"].([]map[string]interface{}), map[string]interface{}{
			"type": "section",
			"text": map[string]string{
				"type": "mrkdwn",
				"text": fmt.Sprintf("*Additional Details:*\n%s", detailsText),
			},
		})
	}

	jsonData, err := json.Marshal(slackPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal slack payload: %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create slack request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send slack notification: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("slack returned non-2xx status code: %d", resp.StatusCode)
	}

	return nil
}

func (s *SlackNotificationSender) getSlackWebhookURL(key string) (string, error) {
	if s.credentials == nil || s.credentials.Notifications == nil {
		return "", fmt.Errorf("slack credentials not configured")
	}
	slackCreds, exists := s.credentials.Notifications["slack"]
	if !exists {
		return "", fmt.Errorf("slack credentials not found")
	}
	url, exists := slackCreds[key]
	if !exists {
		return "", fmt.Errorf("slack webhook URL for key '%s' not found", key)
	}
	urlStr, ok := url.(string)
	if !ok {
		return "", fmt.Errorf("slack webhook URL for key '%s' is not a string", key)
	}
	return urlStr, nil
}

// EmailNotificationSender sends notifications via email (placeholder for SMTP integration)
type EmailNotificationSender struct {
	credentials *Credentials
}

func (s *EmailNotificationSender) Name() string {
	return "email"
}

func (s *EmailNotificationSender) Send(ctx context.Context, payload *NotificationPayload) error {
	// This is a placeholder implementation
	// In a real implementation, you would integrate with an SMTP server
	// or email service provider (SendGrid, AWS SES, etc.)

	// For now, just log the email details
	smtpHost, smtpPort, username, password, from, err := s.getEmailCredentials()
	if err != nil {
		return err
	}

	recipient := payload.Topic
	if recipient == "" {
		return fmt.Errorf("email recipient (topic) is required")
	}

	fmt.Printf("[EMAIL] To: %s, From: %s, Subject: Security Alert, Body: %s, SMTP: %s:%d@%s\n",
		recipient, from, payload.Message, username, smtpPort, smtpHost)
	// TODO: Implement actual SMTP sending using password
	_ = password
	return nil
}

func (s *EmailNotificationSender) getEmailCredentials() (host string, port int, username, password, from string, err error) {
	if s.credentials == nil || s.credentials.Notifications == nil {
		return "", 0, "", "", "", fmt.Errorf("email credentials not configured")
	}
	emailCreds, exists := s.credentials.Notifications["email"]
	if !exists {
		return "", 0, "", "", "", fmt.Errorf("email credentials not found")
	}

	hostVal, exists := emailCreds["smtp_host"]
	if !exists {
		return "", 0, "", "", "", fmt.Errorf("smtp_host not found in email credentials")
	}
	host, ok := hostVal.(string)
	if !ok {
		return "", 0, "", "", "", fmt.Errorf("smtp_host is not a string")
	}

	portVal, exists := emailCreds["smtp_port"]
	if !exists {
		return "", 0, "", "", "", fmt.Errorf("smtp_port not found in email credentials")
	}
	portFloat, ok := portVal.(float64)
	if !ok {
		return "", 0, "", "", "", fmt.Errorf("smtp_port is not a number")
	}
	port = int(portFloat)

	usernameVal, exists := emailCreds["username"]
	if !exists {
		return "", 0, "", "", "", fmt.Errorf("username not found in email credentials")
	}
	username, ok = usernameVal.(string)
	if !ok {
		return "", 0, "", "", "", fmt.Errorf("username is not a string")
	}

	passwordVal, exists := emailCreds["password"]
	if !exists {
		return "", 0, "", "", "", fmt.Errorf("password not found in email credentials")
	}
	password, ok = passwordVal.(string)
	if !ok {
		return "", 0, "", "", "", fmt.Errorf("password is not a string")
	}

	fromVal, exists := emailCreds["from"]
	if !exists {
		from = username // default to username
	} else {
		from, ok = fromVal.(string)
		if !ok {
			return "", 0, "", "", "", fmt.Errorf("from is not a string")
		}
	}

	return host, port, username, password, from, nil
}

// Helper function to send notifications from action context
func sendActionNotification(ctx context.Context, notification *Notification, meta ActionMeta, actionType, ruleName string, registry *NotificationRegistry) {
	if notification == nil || registry == nil {
		return
	}

	if err := registry.SendNotification(ctx, notification, meta, actionType, ruleName); err != nil {
		fmt.Printf("[Notification Warning] Failed to send notification: %v\n", err)
	}
}

// Helper to extract rule name from fiber context (if set)
func getRuleNameFromContext(c *fiber.Ctx) string {
	if ruleName := c.Locals("rule_name"); ruleName != nil {
		if name, ok := ruleName.(string); ok {
			return name
		}
	}
	return "unknown"
}
