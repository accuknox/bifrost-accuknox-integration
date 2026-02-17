package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

const PluginName = "accuknox-logger"

type AccuKnoxConfig struct {
	Enabled  bool   `json:"enabled"`
	ApiKey   string `json:"api_key"`
	UserInfo string `json:"user_info"`
}

type AccuKnoxClient struct {
	baseURL    string
	apiKey     string
	userInfo   string
	httpClient *http.Client
}

var pluginConfig AccuKnoxConfig
var accuknoxClient *AccuKnoxClient
var promptCache sync.Map // FIX 3: was map[string]string, not concurrency-safe

var envURLs = map[string]string{
	"localhost": "http://localhost:8081/llm-defence/application-query",
	"dev":       "https://cwpp.dev.accuknox.com/llm-defence/application-query",
	"stage":     "https://cwpp.stage.accuknox.com/llm-defence/application-query",
	"demo":      "https://cwpp.demo.accuknox.com/llm-defence/application-query",
	"prod":      "https://cwpp.prod.accuknox.com/llm-defence/application-query",
}

const accuknoxSessionKey = schemas.BifrostContextKey("accuknox_session_id") // FIX 2: typed key

func Init(config any) error {
	log.Println("[AccuKnox Plugin] Init called")
	if config != nil {
		configBytes, err := json.Marshal(config)
		if err != nil {
			return fmt.Errorf("failed to marshal config: %w", err)
		}
		if err := json.Unmarshal(configBytes, &pluginConfig); err != nil {
			return fmt.Errorf("failed to unmarshal config: %w", err)
		}
	}
	if pluginConfig.Enabled {
		log.Printf("[AccuKnox Plugin] Initialized with user_info: %s", pluginConfig.UserInfo)
		if pluginConfig.ApiKey != "" && pluginConfig.ApiKey != "your-accuknox-api-key-here" {
			client, err := initAccuKnoxClient(pluginConfig.ApiKey, pluginConfig.UserInfo)
			if err != nil {
				log.Printf("[AccuKnox Plugin] WARNING: Failed to initialize AccuKnox client: %v", err)
			} else {
				accuknoxClient = client
				log.Printf("[AccuKnox Plugin] AccuKnox API client initialized: %s", client.baseURL)
			}
		} else {
			log.Println("[AccuKnox Plugin] No valid API key provided, running without AccuKnox API integration")
		}
	}
	return nil
}

func initAccuKnoxClient(apiKey, userInfo string) (*AccuKnoxClient, error) {
	baseURL, err := getBaseURLFromToken(apiKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode token: %w", err)
	}
	return &AccuKnoxClient{
		baseURL:  baseURL,
		apiKey:   apiKey,
		userInfo: userInfo,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

func getBaseURLFromToken(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT token format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("failed to decode JWT payload: %w", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("failed to parse JWT claims: %w", err)
	}
	iss, ok := claims["iss"].(string)
	if !ok {
		return "", fmt.Errorf("missing 'iss' field in token")
	}
	parts = strings.Split(iss, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid issuer format: %s", iss)
	}
	baseURL, ok := envURLs[parts[1]]
	if !ok {
		return "", fmt.Errorf("invalid environment: %s", parts[1])
	}
	return baseURL, nil
}

func GetName() string {
	return PluginName
}

func PreLLMHook(ctx *schemas.BifrostContext, req *schemas.BifrostRequest) (*schemas.BifrostRequest, *schemas.LLMPluginShortCircuit, error) {
	if !pluginConfig.Enabled {
		return req, nil, nil
	}
	log.Println("[AccuKnox Plugin] PreHook called")

	provider, model, _ := req.GetRequestFields()
	requestID := "unknown"
	if ctx != nil {
		if id, ok := ctx.Value(schemas.BifrostContextKeyRequestID).(string); ok {
			requestID = id
		}
	}

	var inputContent string
	switch req.RequestType {
	case schemas.ChatCompletionRequest, schemas.ChatCompletionStreamRequest:
		if req.ChatRequest != nil && req.ChatRequest.Input != nil {
			inputContent = extractMessagesContent(req.ChatRequest.Input)
		}
	case schemas.TextCompletionRequest, schemas.TextCompletionStreamRequest:
		if req.TextCompletionRequest != nil && req.TextCompletionRequest.Input.PromptStr != nil {
			inputContent = *req.TextCompletionRequest.Input.PromptStr
		}
	}

	log.Println("=" + strings.Repeat("=", 80))
	log.Printf("[AccuKnox Plugin] REQUEST ID: %s", requestID)
	log.Printf("[AccuKnox Plugin] Provider: %s", provider)
	log.Printf("[AccuKnox Plugin] Model: %s", model)
	log.Printf("[AccuKnox Plugin] Request Type: %s", req.RequestType)
	log.Printf("[AccuKnox Plugin] Timestamp: %s", time.Now().Format(time.RFC3339))
	log.Println("[AccuKnox Plugin] INPUT PROMPT:")
	log.Println(inputContent)
	log.Println(strings.Repeat("=", 81))

	// FIX 3: use sync.Map
	promptCache.Store(requestID, inputContent)

	// FIX 1: only scan when there's actual content to scan
	if accuknoxClient != nil && inputContent != "" {
		sessionID, err := accuknoxClient.scanPrompt(inputContent)
		if err != nil {
			log.Printf("[AccuKnox Plugin] ERROR: Failed to scan prompt: %v", err)
		} else {
			log.Printf("[AccuKnox Plugin] Prompt scanned successfully, session_id: %s", sessionID)
			// FIX 2: use typed context key
			if ctx != nil {
				ctx.SetValue(accuknoxSessionKey, sessionID)
			}
		}
	}

	return req, nil, nil
}

func PostLLMHook(ctx *schemas.BifrostContext, resp *schemas.BifrostResponse, bifrostErr *schemas.BifrostError) (*schemas.BifrostResponse, *schemas.BifrostError, error) {
	if !pluginConfig.Enabled {
		return resp, bifrostErr, nil
	}
	log.Println("[AccuKnox Plugin] PostHook called")

	requestID := "unknown"
	if ctx != nil {
		if id, ok := ctx.Value(schemas.BifrostContextKeyRequestID).(string); ok {
			requestID = id
		}
	}

	if bifrostErr != nil {
		log.Println("=" + strings.Repeat("=", 80))
		log.Printf("[AccuKnox Plugin] REQUEST ID: %s", requestID)
		log.Println("[AccuKnox Plugin] ERROR RESPONSE:")
		log.Printf("Error: %+v", bifrostErr)
		log.Println(strings.Repeat("=", 81))
		return resp, bifrostErr, nil
	}

	var outputContent string
	var tokenUsage *schemas.BifrostLLMUsage

	if resp != nil {
		if resp.ChatResponse != nil {
			if len(resp.ChatResponse.Choices) > 0 {
				choice := resp.ChatResponse.Choices[0]
				if choice.ChatNonStreamResponseChoice != nil &&
					choice.ChatNonStreamResponseChoice.Message != nil &&
					choice.ChatNonStreamResponseChoice.Message.Content != nil &&
					choice.ChatNonStreamResponseChoice.Message.Content.ContentStr != nil {
					outputContent = *choice.ChatNonStreamResponseChoice.Message.Content.ContentStr
				}
			}
			tokenUsage = resp.ChatResponse.Usage
		}
		if resp.TextCompletionResponse != nil {
			if len(resp.TextCompletionResponse.Choices) > 0 {
				choice := resp.TextCompletionResponse.Choices[0]
				if choice.TextCompletionResponseChoice != nil {
					outputContent = *choice.TextCompletionResponseChoice.Text
				}
			}
			tokenUsage = resp.TextCompletionResponse.Usage
		}
	}

	log.Println("=" + strings.Repeat("=", 80))
	log.Printf("[AccuKnox Plugin] REQUEST ID: %s", requestID)
	log.Printf("[AccuKnox Plugin] Timestamp: %s", time.Now().Format(time.RFC3339))
	log.Println("[AccuKnox Plugin] OUTPUT RESPONSE:")
	log.Println(outputContent)
	if tokenUsage != nil {
		log.Printf("[AccuKnox Plugin] Token Usage - Prompt: %d, Completion: %d, Total: %d",
			tokenUsage.PromptTokens, tokenUsage.CompletionTokens, tokenUsage.TotalTokens)
	}
	if resp != nil {
		log.Printf("[AccuKnox Plugin] Latency: %d ms", resp.GetExtraFields().Latency)
	}
	log.Println(strings.Repeat("=", 81))

	if accuknoxClient != nil && resp != nil && outputContent != "" {
		// FIX 2: retrieve session ID with typed key
		sessionID := ""
		if ctx != nil {
			if id, ok := ctx.Value(accuknoxSessionKey).(string); ok {
				sessionID = id
			}
		}

		// FIX 3: retrieve prompt from sync.Map
		originalPrompt := ""
		if val, ok := promptCache.Load(requestID); ok {
			originalPrompt = val.(string)
		}

		err := accuknoxClient.scanResponse(originalPrompt, outputContent, sessionID)
		if err != nil {
			log.Printf("[AccuKnox Plugin] ERROR: Failed to scan response: %v", err)
		} else {
			log.Printf("[AccuKnox Plugin] Response scanned successfully")
		}

		// FIX 3: use sync.Map delete
		promptCache.Delete(requestID)
	}

	return resp, bifrostErr, nil
}

func Cleanup() error {
	log.Println("[AccuKnox Plugin] Cleanup called")
	return nil
}

func extractMessagesContent(messages []schemas.ChatMessage) string {
	var builder strings.Builder
	for i, msg := range messages {
		if i > 0 {
			builder.WriteString("\n")
		}
		if msg.Content != nil {
			if msg.Content.ContentStr != nil {
				builder.WriteString(*msg.Content.ContentStr)
			} else if msg.Content.ContentBlocks != nil {
				for _, block := range msg.Content.ContentBlocks {
					if block.Text != nil {
						builder.WriteString(*block.Text)
					}
				}
			}
		}
	}
	return builder.String()
}

func (c *AccuKnoxClient) scanPrompt(content string) (string, error) {
	payload := map[string]interface{}{
		"query_type": "prompt",
		"content":    content,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}
	req, err := http.NewRequest("POST", c.baseURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.apiKey))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User", c.userInfo)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}
	sessionID, ok := result["session_id"].(string)
	if !ok {
		return "", fmt.Errorf("session_id not found in response")
	}
	return sessionID, nil
}

func (c *AccuKnoxClient) scanResponse(prompt, content, sessionID string) error {
	payload := map[string]interface{}{
		"query_type": "response",
		"prompt":     prompt,
		"content":    content,
		"session_id": sessionID,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}
	req, err := http.NewRequest("POST", c.baseURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.apiKey))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User", c.userInfo)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}
