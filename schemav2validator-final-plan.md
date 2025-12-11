# Schemav2Validator Level 2 Validation - Final Implementation Plan

## Goal

Extend `schemav2validator` to validate objects with `@context` against their referenced domain schemas (Level 2 validation).

**Example:** In a `select` request, validate `beckn:offerAttributes` (with `@context: .../EvChargingOffer/v1/context.jsonld`) against `EvChargingOffer/v1/attributes.yaml`

---

## Architecture

### Current Flow (Level 1 Only)
```
Request → Validate() → actionSchemas[action].VisitJSON(body) → Done
          (Objects with @context pass because additionalProperties: true)
```

### New Flow (Level 1 + Level 2)
```
Request → Validate()
       → LEVEL 1: actionSchemas[action].VisitJSON(body) ✓
       → if enableReferencedSchemas:
           → LEVEL 2: validateReferencedSchemas(body)
               → Find ALL objects with @context (anywhere in JSON)
               → For each: load schema, match by @type, validate
               → If fails: Return error (same as Level 1)
       → Return success
```

---

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `schemav2validator.go` | **MODIFY** | Add all Level 2 code (config, cache, helpers, validation) |
| `cmd/plugin.go` | **MODIFY** | Parse new config fields |
| `config/local-simple.yaml` | **UPDATE** | Add example config |

> **Note:** All Level 2 code goes in `schemav2validator.go` (single file approach, following existing codebase pattern)

---

## Concepts Included from Lead's Plan

| Concept | Description |
|---------|-------------|
| URL Hashing | `hashURL()` using SHA256 for cache keys |
| Background Cleanup | `cleanupExpiredReferencedSchemas()` in `refreshLoop()` |
| Plugin Provider Update | Parse new config in `cmd/plugin.go` |
| Level 2 Fails Request | Return error on Level 2 failure (same as Level 1) |
| URL/File Support | Load referenced schemas from URL or local file |
| Format Validation | Uses `EnableFormatValidation()` same as Level 1 |

---

## `pkg/plugin/implementation/schemav2validator/schemav2validator.go` (MODIFY)

### Overview of Changes

The following code sections will be **ADDED** to the existing `schemav2validator.go` file. Existing code remains unchanged.

---

### Section 1: Add Imports (add to existing import block)

```go
// Add these to existing imports:
import (
	// ... existing imports ...
	"crypto/sha256"
	"encoding/hex"
)
```

---

### Section 2: Add Config Fields (modify existing Config struct, ~line 40)

```go
// Config struct for Schemav2Validator.
type Config struct {
	Type     string // "url", "file", or "dir"
	Location string // URL, file path, or directory path
	CacheTTL int

	// NEW: Referenced schema configuration
	EnableReferencedSchemas bool
	ReferencedSchemaConfig  ReferencedSchemaConfig
}

// ReferencedSchemaConfig holds configuration for referenced schema validation
type ReferencedSchemaConfig struct {
	CacheTTL        int       // seconds, default 86400 (24h)
	MaxCacheSize    int       // default 100
	DownloadTimeout int       // seconds, default 30
	AllowedDomains  []string  // whitelist (empty = all allowed)
	URLTransform    string    // e.g. "context.jsonld->attributes.yaml"
}
```

---

### Section 3: Add New Structs (add after cachedSpec struct, ~line 38)

```go
// referencedObject represents ANY object with @context in the request
type referencedObject struct {
	Path    string
	Context string
	Type    string
	Data    map[string]interface{}
}

// schemaCache caches loaded domain schemas with LRU eviction
type schemaCache struct {
	mu      sync.RWMutex
	schemas map[string]*cachedDomainSchema
	maxSize int
}

// cachedDomainSchema holds a cached domain schema with metadata
type cachedDomainSchema struct {
	doc          *openapi3.T
	loadedAt     time.Time
	expiresAt    time.Time
	lastAccessed time.Time
	accessCount  int64
}
```

---

### Section 4: Add schemaCache Field to schemav2Validator Struct (~line 26)

```go
// schemav2Validator implements the SchemaValidator interface.
type schemav2Validator struct {
	config      *Config
	spec        *cachedSpec
	specMutex   sync.RWMutex
	schemaCache *schemaCache // NEW
}
```

---

### Section 5: Add Helper Functions (add at end of file)

```go
// newSchemaCache creates a new schema cache
func newSchemaCache(maxSize int) *schemaCache {
	return &schemaCache{
		schemas: make(map[string]*cachedDomainSchema),
		maxSize: maxSize,
	}
}

// hashURL creates a SHA256 hash of the URL for use as cache key
func hashURL(urlStr string) string {
	hash := sha256.Sum256([]byte(urlStr))
	return hex.EncodeToString(hash[:])
}

// isValidSchemaPath validates URL or file path
func isValidSchemaPath(schemaPath string) bool {
	u, err := url.Parse(schemaPath)
	if err != nil {
		// Could be a simple file path
		return schemaPath != ""
	}
	// Support: http://, https://, file://, or no scheme (local path)
	return u.Scheme == "http" || u.Scheme == "https" || 
	       u.Scheme == "file" || u.Scheme == ""
}

// get retrieves a cached schema and updates access tracking
func (c *schemaCache) get(urlHash string) (*openapi3.T, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	cached, exists := c.schemas[urlHash]
	if !exists || time.Now().After(cached.expiresAt) {
		return nil, false
	}

	// Update access tracking
	cached.lastAccessed = time.Now()
	cached.accessCount++

	return cached.doc, true
}

// set stores a schema in the cache with TTL and LRU eviction
func (c *schemaCache) set(urlHash string, doc *openapi3.T, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// LRU eviction if cache is full
	if len(c.schemas) >= c.maxSize {
		var oldest string
		var oldestTime time.Time
		for k, v := range c.schemas {
			if oldest == "" || v.lastAccessed.Before(oldestTime) {
				oldest, oldestTime = k, v.lastAccessed
			}
		}
		if oldest != "" {
			delete(c.schemas, oldest)
		}
	}

	c.schemas[urlHash] = &cachedDomainSchema{
		doc:          doc,
		loadedAt:     time.Now(),
		expiresAt:    time.Now().Add(ttl),
		lastAccessed: time.Now(),
		accessCount:  1,
	}
}

// cleanupExpired removes expired schemas from cache
func (c *schemaCache) cleanupExpired() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	expired := make([]string, 0)

	for urlHash, cached := range c.schemas {
		if now.After(cached.expiresAt) {
			expired = append(expired, urlHash)
		}
	}

	for _, urlHash := range expired {
		delete(c.schemas, urlHash)
	}

	return len(expired)
}

// loadSchemaFromPath loads a schema from URL or local file with timeout and caching
func (c *schemaCache) loadSchemaFromPath(ctx context.Context, schemaPath string, ttl, timeout time.Duration) (*openapi3.T, error) {
	urlHash := hashURL(schemaPath)

	// Check cache first
	if doc, found := c.get(urlHash); found {
		log.Debugf(ctx, "Schema cache hit for: %s", schemaPath)
		return doc, nil
	}

	log.Debugf(ctx, "Schema cache miss, loading from: %s", schemaPath)

	// Validate path format
	if !isValidSchemaPath(schemaPath) {
		return nil, fmt.Errorf("invalid schema path: %s", schemaPath)
	}

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true

	var doc *openapi3.T
	var err error

	u, parseErr := url.Parse(schemaPath)
	if parseErr == nil && (u.Scheme == "http" || u.Scheme == "https") {
		// Load from URL with timeout
		loadCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		loader.Context = loadCtx
		doc, err = loader.LoadFromURI(u)
	} else {
		// Load from local file (file:// or path)
		filePath := schemaPath
		if u != nil && u.Scheme == "file" {
			filePath = u.Path
		}
		doc, err = loader.LoadFromFile(filePath)
	}

	if err != nil {
		log.Errorf(ctx, err, "Failed to load schema from: %s", schemaPath)
		return nil, fmt.Errorf("failed to load schema from %s: %w", schemaPath, err)
	}

	// Validate loaded schema (non-blocking, just log warnings)
	if err := doc.Validate(ctx); err != nil {
		log.Debugf(ctx, "Schema validation warnings for %s: %v", schemaPath, err)
	}

	c.set(urlHash, doc, ttl)
	log.Debugf(ctx, "Loaded and cached schema from: %s", schemaPath)

	return doc, nil
}

// findReferencedObjects recursively finds ALL objects with @context in the data
func findReferencedObjects(data interface{}, path string) []referencedObject {
	var results []referencedObject

	switch v := data.(type) {
	case map[string]interface{}:
		// Check for @context and @type
		if contextVal, hasContext := v["@context"].(string); hasContext {
			if typeVal, hasType := v["@type"].(string); hasType {
				results = append(results, referencedObject{
					Path:    path,
					Context: contextVal,
					Type:    typeVal,
					Data:    v,
				})
			}
		}

		// Recurse into nested objects
		for key, val := range v {
			newPath := key
			if path != "" {
				newPath = path + "." + key
			}
			results = append(results, findReferencedObjects(val, newPath)...)
		}

	case []interface{}:
		// Recurse into arrays
		for i, item := range v {
			newPath := fmt.Sprintf("%s[%d]", path, i)
			results = append(results, findReferencedObjects(item, newPath)...)
		}
	}

	return results
}

// transformContextToSchemaURL transforms @context URL to schema URL
func transformContextToSchemaURL(contextURL, transform string) string {
	parts := strings.Split(transform, "->")
	if len(parts) != 2 {
		// Default transformation
		return strings.Replace(contextURL, "context.jsonld", "attributes.yaml", 1)
	}
	return strings.Replace(contextURL, strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), 1)
}

// findSchemaByType finds a schema in the document by @type value
func findSchemaByType(doc *openapi3.T, typeName string) (*openapi3.SchemaRef, error) {
	if doc.Components == nil || doc.Components.Schemas == nil {
		return nil, fmt.Errorf("no schemas found in document")
	}

	// Try direct match by schema name
	if schema, exists := doc.Components.Schemas[typeName]; exists {
		return schema, nil
	}

	// Fallback: Try x-jsonld.@type match
	for _, schema := range doc.Components.Schemas {
		if schema.Value == nil {
			continue
		}
		if xJsonld, ok := schema.Value.Extensions["x-jsonld"].(map[string]interface{}); ok {
			if atType, ok := xJsonld["@type"].(string); ok && atType == typeName {
				return schema, nil
			}
		}
	}

	return nil, fmt.Errorf("no schema found for @type: %s", typeName)
}

// isAllowedDomain checks if the URL domain is in the whitelist
func isAllowedDomain(schemaURL string, allowedDomains []string) bool {
	if len(allowedDomains) == 0 {
		return true // No whitelist = all allowed
	}
	for _, domain := range allowedDomains {
		if strings.Contains(schemaURL, domain) {
			return true
		}
	}
	return false
}

// validateReferencedObject validates a single object with @context
func (c *schemaCache) validateReferencedObject(
	ctx context.Context,
	obj referencedObject,
	urlTransform string,
	ttl, timeout time.Duration,
	allowedDomains []string,
) error {
	// Domain whitelist check
	if !isAllowedDomain(obj.Context, allowedDomains) {
		log.Warnf(ctx, "Domain not in whitelist: %s", obj.Context)
		return fmt.Errorf("domain not allowed: %s", obj.Context)
	}

	// Transform @context to schema path (URL or file)
	schemaPath := transformContextToSchemaURL(obj.Context, urlTransform)
	log.Debugf(ctx, "Transformed %s -> %s", obj.Context, schemaPath)

	// Load schema with timeout (supports URL or local file)
	doc, err := c.loadSchemaFromPath(ctx, schemaPath, ttl, timeout)
	if err != nil {
		return fmt.Errorf("at %s: %w", obj.Path, err)
	}

	// Find schema by @type
	schema, err := findSchemaByType(doc, obj.Type)
	if err != nil {
		log.Errorf(ctx, err, "Schema not found for @type: %s at path: %s", obj.Type, obj.Path)
		return fmt.Errorf("at %s: %w", obj.Path, err)
	}

	// Validate object against schema (same options as Level 1)
	opts := []openapi3.SchemaValidationOption{
		openapi3.VisitAsRequest(),
		openapi3.EnableFormatValidation(),
	}
	if err := schema.Value.VisitJSON(obj.Data, opts...); err != nil {
		log.Debugf(ctx, "Validation failed for @type: %s at path: %s: %v", obj.Type, obj.Path, err)
		return fmt.Errorf("at %s: %w", obj.Path, err)
	}

	log.Debugf(ctx, "Validation passed for @type: %s at path: %s", obj.Type, obj.Path)
	return nil
}
```

---

### Section 6: Modify New() Function (modify existing ~line 47)

Add cache initialization after creating validator:
```go
func New(ctx context.Context, config *Config) (*schemav2Validator, func() error, error) {
	// ... existing validation ...

	v := &schemav2Validator{
		config: config,
	}

	// NEW: Initialize referenced schema cache if enabled
	if config.EnableReferencedSchemas {
		maxSize := 100
		if config.ReferencedSchemaConfig.MaxCacheSize > 0 {
			maxSize = config.ReferencedSchemaConfig.MaxCacheSize
		}
		v.schemaCache = newSchemaCache(maxSize)
		log.Infof(ctx, "Initialized referenced schema cache with max size: %d", maxSize)
	}

	if err := v.initialise(ctx); err != nil {
		return nil, nil, fmt.Errorf("failed to initialise schemav2Validator: %v", err)
	}

	go v.refreshLoop(ctx)

	return v, nil, nil
}
```

### Modify refreshLoop() - add cleanup ticker:
```go
func (v *schemav2Validator) refreshLoop(ctx context.Context) {
	coreTicker := time.NewTicker(time.Duration(v.config.CacheTTL) * time.Second)
	defer coreTicker.Stop()

	// NEW: Ticker for referenced schema cleanup
	var refTicker *time.Ticker
	if v.config.EnableReferencedSchemas {
		ttl := v.config.ReferencedSchemaConfig.CacheTTL
		if ttl <= 0 {
			ttl = 86400 // Default 24 hours
		}
		refTicker = time.NewTicker(time.Duration(ttl) * time.Second)
		defer refTicker.Stop()
	}

	for {
		if refTicker != nil {
			select {
			case <-ctx.Done():
				return
			case <-coreTicker.C:
				v.reloadExpiredSpec(ctx)
			case <-refTicker.C:
				if v.schemaCache != nil {
					count := v.schemaCache.cleanupExpired()
					if count > 0 {
						log.Debugf(ctx, "Cleaned up %d expired referenced schemas", count)
					}
				}
			}
		} else {
			select {
			case <-ctx.Done():
				return
			case <-coreTicker.C:
				v.reloadExpiredSpec(ctx)
			}
		}
	}
}
```

### Modify Validate() - add Level 2 after Level 1:
```go
func (v *schemav2Validator) Validate(ctx context.Context, reqURL *url.URL, data []byte) error {
	// ... existing Level 1 validation code until after VisitJSON ...

	log.Debugf(ctx, "LEVEL 1 validation passed for action: %s", action)

	// NEW: LEVEL 2 - Referenced schema validation (if enabled)
	if v.config.EnableReferencedSchemas && v.schemaCache != nil {
		log.Debugf(ctx, "starting LEVEL 2 validation for action: %s", action)
		if err := v.validateReferencedSchemas(ctx, jsonData); err != nil {
			// Level 2 failure - return error (same behavior as Level 1)
			log.Debugf(ctx, "LEVEL 2 validation failed for action %s: %v", action, err)
			return v.formatValidationError(err)
		}
		log.Debugf(ctx, "LEVEL 2 validation passed for action: %s", action)
	}

	return nil
}
```

### Add new method validateReferencedSchemas():
```go
// validateReferencedSchemas validates all objects with @context against their schemas
func (v *schemav2Validator) validateReferencedSchemas(ctx context.Context, body interface{}) error {
	// Extract "message" object - only scan inside message, not root
	bodyMap, ok := body.(map[string]interface{})
	if !ok {
		return fmt.Errorf("body is not a valid JSON object")
	}

	message, hasMessage := bodyMap["message"]
	if !hasMessage {
		return fmt.Errorf("missing 'message' field in request body")
	}

	// Find all objects with @context starting from message
	objects := findReferencedObjects(message, "message")

	if len(objects) == 0 {
		log.Debugf(ctx, "No objects with @context found in message, skipping LEVEL 2 validation")
		return nil
	}

	log.Debugf(ctx, "Found %d objects with @context for LEVEL 2 validation", len(objects))

	// Get config with defaults
	urlTransform := "context.jsonld->attributes.yaml"
	ttl := 86400 * time.Second  // 24 hours default
	timeout := 30 * time.Second
	var allowedDomains []string

	refConfig := v.config.ReferencedSchemaConfig
	if refConfig.URLTransform != "" {
		urlTransform = refConfig.URLTransform
	}
	if refConfig.CacheTTL > 0 {
		ttl = time.Duration(refConfig.CacheTTL) * time.Second
	}
	if refConfig.DownloadTimeout > 0 {
		timeout = time.Duration(refConfig.DownloadTimeout) * time.Second
	}
	allowedDomains = refConfig.AllowedDomains

	log.Debugf(ctx, "LEVEL 2 config: urlTransform=%s, ttl=%v, timeout=%v, allowedDomains=%v",
		urlTransform, ttl, timeout, allowedDomains)

	// Validate each object and collect errors
	var errors []string
	for _, obj := range objects {
		log.Debugf(ctx, "Validating object at path: %s, @context: %s, @type: %s",
			obj.Path, obj.Context, obj.Type)

		if err := v.schemaCache.validateReferencedObject(ctx, obj, urlTransform, ttl, timeout, allowedDomains); err != nil {
			errors = append(errors, err.Error())
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("validation errors:\n  - %s", strings.Join(errors, "\n  - "))
	}

	return nil
}
```

---

## `pkg/plugin/implementation/schemav2validator/cmd/plugin.go` (MODIFY)

### Add to imports:
```go
import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/beckn-one/beckn-onix/pkg/plugin/definition"
	"github.com/beckn-one/beckn-onix/pkg/plugin/implementation/schemav2validator"
)
```

### Modify New() function - parse new config fields:
```go
func (vp schemav2ValidatorProvider) New(ctx context.Context, config map[string]string) (definition.SchemaValidator, func() error, error) {
	if ctx == nil {
		return nil, nil, errors.New("context cannot be nil")
	}

	typeVal, hasType := config["type"]
	locVal, hasLoc := config["location"]

	if !hasType || typeVal == "" {
		return nil, nil, errors.New("type not configured")
	}
	if !hasLoc || locVal == "" {
		return nil, nil, errors.New("location not configured")
	}

	cfg := &schemav2validator.Config{
		Type:     typeVal,
		Location: locVal,
		CacheTTL: 3600,
	}

	if ttlStr, ok := config["cacheTTL"]; ok {
		if ttl, err := strconv.Atoi(ttlStr); err == nil && ttl > 0 {
			cfg.CacheTTL = ttl
		}
	}

	// NEW: Parse enableReferencedSchemas
	if enableStr, ok := config["enableReferencedSchemas"]; ok {
		cfg.EnableReferencedSchemas = enableStr == "true"
	}

	// NEW: Parse referencedSchemaConfig (if enabled)
	if cfg.EnableReferencedSchemas {
		// Set defaults
		cfg.ReferencedSchemaConfig = schemav2validator.ReferencedSchemaConfig{
			CacheTTL:        86400, // 24 hours
			MaxCacheSize:    100,
			DownloadTimeout: 30,
			URLTransform:    "context.jsonld->attributes.yaml",
		}

		if v, ok := config["referencedSchemaConfig.cacheTTL"]; ok {
			if ttl, err := strconv.Atoi(v); err == nil && ttl > 0 {
				cfg.ReferencedSchemaConfig.CacheTTL = ttl
			}
		}
		if v, ok := config["referencedSchemaConfig.maxCacheSize"]; ok {
			if size, err := strconv.Atoi(v); err == nil && size > 0 {
				cfg.ReferencedSchemaConfig.MaxCacheSize = size
			}
		}
		if v, ok := config["referencedSchemaConfig.downloadTimeout"]; ok {
			if timeout, err := strconv.Atoi(v); err == nil && timeout > 0 {
				cfg.ReferencedSchemaConfig.DownloadTimeout = timeout
			}
		}
		if v, ok := config["referencedSchemaConfig.allowedDomains"]; ok && v != "" {
			cfg.ReferencedSchemaConfig.AllowedDomains = strings.Split(v, ",")
		}
		if v, ok := config["referencedSchemaConfig.urlTransform"]; ok && v != "" {
			cfg.ReferencedSchemaConfig.URLTransform = v
		}
	}

	return schemav2validator.New(ctx, cfg)
}
```

---

## Configuration Example

### Disabled (Default - backward compatible):
```yaml
schemaValidator:
  id: schemav2validator
  config:
    type: url
    location: https://raw.githubusercontent.com/.../beckn.yaml
    cacheTTL: 3600
```

### Enabled:
```yaml
schemaValidator:
  id: schemav2validator
  config:
    type: url
    location: https://raw.githubusercontent.com/.../beckn.yaml
    cacheTTL: 3600
    
    # NEW: Referenced schema configuration
    enableReferencedSchemas: true
    referencedSchemaConfig:
      cacheTTL: 86400               # 24 hours (in seconds)
      maxCacheSize: 100
      downloadTimeout: 30           # seconds
      urlTransform: "context.jsonld->attributes.yaml"
      allowedDomains:
        - raw.githubusercontent.com
        - schemas.beckn.org
```

### Production Example (from lead's plan):
```yaml
# config/onix/onix-bap.yaml
modules:
  - name: bapTxnReceiver
    handler:
      plugins:
        schemaValidator:
          id: schemav2validator
          config:
            type: url
            location: https://schemas.beckn.org/core/v2.0.yaml
            cacheTTL: 7200
            
            enableReferencedSchemas: true
            referencedSchemaConfig:
              cacheTTL: 172800        # 48 hours for production
              maxCacheSize: 500       # Higher for production
              downloadTimeout: 30
              allowedDomains:
                - schemas.beckn.org
                - raw.githubusercontent.com
```

---

## Verification Plan

### Existing Tests
- `schemav2validator_test.go` - existing tests for Level 1 validation
- `cmd/plugin_test.go` - existing tests for plugin provider

### New Tests to Add

#### 1. Unit Tests (`referenced_validator_test.go`) - Using Local Files

Test data structure:
```
pkg/plugin/implementation/schemav2validator/testdata/
├── domain-schemas/
│   ├── EvChargingOffer/
│   │   └── v1/
│   │       ├── attributes.yaml    # Test schema
│   │       └── context.jsonld     # Test context
│   └── EvChargingSession/
│       └── v1/
│           ├── attributes.yaml
│           └── context.jsonld
└── requests/
    ├── select_valid.json          # Valid select request
    ├── select_invalid_offer.json  # Invalid offerAttributes
    └── select_no_context.json     # No @context objects
```

Unit test cases:
- `TestHashURL` - verify consistent hashing
- `TestIsValidSchemaURL` - valid/invalid URLs
- `TestFindReferencedObjects` - find all @context objects
- `TestTransformContextToSchemaURL` - URL transformation
- `TestFindSchemaByType` - schema lookup by @type
- `TestIsAllowedDomain` - domain whitelist check
- `TestSchemaCache_GetSet` - cache basic operations
- `TestSchemaCache_LRUEviction` - evicts oldest when full
- `TestSchemaCache_TTLExpiry` - expired entries not returned
- `TestSchemaCache_CleanupExpired` - background cleanup works
- `TestLoadSchemaFromURL_LocalFile` - load from file:// URL
- `TestValidateReferencedObject_Valid` - valid object passes
- `TestValidateReferencedObject_InvalidField` - invalid field fails

#### 2. Integration Tests (in `schemav2validator_test.go`) - Using Real GitHub URLs

Integration test cases (require network):
- `TestValidate_Level2Enabled_RealSchema` - validates against real EvChargingOffer schema
- `TestValidate_Level2Disabled` - only Level 1 runs
- `TestValidate_Level2GracefulDegradation` - Level 2 fails, request still passes
- `TestValidate_Level2CacheHit` - second request uses cached schema
- `TestValidate_Level2DomainWhitelist` - blocked domain fails

Real schema URLs for testing:
```
https://raw.githubusercontent.com/beckn/protocol-specifications-new/refs/heads/draft/schema/EvChargingOffer/v1/attributes.yaml
https://raw.githubusercontent.com/beckn/protocol-specifications-new/refs/heads/draft/schema/EvChargingSession/v1/attributes.yaml
```

### Test Commands
```bash
# Run all schemav2validator tests
cd /home/sanketika4/Workspace/becknOnix/beckn-onix-updated/beckn-onix-1/beckn-onix
go test ./pkg/plugin/implementation/schemav2validator/... -v

# Run with coverage
go test ./pkg/plugin/implementation/schemav2validator/... -cover -v

# Run only unit tests (fast, no network)
go test ./pkg/plugin/implementation/schemav2validator/... -v -short

# Run integration tests (requires network)
go test ./pkg/plugin/implementation/schemav2validator/... -v -run Integration
```

### Manual Testing
1. Start ONIX with `enableReferencedSchemas: true`
2. Send a `/select` request with `select.json` containing `offerAttributes`
3. Check logs for "LEVEL 2 validation passed" message
4. Send request with invalid `offerAttributes` field
5. Check logs for "LEVEL 2 validation failed" warning (request should still succeed)

### Test Data Files

#### testdata/requests/select_valid.json
```json
{
  "context": {
    "version": "2.0.0",
    "action": "select",
    "domain": "beckn.one:deg:ev-charging:*",
    "timestamp": "2024-01-15T10:30:00Z",
    "message_id": "bb9f86db-9a3d-4e9c-8c11-81c8f1a7b901",
    "transaction_id": "2b4d69aa-22e4-4c78-9f56-5a7b9e2b2002",
    "bap_id": "bap.example.com",
    "bap_uri": "https://bap.example.com",
    "ttl": "PT30S"
  },
  "message": {
    "order": {
      "@context": "https://raw.githubusercontent.com/beckn/protocol-specifications-new/refs/heads/draft/schema/core/v2/context.jsonld",
      "@type": "beckn:Order",
      "beckn:id": "order-ev-charging-001",
      "beckn:orderStatus": "CREATED",
      "beckn:seller": "ecopower-charging",
      "beckn:orderItems": [
        {
          "beckn:lineId": "line-001",
          "beckn:orderedItem": "ev-charger-ccs2-001",
          "beckn:quantity": {
            "unitText": "Kilowatt Hour",
            "unitCode": "KWH",
            "unitQuantity": 2.5
          },
          "beckn:acceptedOffer": {
            "@context": "https://raw.githubusercontent.com/beckn/protocol-specifications-new/refs/heads/draft/schema/core/v2/context.jsonld",
            "@type": "beckn:Offer",
            "beckn:id": "offer-ccs2-60kw-kwh",
            "beckn:offerAttributes": {
              "@context": "https://raw.githubusercontent.com/beckn/protocol-specifications-new/refs/heads/draft/schema/EvChargingOffer/v1/context.jsonld",
              "@type": "ChargingOffer",
              "buyerFinderFee": {
                "feeType": "PERCENTAGE",
                "feeValue": 2.5
              },
              "idleFeePolicy": "₹2/min after 10 min post-charge"
            }
          }
        }
      ]
    }
  }
}
```

---

## Summary

| File | Changes |
|------|---------|
| `schemav2validator.go` | MODIFY - ~350 lines added (all Level 2 code) |
| `cmd/plugin.go` | MODIFY - ~30 lines added |

**Key Features:**
- ✅ URL hashing for cache keys
- ✅ Background cleanup of expired schemas
- ✅ Level 2 fails request on error (same as Level 1)
- ✅ URL and local file support
- ✅ Domain whitelist support
- ✅ Format validation enabled
- ✅ Configurable timeouts
- ✅ 100% backward compatible
- ✅ Single file approach (follows existing codebase pattern)
