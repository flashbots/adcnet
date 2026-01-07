package services

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/flashbots/adcnet/crypto"
	"github.com/flashbots/adcnet/protocol"
	_ "github.com/lib/pq"
)

// PostgresStore implements RegistryStore with PostgreSQL persistence.
type PostgresStore struct {
	db *sql.DB
}

// PostgresConfig contains PostgreSQL connection settings.
type PostgresConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	Database string
	SSLMode  string
}

// ConnectionString returns the PostgreSQL connection string.
func (c *PostgresConfig) ConnectionString() string {
	sslMode := c.SSLMode
	if sslMode == "" {
		sslMode = "disable"
	}
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.Database, sslMode)
}

// NewPostgresStore creates a new PostgreSQL-backed store.
func NewPostgresStore(config *PostgresConfig) (*PostgresStore, error) {
	db, err := sql.Open("postgres", config.ConnectionString())
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("pinging database: %w", err)
	}

	store := &PostgresStore{db: db}
	if err := store.migrate(); err != nil {
		return nil, fmt.Errorf("running migrations: %w", err)
	}

	return store, nil
}

func (s *PostgresStore) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS registered_services (
		public_key VARCHAR(128) PRIMARY KEY,
		service_type VARCHAR(32) NOT NULL,
		http_endpoint VARCHAR(512) NOT NULL,
		exchange_key VARCHAR(256) NOT NULL,
		attestation BYTEA,
		signature BYTEA NOT NULL,
		signer_public_key VARCHAR(128) NOT NULL,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
		updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
	);

	CREATE INDEX IF NOT EXISTS idx_services_type ON registered_services(service_type);
	CREATE INDEX IF NOT EXISTS idx_services_created ON registered_services(created_at);
	`

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := s.db.ExecContext(ctx, schema)
	return err
}

// SaveService persists a signed service registration.
func (s *PostgresStore) SaveService(signed *protocol.Signed[RegisteredService]) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	svc := signed.Object

	query := `
	INSERT INTO registered_services 
		(public_key, service_type, http_endpoint, exchange_key, attestation, signature, signer_public_key, updated_at)
	VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
	ON CONFLICT (public_key) DO UPDATE SET
		service_type = EXCLUDED.service_type,
		http_endpoint = EXCLUDED.http_endpoint,
		exchange_key = EXCLUDED.exchange_key,
		attestation = EXCLUDED.attestation,
		signature = EXCLUDED.signature,
		signer_public_key = EXCLUDED.signer_public_key,
		updated_at = NOW()
	`

	_, err := s.db.ExecContext(ctx, query,
		svc.PublicKey,
		string(svc.ServiceType),
		svc.HTTPEndpoint,
		svc.ExchangeKey,
		svc.Attestation,
		signed.Signature.Bytes(),
		signed.PublicKey.String(),
	)
	return err
}

// DeleteService removes a service registration.
func (s *PostgresStore) DeleteService(publicKey string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.db.ExecContext(ctx, "DELETE FROM registered_services WHERE public_key = $1", publicKey)
	return err
}

// LoadAllServices retrieves all persisted service registrations.
func (s *PostgresStore) LoadAllServices() (map[ServiceType]map[string]*protocol.Signed[RegisteredService], error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rows, err := s.db.QueryContext(ctx, `
		SELECT public_key, service_type, http_endpoint, exchange_key, attestation, signature, signer_public_key
		FROM registered_services
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := map[ServiceType]map[string]*protocol.Signed[RegisteredService]{
		ServerService:     make(map[string]*protocol.Signed[RegisteredService]),
		AggregatorService: make(map[string]*protocol.Signed[RegisteredService]),
		ClientService:     make(map[string]*protocol.Signed[RegisteredService]),
	}

	for rows.Next() {
		var (
			publicKey    string
			serviceType  string
			httpEndpoint string
			exchangeKey  string
			attestation  []byte
			signature    []byte
			signerPubKey string
		)

		if err := rows.Scan(&publicKey, &serviceType, &httpEndpoint, &exchangeKey, &attestation, &signature, &signerPubKey); err != nil {
			return nil, fmt.Errorf("scanning row: %w", err)
		}

		svcType := ServiceType(serviceType)
		if !svcType.Valid() {
			continue
		}

		signerKey, err := crypto.NewPublicKeyFromString(signerPubKey)
		if err != nil {
			continue
		}

		signed := &protocol.Signed[RegisteredService]{
			PublicKey: signerKey,
			Signature: crypto.NewSignature(signature),
			Object: &RegisteredService{
				ServiceType:  svcType,
				HTTPEndpoint: httpEndpoint,
				PublicKey:    publicKey,
				ExchangeKey:  exchangeKey,
				Attestation:  attestation,
			},
		}

		result[svcType][publicKey] = signed
	}

	return result, rows.Err()
}

// Close closes the database connection.
func (s *PostgresStore) Close() error {
	return s.db.Close()
}

// InMemoryStore implements RegistryStore for testing without a database.
type InMemoryStore struct {
	services map[string]*protocol.Signed[RegisteredService]
}

// NewInMemoryStore creates an in-memory store.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		services: make(map[string]*protocol.Signed[RegisteredService]),
	}
}

// SaveService stores a service in memory.
func (s *InMemoryStore) SaveService(signed *protocol.Signed[RegisteredService]) error {
	s.services[signed.Object.PublicKey] = signed
	return nil
}

// DeleteService removes a service from memory.
func (s *InMemoryStore) DeleteService(publicKey string) error {
	delete(s.services, publicKey)
	return nil
}

// LoadAllServices returns all stored services.
func (s *InMemoryStore) LoadAllServices() (map[ServiceType]map[string]*protocol.Signed[RegisteredService], error) {
	result := map[ServiceType]map[string]*protocol.Signed[RegisteredService]{
		ServerService:     make(map[string]*protocol.Signed[RegisteredService]),
		AggregatorService: make(map[string]*protocol.Signed[RegisteredService]),
		ClientService:     make(map[string]*protocol.Signed[RegisteredService]),
	}

	for pk, signed := range s.services {
		svcType := signed.Object.ServiceType
		result[svcType][pk] = signed
	}

	return result, nil
}
